#!/usr/bin/env python3
"""Opt-in native Codex adapter; bounded local state, never a permission grant."""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
if __package__:
    from . import necessity_select, necessity_review
else:
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import necessity_select
    import necessity_review

EVENTS = {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStop"}
TOOLS = {"apply_patch", "Bash", "exec_command", "shell", "shell_command"}


class IntakeError(ValueError):
    """A stable, content-free diagnostic reason."""


def scope_of(payload, cfg):
    value = payload.get("cwd")
    if not isinstance(value, str) or not Path(value).is_absolute():
        return "unknown"
    cwd = Path(value).resolve()
    if any(beneath(cwd, Path(p).resolve()) for p in cfg["excludes"]):
        return "excluded"
    return "inside" if any(beneath(cwd, Path(p).resolve()) for p in cfg["scopes"]) else "outside"


def diagnostic(cfg, payload, event, raw, exc):
    """Persist only fixed labels, sizes and a digest, never rejected content."""
    reason = str(exc) if isinstance(exc, IntakeError) else (
        "invalid_json" if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)) else
        "state_error" if isinstance(exc, sqlite3.Error) else "internal_" + type(exc).__name__)
    # Exception messages, arbitrary event/tool names, paths and identifiers are
    # not safe evidence. Only known protocol labels cross this boundary.
    payload = payload if isinstance(payload, dict) else {}
    tool = payload.get("tool_name")
    info = {"reason_code": reason, "event": event if isinstance(event, str) and event in EVENTS else "unknown",
            "tool": tool if isinstance(tool, str) and tool in TOOLS | {"view_image"} else "other",
            "scope": "unknown", "input_bytes": len(raw),
            "review_limit_bytes": cfg.get("max_input_bytes") if cfg else None,
            "evidence_sha256": hashlib.sha256(raw).hexdigest(), "status": "unassessed"}
    reference = digest(info)
    saved = False
    if cfg:
        store = None
        try:
            info["scope"] = scope_of(payload, cfg)
            reference = digest(info)
            store = Store(cfg)
            store.transaction()
            store.db.execute("DELETE FROM diagnostics WHERE touched < ?", (time.time() - cfg["retention_seconds"],))
            store.db.execute("INSERT OR REPLACE INTO diagnostics(id,touched,data) VALUES(?,?,?)",
                             (reference, time.time(), json.dumps(info)))
            # Reuse the selected-evidence byte budget for bounded diagnostics;
            # eviction here cannot remove any candidate or its resolution.
            while store.db.execute("SELECT COALESCE(SUM(length(CAST(data AS BLOB))),0) FROM diagnostics").fetchone()[0] > cfg["max_input_bytes"]:
                store.db.execute("DELETE FROM diagnostics WHERE id=(SELECT id FROM diagnostics ORDER BY touched LIMIT 1)")
            saved = store.db.execute("SELECT 1 FROM diagnostics WHERE id=?", (reference,)).fetchone() is not None
            store.db.commit()
        except Exception:
            # Diagnostic failure must not replace the original tool outcome.
            pass
        finally:
            if store:
                store.close()
    return "Necessity hook unassessed: %s; diagnostic %s (%s). Inspect necessity status/check; preserve incomplete status." % (
        reason, reference, "saved" if saved else "not persisted")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def beneath(path, root):
    return path == root or root in path.parents


def load_config(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("version") != 1:
        raise ValueError("unsupported configuration")
    for name in ("deadline_seconds", "max_input_bytes", "max_output_bytes", "reviews_per_session", "retention_seconds", "max_sessions"):
        if type(value.get(name)) is not int or value[name] <= 0:
            raise ValueError("positive explicit limit required: " + name)
    for name in ("scopes", "excludes"):
        if not isinstance(value.get(name), list) or any(not isinstance(p, str) or not Path(p).is_absolute() for p in value[name]):
            raise ValueError("absolute scope paths required")
    if not value["scopes"] or not Path(value["state_dir"]).is_absolute():
        raise ValueError("scope and absolute state directory required")
    if not value.get("model") or not value.get("effort"):
        raise ValueError("explicit reviewer model and effort required")
    if value["retention_seconds"] < value["deadline_seconds"] * 2:
        raise ValueError("state retention must cover the native hook timeout")
    return value


def safe_text(text, cwd):
    # Refuse sensitive material instead of claiming that a lossy redaction was reviewed.
    if re.search(r"(?i)(?:bearer\s+\S+|(?:api[_-]?key|password|secret|token)\s*[=:]\s*[^\s,}]+|-----BEGIN .*PRIVATE KEY|\b(?:gh[pousr]_|sk-)[A-Za-z0-9_-]+)", text):
        raise ValueError("potential credential in input; review withheld")
    return text.replace(str(Path(cwd).resolve()), "<workspace>").replace(str(Path.home()), "<home>")


def context_output(event, message):
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": message}}


def decision_output(event, candidate, result):
    message = "Necessity review " + candidate + ": " + json.dumps(result, ensure_ascii=False)
    if event == "PreToolUse" and result["action"] in {"revise", "unassessed"}:
        return {"hookSpecificOutput": {"hookEventName": event, "permissionDecision": "deny", "permissionDecisionReason": message}}
    return context_output(event, message)


def unassessed(reason):
    return {"action": "unassessed", "disposition": "unassessed", "reason": reason,
            "protections": "Keep existing permission checks and evidence.", "owner_or_entry": "",
            "next_step": "Use a verified existing entry, or report this exact operation as unassessed. No blanket exception."}


def bounded_summary(messages, limit):
    selected = []
    for message in messages:
        if len(json.dumps(selected + [message], ensure_ascii=False).encode()) > limit // 2:
            return json.dumps(selected, ensure_ascii=False) + " Additional pending records omitted by output budget: %d; unassessed, inspect the local necessity state via the management entry." % (len(messages) - len(selected))
        selected.append(message)
    return json.dumps(selected, ensure_ascii=False)


class Store:
    def __init__(self, cfg):
        directory = Path(cfg["state_dir"])
        if directory.is_symlink():
            raise ValueError("state directory is a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / "necessity.sqlite3"
        if path.is_symlink():
            raise ValueError("state file is a symlink")
        self.db = sqlite3.connect(path, timeout=cfg["deadline_seconds"], isolation_level=None)
        if os.name == "posix":
            path.chmod(0o600)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, family TEXT NOT NULL, touched REAL NOT NULL, data TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS candidates (session TEXT REFERENCES sessions(id) ON DELETE CASCADE, id TEXT, status TEXT, result TEXT, notified INTEGER DEFAULT 0, started REAL NOT NULL, resolution TEXT, PRIMARY KEY(session,id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS diagnostics (id TEXT PRIMARY KEY, touched REAL NOT NULL, data TEXT NOT NULL)")
        self.cfg = cfg
        self.family = ""

    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")

    def session(self, sid):
        now = time.time()
        self.db.execute("DELETE FROM sessions WHERE touched < ?", (now - self.cfg["retention_seconds"],))
        row = self.db.execute("SELECT data FROM sessions WHERE id=?", (sid,)).fetchone()
        if row:
            value = json.loads(row[0])
            # Older state predates request inheritance. It could only have been
            # populated by this lane's prompt hook, so preserve it as direct.
            if "request_origin" not in value:
                value["request_origin"] = "direct" if value.get("contract") and value.get("prompt") else "unavailable"
            return value
        if self.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] >= self.cfg["max_sessions"]:
            raise ValueError("state session capacity reached; no existing decisions evicted")
        value = {"contract": "", "prompt": "", "problem": "current request unavailable", "request_origin": "unavailable", "history": [], "coverage": [], "coverage_notice": "", "stop_notice": "", "posts": []}
        self.save(sid, value)
        return value

    def save(self, sid, value):
        self.db.execute("INSERT INTO sessions(id,family,touched,data) VALUES(?,?,?,?)", (sid, self.family or sid, time.time(), json.dumps(value)))

    def update(self, sid, value):
        # Do not REPLACE an existing parent: that would cascade-delete decisions.
        self.db.execute("UPDATE sessions SET touched=?,data=? WHERE id=?", (time.time(), json.dumps(value), sid))

    def close(self):
        self.db.close()


def direct_context(state):
    """Return a usable lane-local prompt context, never a derived one."""
    contract, prompt = state.get("contract"), state.get("prompt")
    if state.get("request_origin") != "direct" or state.get("problem"):
        return None
    if not isinstance(contract, str) or not contract.strip() or not isinstance(prompt, str) or not prompt.strip():
        return None
    return contract, prompt


def refresh_request_context(store, sid, state):
    """Refresh a non-direct lane from one unambiguous direct family context."""
    if state.get("request_origin") == "direct":
        return
    contexts = {}
    for source, encoded in store.db.execute("SELECT id,data FROM sessions WHERE family=? AND id<>?", (store.family, sid)):
        source_state = json.loads(encoded)
        if "request_origin" not in source_state:
            source_state["request_origin"] = "direct" if source_state.get("contract") and source_state.get("prompt") else "unavailable"
        context = direct_context(source_state)
        if context:
            contexts.setdefault(context, []).append(source)
    if len(contexts) == 1:
        (contract, prompt), sources = next(iter(contexts.items()))
        state["contract"], state["prompt"], state["problem"] = contract, prompt, ""
        # Retain the source identity without importing that lane's decisions or cache.
        state["request_origin"] = "inherited:" + min(sources)
    elif len(contexts) > 1:
        state["contract"], state["prompt"] = "", ""
        state["problem"] = "ambiguous direct request contexts in session family"
        state["request_origin"] = "ambiguous"
    else:
        state["contract"], state["prompt"] = "", ""
        state["problem"] = "current request unavailable"
        state["request_origin"] = "unavailable"


def file_facts(paths, cwd, limit):
    facts = []
    for name in sorted(set(paths)):
        path = Path(cwd) / name
        resolved = path.resolve()
        if not beneath(resolved, Path(cwd).resolve()) or path.is_symlink():
            facts.append([digest(name), "outside-observed-scope"])
            continue
        try:
            if not stat.S_ISREG(resolved.stat().st_mode):
                facts.append([digest(name), "non-regular-unassessed"])
                continue
            with resolved.open("rb") as source:
                data = source.read(limit + 1)
            facts.append([digest(name), hashlib.sha256(data).hexdigest() if len(data) <= limit else "oversized-unassessed"])
        except FileNotFoundError:
            facts.append([digest(name), "absent"])
        except OSError:
            facts.append([digest(name), "unreadable-unassessed"])
    return facts


def management_call(payload, cfg):
    """Recognize one intact, statically addressed recovery entry before Store."""
    if payload.get("tool_name") not in {"Bash", "exec_command", "shell", "shell_command"}:
        return False
    tool = payload.get("tool_input")
    if not isinstance(tool, dict):
        return False
    try:
        owner = json.loads((HERE / ".necessity-install.json").read_text(encoding="utf-8"))["management"]

        def unsafe(path):
            path = Path(path)
            return any(
                item.is_symlink() or getattr(item.lstat(), "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                for item in (path, *path.parents)
            )

        def same(left, right):
            return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))

        launcher, source = Path(owner["launcher"]), Path(owner["source"])
        names = ("__init__.py", "necessity_install.py", "necessity_hook.py",
                 "necessity_review.py", "necessity_select.py", "necessity_parse.ps1")
        if (not same(owner["python"], sys.executable)
                or not launcher.is_absolute() or unsafe(launcher) or not launcher.is_file()
                or hashlib.sha256(launcher.read_bytes()).hexdigest() != owner["launcher_sha256"]
                or Path(owner["home"]).resolve() != HERE.parent.resolve()
                or not source.is_absolute() or unsafe(source)):
            return False
        for name in names:
            path = source / name
            if unsafe(path) or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != owner["files"].get(name):
                return False

        shell = tool.get("shell") or cfg.get("shell") or ("bash" if os.name == "posix" else "unknown-native-shell")
        words = necessity_select.static_argv(
            tool.get("command", tool.get("cmd", "")), shell,
            parser_timeout=cfg["deadline_seconds"])
        if not words:
            return False
        workdir = Path(tool.get("workdir", payload.get("cwd", "")))
        if not workdir.is_absolute():
            return False
        if words[0] == "necessity-review":
            # Preserve PATH order, including relative/empty entries. Windows
            # may additionally search cwd; do not guess that from another cwd.
            if os.name == "nt" and not same(workdir, Path.cwd()):
                return False
            search_path = os.pathsep.join(
                os.path.abspath(workdir / item)
                for item in os.environ.get("PATH", "").split(os.pathsep))
            resolved = shutil.which(words[0], path=search_path)
        elif Path(words[0]).is_absolute():
            resolved = words[0]
        else:
            return False
        if not resolved or unsafe(resolved) or Path(resolved).resolve() != launcher.resolve():
            return False

        # A console launcher imports a package by name. Verify that its actual
        # import basis selects the pinned package, without executing its init.
        # Relative PYTHONPATH entries may change meaning at a different cwd.
        if not same(workdir, Path.cwd()) and "PYTHONPATH" in os.environ and any(
                not Path(item).is_absolute()
                for item in os.environ["PYTHONPATH"].split(os.pathsep)):
            return False
        search = [str(launcher.parent)] + list(sys.path[1:])
        package_spec = importlib.machinery.PathFinder.find_spec("necessity_review", search)
        if (package_spec is None or package_spec.origin is None
                or not same(package_spec.origin, source / "__init__.py")
                or not package_spec.submodule_search_locations
                or len(package_spec.submodule_search_locations) != 1
                or not same(package_spec.submodule_search_locations[0], source)):
            return False
        module_spec = importlib.machinery.PathFinder.find_spec(
            "necessity_review.necessity_install", package_spec.submodule_search_locations)
        if (module_spec is None or module_spec.origin is None
                or not same(module_spec.origin, source / "necessity_install.py")):
            return False

        if words[1:] in (["--help"], ["-h"]):
            return True
        if len(words) < 2 or words[1] not in {"check", "status", "record", "remove"}:
            return False
        operation, args = words[1], words[2:]
        options = {"--codex-home"}
        if operation == "check":
            options.add("--settings")
        if operation == "record":
            options.update({"--candidate", "--outcome", "--evidence"})
        home, help_requested, index = None, False, 0
        while index < len(args):
            word = args[index]
            if word in {"--help", "-h"}:
                help_requested = True
                index += 1
                continue
            flag, separator, value = word.partition("=")
            if flag not in options:
                return False
            if not separator:
                index += 1
                if index == len(args):
                    return False
                value = args[index]
            if flag == "--codex-home":
                if home is not None or not Path(value).is_absolute() or Path(value).resolve() != Path(owner["home"]).resolve():
                    return False
                home = value
            index += 1
        return home is not None or help_requested
    except (OSError, ValueError, TypeError, KeyError):
        return False


def handle(payload, cfg, reviewer=necessity_review.review):
    event = payload.get("hook_event_name")
    if event not in EVENTS:
        return {}
    # A dedicated reviewer has no model tools; only our own hooks are suppressed.
    # Other native security hooks remain enabled and subject to normal trust.
    if os.environ.get("AGENT_RULES_NECESSITY_REVIEWER") == "1":
        if event == "PreToolUse":
            return {"hookSpecificOutput": {"hookEventName": event, "permissionDecision": "deny", "permissionDecisionReason": "Necessity reviewer must judge supplied evidence without tools."}}
        return {}
    scope = scope_of(payload, cfg)
    if scope in {"outside", "excluded"}:
        return {}
    if event in {"PreToolUse", "PostToolUse"} and payload.get("tool_name") not in TOOLS:
        return {}
    if scope == "unknown":
        raise IntakeError("missing_absolute_cwd")
    cwd = Path(payload["cwd"]).resolve()
    # Recovery cannot depend on request resolution, a candidate slot, or even
    # opening candidate state. Post must not create pending work for it either.
    if event in {"PreToolUse", "PostToolUse"} and management_call(payload, cfg):
        return {}
    if event in {"PreToolUse", "PostToolUse"}:
        tool = payload.get("tool_input")
        if not isinstance(tool, dict) or not isinstance(tool.get("command", tool.get("cmd")), str):
            raise IntakeError("missing_tool_command")
        if len(tool.get("command", tool.get("cmd")).encode()) > cfg["max_input_bytes"]:
            raise IntakeError("selected_command_too_large")
    if event == "UserPromptSubmit" and isinstance(payload.get("prompt"), str) and len(payload["prompt"].encode()) > cfg["max_input_bytes"]:
        raise IntakeError("selected_prompt_too_large")
    if not isinstance(payload.get("session_id"), str) or not payload["session_id"]:
        raise IntakeError("missing_session_id")
    actor = payload.get("agent_id") or payload.get("transcript_path") or "root"
    sid = digest([str(cwd), payload["session_id"], actor])
    store = Store(cfg)
    store.family = digest([str(cwd), payload["session_id"]])
    try:
        store.transaction()
        state = store.session(sid)
        if event == "UserPromptSubmit":
            prompt = payload.get("prompt")
            inherited = state.get("request_origin", "").startswith("inherited:")
            state["request_origin"] = "direct"
            if not isinstance(prompt, str) or not prompt.strip():
                state["contract"], state["prompt"] = "", ""
                state["problem"] = "current request unavailable"
            else:
                try:
                    prompt = safe_text(prompt, cwd)
                    # The first request is retained for continuation; every new prompt
                    # changes the exact decision key, so previous permission is not reused.
                    state["prompt"] = prompt
                    if inherited or not state["contract"]:
                        state["contract"] = prompt
                    state["problem"] = ""
                    if "https://github.com/" in prompt:
                        # URL alone is not the contract. Fetch once outside the state lock.
                        state["problem"] = "referenced request must be resolved"
                except ValueError as exc:
                    state["contract"], state["prompt"] = "", ""
                    state["problem"] = str(exc)
            state["stop_notice"] = ""
            store.update(sid, state)
            store.db.commit()
            if state["problem"] == "referenced request must be resolved":
                try:
                    contract = necessity_review.resolve_request(payload["prompt"], cfg)
                    contract = safe_text(contract, cwd)
                    if len(contract.encode()) > cfg["max_input_bytes"]:
                        raise ValueError("request exceeds input limit; not truncated")
                    problem = ""
                except (ValueError, OSError) as exc:
                    contract, problem = "", str(exc)
                store.transaction()
                current = store.session(sid)
                if current["prompt"] == state["prompt"]:
                    current["contract"], current["problem"] = contract, problem
                    store.update(sid, current)
                store.db.commit()
            return {}
        refresh_request_context(store, sid, state)
        # Store a refreshed inherited context even when this event has no relevant
        # tool, so a later candidate cannot use stale parent requirements.
        store.update(sid, state)
        if event == "SessionStart":
            pending = store.db.execute("SELECT id,result FROM candidates WHERE session=? AND resolution IS NULL", (sid,)).fetchall()
            store.db.commit()
            if pending:
                return context_output(event, "Unresolved necessity reviews: " + bounded_summary(pending, cfg["max_output_bytes"]))
            if payload.get("source") in {"resume", "compact"}:
                return context_output(event, "No unresolved reviews are being returned from retained state. "
                                      "This does not establish that expired or missing history was handled. "
                                      "Check the existing task result and necessity status; report missing history as unassessed.")
            return {}
        if event in {"Stop", "SubagentStop"}:
            rows = store.db.execute("SELECT id,status,result FROM candidates WHERE session=? AND resolution IS NULL AND notified=0", (sid,)).fetchall()
            messages = ["%s: %s" % (row[0], row[2] or row[1]) for row in rows]
            if digest(state["coverage"]) != state["coverage_notice"]:
                messages += state["coverage"]
            pending_digest = digest(messages)
            if messages and state["stop_notice"] != pending_digest:
                state["stop_notice"] = pending_digest
                state["coverage_notice"] = digest(state["coverage"])
                store.db.execute("UPDATE candidates SET notified=1 WHERE session=?", (sid,))
                store.update(sid, state)
                store.db.commit()
                message = "Necessity review: preserve these unresolved/proposed items in the existing task result, with disposition or explicit incomplete status; do not implement a proposed reusable feature automatically. " + bounded_summary(messages, cfg["max_output_bytes"])
                if payload.get("stop_hook_active"):
                    return {"systemMessage": message + " Further continuation suppressed; unresolved work remains."}
                return {"decision": "block", "reason": message}
            store.db.commit()
            return {}
        name = payload.get("tool_name")
        tool = payload.get("tool_input", {})
        command = tool.get("command", tool.get("cmd", "")) if isinstance(tool, dict) else ""
        operation_cwd = Path(tool.get("workdir", str(cwd))).resolve() if isinstance(tool, dict) else cwd
        if not beneath(operation_cwd, cwd):
            store.db.commit()
            return decision_output(event, "outside-session-scope", unassessed("tool working directory is outside the observed session scope")) if event == "PreToolUse" else {}
        if name == "apply_patch":
            # Patch bytes are data, not an immediate management program. Track observed
            # targets for subsequent execution without persisting patch contents.
            analysis = {"features": [], "coverage": [], "writes": re.findall(r"^\*\*\* (?:Add|Update) File: (.+)$", command, re.M), "executes": [], "responsibilities": ["write"]}
        elif name in {"Bash", "exec_command", "shell", "shell_command"}:
            native_shell = tool.get("shell") or cfg.get("shell") or ("bash" if os.name == "posix" else "unknown-native-shell")
            analysis = necessity_select.analyze(command, native_shell, parser_timeout=cfg["deadline_seconds"])
        else:
            store.db.commit()
            return {}
        coverage = analysis["coverage"]
        for item in coverage:
            if item not in state["coverage"]:
                state["coverage"].append(item)
        history = state["history"]
        targets = analysis["writes"] + analysis["executes"]
        target_ids = {digest(str((operation_cwd / p).resolve())) for p in targets}
        features = list(analysis["features"])
        executed = {digest(str((operation_cwd / p).resolve())) for p in analysis["executes"]}
        if any(executed.intersection(h["writes"]) for h in history):
            features.append("execute-observed-generated-file")
        if any(target_ids.intersection(h["targets"]) and analysis["writes"] for h in history):
            features.append("repeat-write-observed-target")
        related = [h for h in history if target_ids.intersection(h["targets"])]
        if any(h["outcome"] == "failed" for h in related):
            features.append("reconstruction-after-observed-failure")
        if event == "PostToolUse":
            post_id = digest([payload.get("turn_id"), payload.get("tool_use_id"), name, command])
            if post_id in state["posts"]:
                store.db.commit()
                return {}
            state["posts"].append(post_id)
            response = payload.get("tool_response", {})
            # Only machine-readable status is evidence; output prose is not an exit code.
            code = response.get("exit_code") if isinstance(response, dict) else None
            outcome = "failed" if type(code) is int and code != 0 else "succeeded" if code == 0 else "unknown"
            history.append({"targets": sorted(target_ids), "writes": [digest(str((operation_cwd / p).resolve())) for p in analysis["writes"]], "responsibilities": analysis["responsibilities"], "outcome": outcome})
            # The same configured input budget bounds local history; no raw program stored.
            while len(json.dumps(history).encode()) > cfg["max_input_bytes"]:
                history.pop(0)
                if "older operation history expired" not in state["coverage"]:
                    state["coverage"].append("older operation history expired")
            while len(json.dumps(state["posts"]).encode()) > cfg["max_input_bytes"]:
                state["posts"].pop(0)
            store.update(sid, state)
            store.db.commit()
            return {}
        store.update(sid, state)
        if not features and not coverage:
            store.db.commit()
            return {}
        facts = file_facts(targets, operation_cwd, cfg["max_input_bytes"])
        key = digest([str(cwd), actor, payload.get("turn_id"), state["contract"], state["prompt"], state["problem"], command, cfg, facts, related])
        row = store.db.execute("SELECT status,result,started FROM candidates WHERE session=? AND id=?", (sid, key)).fetchone()
        if row:
            if row[0] == "reviewing" and time.time() - row[2] > cfg["deadline_seconds"] * 2:
                interrupted = unassessed("previous review was interrupted; no automatic charged retry")
                store.db.execute("UPDATE candidates SET status=?,result=? WHERE session=? AND id=?", ("interrupted", json.dumps(interrupted), sid, key))
                row = ("interrupted", json.dumps(interrupted), row[2])
            store.db.commit()
            result = json.loads(row[1]) if row[1] else unassessed("identical candidate already under review or interrupted; no duplicate model call")
            return decision_output(event, key, result)
        count = store.db.execute("SELECT COUNT(*) FROM candidates JOIN sessions ON candidates.session=sessions.id WHERE sessions.family=?", (store.family,)).fetchone()[0]
        if count >= cfg["reviews_per_session"]:
            if "candidate/session budget exhausted" not in state["coverage"]:
                state["coverage"].append("candidate/session budget exhausted")
            store.update(sid, state)
            store.db.commit()
            return decision_output(event, key, unassessed("candidate/session budget exhausted; no additional review"))
        store.db.execute("INSERT INTO candidates(session,id,status,started) VALUES(?,?,?,?)", (sid, key, "reviewing", time.time()))
        store.db.commit()  # No lock across model or network calls.
        started = time.monotonic()
        usage = None
        try:
            if state["problem"]:
                raise ValueError(state["problem"])
            if coverage or any("unassessed" in f[1] or f[1] == "outside-observed-scope" for f in facts):
                raise ValueError("incomplete syntax/file coverage: " + "; ".join(coverage))
            generated_sources = {}
            confirmed_entries = []
            for name in analysis["executes"]:
                path = operation_cwd / name
                if not path.is_file() or path.is_symlink() or not beneath(path.resolve(), operation_cwd):
                    continue
                if any(digest(str(path.resolve())) in h["writes"] for h in history):
                    with path.open("rb") as source:
                        content = source.read(cfg["max_input_bytes"] + 1)
                    if len(content) > cfg["max_input_bytes"]:
                        raise ValueError("observed generated file exceeds input bound")
                    generated_sources[safe_text(str(path), cwd)] = safe_text(content.decode("utf-8"), cwd)
                else:
                    confirmed_entries.append({"path": safe_text(str(path), cwd), "evidence": "observed existing file; behavior/arguments not verified"})
            request = {"candidate_id": key, "contract": state["contract"], "current_prompt": state["prompt"], "operation": safe_text(command, cwd), "features": features, "related_outcomes": related, "confirmed_entries": confirmed_entries, "generated_sources": generated_sources, "file_facts": facts}
            if len(json.dumps(request).encode()) > cfg["max_input_bytes"]:
                raise ValueError("review input exceeds configured limit; not truncated")
            result = reviewer(request, cfg)
            usage = result.pop("_usage", None) if isinstance(result, dict) else None
            necessity_review.validate(result, key)
        except (ValueError, OSError) as exc:
            result = unassessed(str(exc))
        notify = result["action"] != "continue" or result["disposition"] == "integrate"
        store.transaction()
        saved_result = dict(result, elapsed_seconds=time.monotonic() - started, usage=usage)
        store.db.execute("UPDATE candidates SET status=?,result=?,notified=? WHERE session=? AND id=?", ("reviewed", json.dumps(saved_result), 0 if notify else 1, sid, key))
        store.db.commit()
        return decision_output(event, key, result)
    finally:
        store.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--event", choices=sorted(EVENTS))
    args = parser.parse_args(argv)
    payload = {}
    cfg = None
    raw = b""
    event = args.event
    try:
        cfg = load_config(args.config)
        # Native transport is not review text. In particular image/base64
        # results are never selected or persisted by handle().
        raw = sys.stdin.buffer.read()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            payload = {}
            raise IntakeError("invalid_envelope")
        if args.event and payload.get("hook_event_name") != args.event:
            raise IntakeError("event_mismatch")
        event = args.event or payload.get("hook_event_name")
        result = handle(payload, cfg)
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except Exception as exc:
        # Do not echo raw inputs or database contents in diagnostics.
        try:
            message = diagnostic(cfg, payload, event, raw, exc)
        except Exception:
            message = "Necessity hook unassessed; diagnostic unavailable. Inspect necessity status/check; preserve incomplete status."
        if event == "PostToolUse":
            print(json.dumps(context_output(event, message)))
            return 0
        if event == "PreToolUse":
            print(json.dumps(decision_output(event, "unavailable", unassessed(message))))
            return 0
        if isinstance(event, str) and event in {"Stop", "SubagentStop"}:
            print(json.dumps({"systemMessage": message + " Stop cannot recover state; work remains unassessed."}))
            return 0
        print(message.encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
