#!/usr/bin/env python3
"""Install, inspect, and remove the opt-in Codex necessity-review hooks.

This module deliberately manages only the entries it records in its manifest.
Native Codex trust and whether an already-running client loaded these hooks are
outside the information available in ``hooks.json``.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

try:  # The distributed wheel also supports Windows, where this lock is absent.
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback is intentionally local
    fcntl = None
try:  # Python 3.11; the wheel declares tomli for 3.10.
    import tomllib
except ImportError:  # pragma: no cover - exercised by the 3.10 wheel
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

HERE = Path(__file__).resolve().parent
FILES = ("necessity_hook.py", "necessity_review.py", "necessity_select.py",
         "necessity_parse.ps1")
MANIFEST = ".necessity-install.json"
CONFIG = "config.json"
EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStop")
BAD_PATH = set("\0\n\r")
WINDOWS_CMD_META = set("%!&|<>()^\n\r")


class InstallError(RuntimeError):
    pass


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _console_launcher():
    """Return the exact console file that invoked this installer, never PATH lookup."""
    value = Path(sys.argv[0])
    if not value.is_absolute():
        value = Path.cwd() / value
    suffix = value.suffix.lower()
    if value.name not in {"necessity-review", "necessity-review.exe"} or suffix not in {"", ".exe"}:
        raise InstallError("install must be invoked by the necessity-review console launcher")
    # Windows distlib may report the launcher without its executable suffix.
    if os.name == "nt" and suffix == "" and value.with_suffix(".exe").is_file():
        value = value.with_suffix(".exe")
    value = _absolute(value, "necessity-review launcher")
    if any(getattr(item.lstat(), "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
           for item in (value, *value.parents)):
        raise InstallError("necessity-review launcher must not traverse a reparse point")
    return value


def _absolute(value, name):
    path = Path(value)
    if not isinstance(value, (str, os.PathLike)) or not path.is_absolute() or path.is_symlink() or any(ch in BAD_PATH for ch in str(path)):
        raise InstallError("%s must be an absolute non-symlink path" % name)
    parent = path.parent
    while parent != parent.parent:
        if parent.exists() and parent.is_symlink():
            raise InstallError("%s has a symlinked parent" % name)
        parent = parent.parent
    return path


def _json(path, missing=None):
    if not path.exists():
        return missing
    if path.is_symlink():
        raise InstallError("refusing symlink: %s" % path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstallError("malformed JSON: %s" % path) from exc


def _atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".necessity-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


@contextlib.contextmanager
def _lock(root):
    lock = root / ".necessity-install.lock"
    if lock.is_symlink():
        raise InstallError("refusing symlink lock")
    root.mkdir(parents=True, exist_ok=True)
    with open(lock, "a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:  # Windows locks one byte and the OS releases it when a process dies.
            import msvcrt  # pragma: no cover - Windows-only
            handle.seek(0)
            if not handle.read(1):
                handle.seek(0)
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise InstallError("another necessity installer holds the lock") from exc
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:  # pragma: no cover - Windows-only
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def _settings(path):
    document = _json(path)
    if not isinstance(document, dict):
        raise InstallError("settings must be one JSON object")
    required = ("version", "scopes", "excludes", "state_dir", "model", "effort",
                "deadline_seconds", "max_input_bytes", "max_output_bytes",
                "reviews_per_session", "retention_seconds", "max_sessions")
    if set(document) - {"codex_executable", "shell"} != set(required) or document["version"] != 1:
        raise InstallError("settings must contain exactly the version-1 necessity fields")
    if "codex_executable" in document:
        document["codex_executable"] = str(_absolute(document["codex_executable"], "codex_executable"))
    if "shell" in document and document["shell"] not in {"bash", "powershell", "pwsh", "sh"}:
        raise InstallError("unsupported configured native shell")
    for key in ("scopes", "excludes"):
        if not isinstance(document[key], list) or not all(isinstance(v, str) for v in document[key]):
            raise InstallError("%s must be a list of absolute roots" % key)
        document[key] = [str(_absolute(v, key)) for v in document[key]]
    if not document["scopes"]:
        raise InstallError("scopes must name at least one absolute root")
    document["state_dir"] = str(_absolute(document["state_dir"], "state_dir"))
    if not isinstance(document["model"], str) or not document["model"] or not isinstance(document["effort"], str) or not document["effort"]:
        raise InstallError("model and effort are required")
    for key in required[6:]:
        if not isinstance(document[key], int) or isinstance(document[key], bool) or document[key] <= 0:
            raise InstallError("%s must be an explicit positive integer" % key)
    if document["retention_seconds"] < document["deadline_seconds"] * 2:
        raise InstallError("state retention must cover the native hook timeout")
    return document


def _is_windows():
    return os.name == "nt"


def _require_windows_pwsh(settings):
    if not _is_windows():
        return
    if settings.get("shell") != "pwsh":
        raise InstallError('Windows necessity settings require shell: "pwsh"')
    executable = shutil.which("pwsh")
    if not executable:
        raise InstallError("PowerShell 7 or newer (pwsh) is required on Windows")
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.Major"],
            capture_output=True, text=True, timeout=10, check=False)
        major = int(result.stdout.strip()) if result.returncode == 0 else 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot verify PowerShell 7 or newer (pwsh)") from exc
    if major < 7:
        raise InstallError("PowerShell 7 or newer (pwsh) is required on Windows")


def _command(config, *, event=None, windows=None):
    """Encode the fixed argv without resolving away an active virtualenv."""
    executable = str(Path(sys.executable))
    if not Path(executable).is_absolute():
        raise InstallError("Python executable must be absolute")
    if event is not None and event not in EVENTS:
        raise InstallError("unsupported hook event")
    argv = (executable, str(config.parent / "necessity_hook.py"), "--config", str(config))
    if event is not None:
        argv += ("--event", event)
    windows = os.name == "nt" if windows is None else windows
    if windows:
        if any(any(ch in WINDOWS_CMD_META for ch in value) for value in argv):
            raise InstallError("Windows hook command paths contain cmd metacharacters")
        return subprocess.list2cmdline(list(argv))
    return " ".join(shlex.quote(value) for value in argv)


def _entry(command, timeout):
    return {"type": "command", "command": command, "timeout": timeout}


def _event_command(command, event):
    """Bind a manifest's historical base command to one native event."""
    if event not in EVENTS:
        raise InstallError("unsupported hook event")
    # Event names are a fixed ASCII enum, so this is valid for both shell
    # encodings produced by _command and does not reinterpret a path.
    return command + " --event " + event


def _hook_map(document):
    if not isinstance(document, dict):
        raise InstallError("hooks.json must be an object")
    hooks = document.get("hooks")
    if hooks is None:
        document["hooks"] = {}
        return document["hooks"]
    if not isinstance(hooks, dict):
        raise InstallError("hooks.json hooks must be an object")
    return hooks


def _owned_entries(hooks, command):
    hooks = _hook_map(hooks)
    found = []
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise InstallError("hooks.json event %s is malformed" % event)
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                raise InstallError("hooks.json event %s is malformed" % event)
            for hook in group["hooks"]:
                if isinstance(hook, dict) and hook.get("type") == "command" and hook.get("command") == command:
                    found.append((event, group, hook))
    return found


def _exact_hooks(hooks, command, timeout):
    """Require the six event-bound groups currently installed."""
    return (not _owned_entries(hooks, command) and all(_owned_entries(hooks, _event_command(command, event)) == [
        (event, {"hooks": [_entry(_event_command(command, event), timeout)]},
         _entry(_event_command(command, event), timeout))]
        for event in EVENTS))


def _exact_legacy_hooks(hooks, command, timeout):
    """Recognize pre-event manifests so their ownership remains removable."""
    found = _owned_entries(hooks, command)
    expected = _entry(command, timeout)
    return (len(found) == len(EVENTS) and {event for event, _, _ in found} == set(EVENTS)
            and all(group == {"hooks": [expected]} and hook == expected
                    for _, group, hook in found))


def _any_owned_entries(hooks, command):
    entries = _owned_entries(hooks, command)
    for event in EVENTS:
        entries.extend(_owned_entries(hooks, _event_command(command, event)))
    return entries


def _valid_toml(path):
    if not path.exists():
        return
    if path.is_symlink():
        raise InstallError("refusing symlink config.toml")
    if tomllib is None:
        raise InstallError("TOML parser unavailable; cannot safely inspect config.toml")
    try:
        tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstallError("malformed config.toml") from exc


def _manifest(root):
    value = _json(root / MANIFEST)
    if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("files"), dict):
        raise InstallError("missing or malformed necessity ownership manifest")
    if value.get("command") != _command(root / CONFIG) or not isinstance(value.get("timeout"), int) or value["timeout"] <= 0:
        raise InstallError("necessity ownership manifest does not describe this installation")
    allowed = set(FILES) | {CONFIG}
    files = value["files"]
    if CONFIG not in files or not set(files).issubset(allowed):
        raise InstallError("necessity ownership manifest names an unsafe file")
    if any(not isinstance(name, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
           for name, digest in files.items()):
        raise InstallError("necessity ownership manifest has invalid file digests")
    return value


def _expected(source, settings, root):
    scripts = {}
    for name in FILES:
        path = source / name
        if name == "necessity_parse.ps1" and not path.exists():
            continue
        if not path.is_file() or path.is_symlink():
            raise InstallError("required public script is missing or unsafe: %s" % path)
        scripts[name] = _digest(path)
    config = root / CONFIG
    command = _command(config)
    return scripts, config, command, settings["deadline_seconds"] * 2


def _same_install(manifest, scripts, settings_bytes, command, timeout, root):
    if manifest.get("command") != command or manifest.get("timeout") != timeout:
        return False
    wanted = dict(scripts)
    wanted[CONFIG] = hashlib.sha256(settings_bytes).hexdigest()
    if manifest.get("files") != wanted:
        return False
    return all((root / name).is_file() and not (root / name).is_symlink() and _digest(root / name) == digest
               for name, digest in wanted.items())


def install(codex_home, settings_path, *, source=None):
    home = _absolute(codex_home, "codex_home")
    settings_path = _absolute(settings_path, "settings")
    settings = _settings(settings_path)
    _require_windows_pwsh(settings)
    settings_bytes = (json.dumps(settings, sort_keys=True, indent=2) + "\n").encode()
    root = home / "necessity-review"
    if home.exists() and home.is_symlink() or root.is_symlink():
        raise InstallError("refusing symlink installation root")
    source = HERE if source is None else Path(source)
    scripts, config, command, timeout = _expected(source, settings, root)
    # Management is always pinned to this package's installed console launcher.
    # A source checkout can never become the management authority.
    launcher_path = _console_launcher()
    package_files = ("__init__.py", "necessity_install.py", "necessity_hook.py", "necessity_review.py", "necessity_select.py", "necessity_parse.ps1")
    management = {
        "launcher": str(launcher_path), "launcher_sha256": _digest(launcher_path),
        "python": str(Path(sys.executable)), "home": str(home), "source": str(source.resolve()),
        "files": {name: _digest(source / name) for name in package_files},
    }
    hooks_path = home / "hooks.json"
    toml = home / "config.toml"
    with _lock(home):
        old_hooks_bytes = hooks_path.read_bytes() if hooks_path.exists() else None
        hooks = _json(hooks_path, missing={})
        manifest_path = root / MANIFEST
        _valid_toml(toml)
        if toml.exists() and "necessity_hook.py" in toml.read_text(encoding="utf-8"):
            raise InstallError("config.toml contains an external necessity hook conflict")
        existing = _json(manifest_path, missing=None)
        if existing is not None:
            existing = _manifest(root)
            if existing.get("management") == management and _same_install(existing, scripts, settings_bytes, command, timeout, root):
                if _exact_hooks(hooks, command, timeout):
                    return 0
            # Never update an established installation: it may contain an
            # operator's settings or a concurrent source update.
            raise InstallError("existing necessity installation differs; refusing overwrite")
        if any((root / name).exists() for name in tuple(scripts) + (CONFIG, MANIFEST)):
            raise InstallError("necessity installation directory already contains unmanaged files")
        if _any_owned_entries(hooks, command):
            raise InstallError("conflicting owned necessity command already exists")
        # Re-read immediately before replacement: lock coordinates cooperating
        # installers; this detects edits made outside that protocol.
        if (hooks_path.read_bytes() if hooks_path.exists() else None) != old_hooks_bytes:
            raise InstallError("hooks.json changed during installation")
        hooks = dict(hooks)
        hook_map = _hook_map(hooks)
        for event in EVENTS:
            groups = hook_map.setdefault(event, [])
            if not isinstance(groups, list):
                raise InstallError("hooks.json event %s is malformed" % event)
            groups.append({"hooks": [_entry(_event_command(command, event), timeout)]})
        for name in scripts:
            _atomic(root / name, (source / name).read_bytes())
        _atomic(config, settings_bytes)
        files = dict(scripts)
        files[CONFIG] = hashlib.sha256(settings_bytes).hexdigest()
        manifest = {"version": 1, "command": command, "timeout": timeout, "files": files}
        # Pin the existing public management entry, not every Python invocation.
        # Keep the executable spelling used at registration (including venvs).
        if management is not None:
            manifest["management"] = management
        _atomic(manifest_path, (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
        if (hooks_path.read_bytes() if hooks_path.exists() else None) != old_hooks_bytes:
            for name, digest in files.items():
                path = root / name
                if path.is_file() and not path.is_symlink() and _digest(path) == digest:
                    path.unlink()
            if manifest_path.exists() and not manifest_path.is_symlink():
                manifest_path.unlink()
            raise InstallError("hooks.json changed during installation")
        _atomic(hooks_path, (json.dumps(hooks, sort_keys=True, indent=2) + "\n").encode())
    return 0


def check(codex_home, settings_path=None):
    home = _absolute(codex_home, "codex_home")
    root = home / "necessity-review"
    try:
        manifest = _manifest(root)
        _require_windows_pwsh(_settings(root / CONFIG))
        hooks = _json(home / "hooks.json")
        command = manifest["command"]
        files_ok = all((root / name).is_file() and not (root / name).is_symlink() and _digest(root / name) == digest
                       for name, digest in manifest["files"].items())
        management = manifest.get("management")
        if not isinstance(management, dict):
            raise InstallError("missing management identity")
        source = Path(management.get("source", ""))
        launcher = Path(management.get("launcher", ""))
        package_files = ("__init__.py", "necessity_install.py", "necessity_hook.py", "necessity_review.py", "necessity_select.py", "necessity_parse.ps1")
        files_ok = files_ok and management.get("python") == str(Path(sys.executable)) and management.get("home") == str(home) and source.is_absolute() and not source.is_symlink()
        files_ok = files_ok and launcher.is_absolute() and launcher.is_file() and not launcher.is_symlink()
        files_ok = files_ok and _digest(launcher) == management.get("launcher_sha256")
        files_ok = files_ok and isinstance(management.get("files"), dict) and all(
            (source / name).is_file() and not (source / name).is_symlink()
            and _digest(source / name) == management["files"].get(name)
            for name in package_files)
        hooks_ok = _exact_hooks(hooks, command, manifest["timeout"])
        if settings_path is not None:
            expected = (json.dumps(_settings(_absolute(settings_path, "settings")), sort_keys=True, indent=2) + "\n").encode()
            files_ok = files_ok and (root / CONFIG).read_bytes() == expected
    except (InstallError, OSError, KeyError, TypeError, ValueError) as exc:
        print("FAIL: %s" % exc)
        return 1
    print("%s: hook definitions and owned files %s; native trust, load, and event delivery cannot be attested"
          % ("OK" if files_ok and hooks_ok else "FAIL", "match" if files_ok and hooks_ok else "do not match"))
    return 0 if files_ok and hooks_ok else 1


def remove(codex_home):
    home = _absolute(codex_home, "codex_home")
    root = home / "necessity-review"
    with _lock(home):
        manifest = _manifest(root)
        hooks_path = home / "hooks.json"
        previous = hooks_path.read_bytes() if hooks_path.exists() else None
        hooks = _json(hooks_path, missing={})
        command = manifest["command"]
        bound = _exact_hooks(hooks, command, manifest["timeout"])
        legacy = _exact_legacy_hooks(hooks, command, manifest["timeout"])
        if not bound and not legacy:
            raise InstallError("incomplete removal: modified or duplicate owned definitions; resolve ownership first")
        if len(_any_owned_entries(hooks, command)) != len(EVENTS):
            raise InstallError("owned necessity hook was modified or co-owned; refusing incomplete removal")
        hook_map = _hook_map(hooks)
        for event in list(hook_map):
            groups = hook_map[event]
            for group in list(groups):
                # A modified or co-owned group is no longer exclusively ours.
                if event in EVENTS:
                    expected = _entry(command if legacy else _event_command(command, event), manifest["timeout"])
                else:
                    expected = None
                if expected is not None and group == {"hooks": [expected]}:
                    groups.remove(group)
            if not groups:
                del hook_map[event]
        if hooks_path.exists() and hooks_path.read_bytes() != previous:
            raise InstallError("hooks.json changed during removal")
        if previous is not None:
            _atomic(hooks_path, (json.dumps(hooks, sort_keys=True, indent=2) + "\n").encode())
        for name, digest in manifest["files"].items():
            path = root / name
            if path.is_file() and not path.is_symlink() and _digest(path) == digest:
                path.unlink()
        manifest_path = root / MANIFEST
        # Retain an altered manifest as evidence rather than deleting it.
        manifest_path.unlink()
    return 0


def _status_rows(database, limit):
    uri = database.resolve().as_uri() + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True)
        try:
            columns = {row[1] for row in db.execute("PRAGMA table_info(candidates)")}
            if not columns:
                return [], 0
            if not {"id", "status", "result"}.issubset(columns):
                raise InstallError("necessity state candidates schema is malformed")
            query = "SELECT id,status,result" + (",resolution" if "resolution" in columns else "") + " FROM candidates ORDER BY rowid DESC"
            rows = db.execute(query).fetchall()
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise InstallError("cannot read necessity state") from exc
    entries = []
    omitted = 0
    for row in rows:
        candidate, status, raw_result = row[:3]
        raw_resolution = row[3] if len(row) == 4 else None
        result = None
        elapsed = usage = None
        if raw_result:
            try:
                saved = json.loads(raw_result)
            except (TypeError, ValueError):
                saved = {"state": "invalid saved result"}
            if isinstance(saved, dict):
                elapsed, usage = saved.pop("elapsed_seconds", None), saved.pop("usage", None)
                # Candidate reports intentionally contain only review verdict
                # fields, never session prompt/contract data.
                result = saved
            else:
                result = {"state": "invalid saved result"}
        try:
            resolution = json.loads(raw_resolution) if raw_resolution else None
        except (TypeError, ValueError):
            resolution = {"state": "invalid saved resolution"}
        entry = {"candidate_id": candidate, "status": status, "result": result,
                 "elapsed_seconds": elapsed, "usage": usage, "resolution": resolution}
        proposed = {"candidates": entries + [entry], "omitted": 0,
                    "native": "trust, load, and event delivery are not attested"}
        if len(json.dumps(proposed, ensure_ascii=False).encode("utf-8")) > limit:
            omitted += 1
        else:
            entries.append(entry)
    return entries, omitted


def _diagnostic_rows(database, limit, candidates, candidate_omitted):
    """Read hook-failure metadata when newer state has the diagnostics table."""
    uri = database.resolve().as_uri() + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True)
        try:
            columns = {row[1] for row in db.execute("PRAGMA table_info(diagnostics)")}
            if not {"id", "touched", "data"}.issubset(columns):
                return [], 0
            rows = db.execute("SELECT id,data FROM diagnostics ORDER BY rowid DESC").fetchall()
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise InstallError("cannot read necessity state") from exc
    entries = []
    omitted = 0
    fields = ("reason_code", "event", "tool", "scope", "input_bytes",
              "review_limit_bytes", "evidence_sha256", "status")
    for identifier, raw_data in rows:
        try:
            metadata = json.loads(raw_data)
        except (TypeError, ValueError):
            omitted += 1
            continue
        if not isinstance(identifier, str) or not isinstance(metadata, dict):
            omitted += 1
            continue
        # Stored diagnostics are deliberately metadata-only.  Do not turn a
        # malformed or future record into a reportable candidate.
        metadata = {field: metadata[field] for field in fields if field in metadata}
        if metadata.get("status") != "unassessed":
            omitted += 1
            continue
        entry = {"diagnostic_id": identifier, "data": metadata}
        proposed = {"candidates": candidates, "omitted": candidate_omitted,
                    "diagnostics": entries + [entry], "diagnostics_omitted": omitted,
                    "native": "trust, load, and event delivery are not attested"}
        if len(json.dumps(proposed, ensure_ascii=False).encode("utf-8")) > limit:
            omitted += 1
        else:
            entries.append(entry)
    return entries, omitted


def status(codex_home):
    """Report persisted candidate outcomes without modifying SQLite or state."""
    home = _absolute(codex_home, "codex_home")
    root = home / "necessity-review"
    try:
        if root.is_symlink():
            raise InstallError("refusing symlink installation root")
        _manifest(root)
        config = _settings(root / CONFIG)
        state = Path(config["state_dir"])
        if state.is_symlink():
            raise InstallError("refusing symlink state directory")
        database = state / "necessity.sqlite3"
        if database.is_symlink():
            raise InstallError("refusing symlink state file")
        if not database.exists():
            document = {"candidates": [], "omitted": 0, "diagnostics": [], "diagnostics_omitted": 0,
                        "state": "no persisted candidate events",
                        "native": "trust, load, and event delivery are not attested"}
        else:
            candidates, omitted = _status_rows(database, config["max_output_bytes"])
            diagnostics, diagnostics_omitted = _diagnostic_rows(
                database, config["max_output_bytes"], candidates, omitted)
            document = {"candidates": candidates, "omitted": omitted,
                        "diagnostics": diagnostics, "diagnostics_omitted": diagnostics_omitted,
                        "native": "trust, load, and event delivery are not attested"}
        if len(json.dumps(document, ensure_ascii=False).encode("utf-8")) > config["max_output_bytes"]:
            # A valid compact report is preferable to truncating JSON or hiding
            # that records were omitted.  Tiny configured limits cannot hold
            # the normal native-attestation text.
            document = {"omitted": document.get("omitted", 0) + len(document.get("candidates", [])),
                        "diagnostics_omitted": document.get("diagnostics_omitted", 0)
                        + len(document.get("diagnostics", []))}
        print(json.dumps(document, ensure_ascii=True))
        return 0
    except (InstallError, OSError) as exc:
        print(("FAIL: %s" % exc).encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr)
        return 1


_CREDENTIAL = re.compile(r"(?:gh[pous]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|"
                         r"AKIA[0-9A-Z]{16}|(?:token|password|secret|authorization)\s*[:=])", re.I)


def record(codex_home, candidate_id, outcome, evidence):
    """Acknowledge a delivered candidate without changing its review verdict."""
    if outcome not in {"handled", "deferred", "unassessed"}:
        raise InstallError("outcome must be handled, deferred, or unassessed")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise InstallError("candidate id is required")
    if not isinstance(evidence, str) or not evidence.strip():
        raise InstallError("evidence is required")
    if _CREDENTIAL.search(evidence):
        raise InstallError("evidence appears to contain a credential")
    home = _absolute(codex_home, "codex_home")
    root = home / "necessity-review"
    config = _settings(root / CONFIG)
    if len(evidence.encode("utf-8")) > config["max_output_bytes"]:
        raise InstallError("evidence exceeds configured output bound")
    database = Path(config["state_dir"]) / "necessity.sqlite3"
    if database.is_symlink() or not database.is_file():
        raise InstallError("necessity state database is unavailable")
    resolution = json.dumps({"outcome": outcome, "evidence": evidence}, ensure_ascii=False)
    try:
        db = sqlite3.connect(database, timeout=config["deadline_seconds"], isolation_level=None)
        try:
            columns = {row[1] for row in db.execute("PRAGMA table_info(candidates)")}
            if "resolution" not in columns:
                raise InstallError("necessity state schema does not support recorded resolutions")
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT session FROM candidates WHERE id=?", (candidate_id,)).fetchall()
            if not rows:
                raise InstallError("candidate id was not found")
            if len(rows) != 1:
                raise InstallError("candidate id is ambiguous")
            db.execute("UPDATE candidates SET resolution=? WHERE session=? AND id=?",
                       (resolution, rows[0][0], candidate_id))
            db.commit()
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise InstallError("cannot record necessity resolution") from exc
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "check"):
        item = commands.add_parser(name)
        item.add_argument("--codex-home", required=True)
        item.add_argument("--settings", required=(name == "install"))
    item = commands.add_parser("remove")
    item.add_argument("--codex-home", required=True)
    item = commands.add_parser("status")
    item.add_argument("--codex-home", required=True)
    item = commands.add_parser("record")
    item.add_argument("--codex-home", required=True)
    item.add_argument("--candidate", required=True)
    item.add_argument("--outcome", required=True, choices=("handled", "deferred", "unassessed"))
    item.add_argument("--evidence", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            return install(args.codex_home, args.settings)
        if args.command == "check":
            return check(args.codex_home, args.settings)
        if args.command == "status":
            return status(args.codex_home)
        if args.command == "record":
            return record(args.codex_home, args.candidate, args.outcome, args.evidence)
        return remove(args.codex_home)
    except InstallError as exc:
        print(("FAIL: %s" % exc).encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
