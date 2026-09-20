"""Behavioral tests for native event handling; no model or user configuration."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "necessity_review"
from necessity_review import necessity_hook as hook
from necessity_review import necessity_install as installer
from necessity_review import necessity_review as review

PWSH = shutil.which("pwsh") or shutil.which("pwsh.exe")
if PWSH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "PowerShell" / "7" / "pwsh.exe"
    PWSH = str(candidate) if candidate.is_file() else None


class HookTests(unittest.TestCase):
    @unittest.skipUnless(PWSH, "requires native PowerShell parser")
    def test_saved_orientation_review_decision_is_not_overridden_by_grouping(self):
        fixture = json.loads((BIN.parent / "tests/fixtures/necessity-orientation.json").read_text())
        self.cfg.update(shell="pwsh", deadline_seconds=10)
        self.disposition = "normal"
        self.prompt(fixture["contract"])
        for case in fixture["cases"]:
            with self.subTest(candidate=case["original_candidate_id"]):
                before = len(self.calls)
                output = self.event("PreToolUse", tool_name="Bash", tool_input={"command": case["operation"]})
                self.assertEqual(before + 1, len(self.calls))
                self.assertEqual(case["operation"], self.calls[-1]["operation"])
                self.assertEqual(fixture["contract"], self.calls[-1]["contract"])
                self.assertEqual(["multiple-responsibilities"], self.calls[-1]["features"])
                self.assertNotEqual("deny", output.get("hookSpecificOutput", {}).get("permissionDecision"))
        # Read-only grouping remains reviewable for semantic irrelevance.
        self.action = "revise"
        output = self.event("PreToolUse", tool_name="Bash", tool_input={"command":
            fixture["cases"][1]["operation"] + "; Get-Content unrelated.txt"})
        self.assertEqual("deny", output["hookSpecificOutput"]["permissionDecision"])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = dict(version=1, shell="bash", scopes=[str(self.root)], excludes=[], state_dir=str(self.root / "state"),
                        model="fixture", effort="low", deadline_seconds=2, max_input_bytes=65536,
                        max_output_bytes=65536, reviews_per_session=5, retention_seconds=3600, max_sessions=10)
        self.calls = []
        self.disposition = "disposable"
        self.action = "continue"

    def reviewer(self, request, config):
        self.calls.append(request)
        return dict(candidate_id=request["candidate_id"], action=self.action, disposition=self.disposition,
                    reason="Needed bounded fixture for the explicit request.", protections="Preserve cleanup and evidence.",
                    owner_or_entry="", next_step="Continue the requested fixture.")

    def event(self, event, **kw):
        return hook.handle(dict(hook_event_name=event, cwd=str(self.root), session_id="root", turn_id="turn1", **kw), self.cfg, self.reviewer)

    def lane_event(self, lane, event, session_id="root", **kw):
        return hook.handle(dict(hook_event_name=event, cwd=str(self.root), session_id=session_id, agent_id=lane,
                                turn_id="turn1", **kw), self.cfg, self.reviewer)

    def lane_state(self, lane, session_id="root"):
        sid = hook.digest([str(self.root.resolve()), session_id, lane])
        db = sqlite3.connect(self.root / "state" / "necessity.sqlite3")
        encoded = db.execute("SELECT data FROM sessions WHERE id=?", (sid,)).fetchone()[0]
        db.close()
        return json.loads(encoded)

    def prompt(self, text="Verify a bounded subprocess fixture and return its result."):
        return self.event("UserPromptSubmit", prompt=text)

    def intake(self, payload, event=None):
        config = self.root / "intake.json"
        config.write_text(json.dumps(self.cfg))
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--config", str(config)] + (["--event", event] if event else [])
        with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw))), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = hook.main(argv)
        return code, json.loads(stdout.getvalue()) if stdout.getvalue() else None, stderr.getvalue()

    def test_native_irrelevant_payload_sizes_do_not_open_state(self):
        for size in (8, 65537, 262144):
            for change in ({"cwd": str(self.root.parent)}, {"cwd": str(self.root / "excluded")},
                           {"tool_name": "view_image"}, {"hook_event_name": "UnrelatedEvent"}):
                with self.subTest(size=size, change=change):
                    self.cfg["excludes"] = [str(self.root / "excluded")]
                    payload = dict(hook_event_name="PostToolUse", cwd=str(self.root), session_id="root",
                                   tool_name="Bash", tool_input={"command": "echo hello"},
                                   tool_response={"data": "A" * size})
                    payload.update(change)
                    with patch.object(hook, "Store", side_effect=AssertionError("state opened")), patch.object(hook, "safe_text", side_effect=AssertionError("content selected")):
                        self.assertEqual(self.intake(payload), (0, {}, ""))
        self.assertFalse((self.root / "state").exists())

    def test_large_post_result_is_never_selected_or_persisted(self):
        self.prompt()
        payload = dict(hook_event_name="PostToolUse", cwd=str(self.root), session_id="root",
                       tool_name="Bash", tool_input={"command": "echo hello"},
                       tool_response={"exit_code": 0, "data": "RAW_IMAGE_MARKER" * 10000,
                                      "authorization": "Bearer SECRET_MARKER"})
        with patch.object(hook, "safe_text", side_effect=AssertionError("result sanitized")):
            self.assertEqual(self.intake(payload, "PostToolUse"), (0, {}, ""))
        self.assertEqual(self.calls, [])
        db = sqlite3.connect(self.root / "state" / "necessity.sqlite3")
        self.addCleanup(db.close)
        self.assertEqual(db.execute("SELECT count(*) FROM candidates").fetchone()[0], 0)
        self.assertEqual(json.loads(db.execute("SELECT data FROM sessions").fetchone()[0])["history"][-1]["outcome"], "succeeded")
        self.assertNotIn("MARKER", "\n".join(db.iterdump()))

    def test_pre_candidate_intake_diagnostics_are_safe_and_separate(self):
        raw = b'{"credential":"Bearer SECRET_MARKER", "image":"RAW_IMAGE_MARKER"'
        code, result, _ = self.intake(raw, "PostToolUse")
        self.assertEqual(code, 0)
        self.assertIn("unassessed", json.dumps(result))
        self.assertIn("saved", json.dumps(result))
        db = sqlite3.connect(self.root / "state" / "necessity.sqlite3")
        self.addCleanup(db.close)
        self.assertEqual(db.execute("SELECT count(*) FROM candidates").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0], 0)
        info = json.loads(db.execute("SELECT data FROM diagnostics").fetchone()[0])
        self.assertEqual(info["reason_code"], "invalid_json")
        self.assertEqual(info["event"], "PostToolUse")
        self.assertEqual(info["scope"], "unknown")
        self.assertEqual(info["input_bytes"], len(raw))
        self.assertNotIn("MARKER", "\n".join(db.iterdump()))
        code, result, _ = self.intake(raw, "PreToolUse")
        self.assertEqual(code, 0)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_post_intake_and_diagnostic_failure_never_fail_delivery(self):
        payload = dict(hook_event_name="PostToolUse", cwd=str(self.root), session_id="root",
                       tool_name="Bash", tool_input={"command": "echo hello"})
        for failure in (RuntimeError("SECRET_MARKER"), sqlite3.OperationalError("SECRET_MARKER")):
            with patch.object(hook, "Store", side_effect=failure):
                code, result, _ = self.intake(payload, "PostToolUse")
            self.assertEqual(code, 0)
            self.assertIn("unassessed", json.dumps(result))
            self.assertNotIn("SECRET_MARKER", json.dumps(result))
        with patch.object(hook, "load_config", side_effect=ValueError("SECRET_MARKER")):
            self.assertEqual(self.intake(payload, "PostToolUse")[0], 0)
        for malformed in (b'[]', b'{"hook_event_name":[]}', b'not JSON'):
            self.assertEqual(self.intake(malformed, "PostToolUse")[0], 0)
            self.assertEqual(self.intake(malformed, "PreToolUse")[1]["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_selected_large_command_remains_unassessed_without_review(self):
        for event in ("PreToolUse", "PostToolUse"):
            payload = dict(hook_event_name=event, cwd=str(self.root), session_id="root",
                           tool_name="Bash", tool_input={"command": "python3 -c '" + "A" * 65537 + "'"})
            code, result, _ = self.intake(payload, event)
            self.assertEqual(code, 0)
            self.assertIn("selected_command_too_large", json.dumps(result))
            if event == "PreToolUse":
                self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(self.calls)

    def command(self, cmd="python3 -c 'import subprocess; from pathlib import Path; Path(\"result\").write_text(\"pending\"); subprocess.run([\"true\"]); print(\"done\")'", **kw):
        return self.event("PreToolUse", tool_name="Bash", tool_use_id="tool1", tool_input={"command": cmd}, **kw)

    def managed_install(self, *, source=BIN, shell="bash"):
        """Install the actual hook files, including the recovery manifest pin."""
        home = self.root / "codex-home"
        settings = self.root / "necessity-settings.json"
        config = dict(self.cfg, shell=shell)
        settings.write_text(json.dumps(config), encoding="utf-8")
        launcher = self.root / "necessity-review"
        launcher.write_text("# fixture console launcher\n", encoding="utf-8")
        with patch.object(installer.sys, "argv", [str(launcher)]):
            self.assertEqual(installer.install(home, settings, source=source), 0)
        return home, home / "necessity-review"

    def management_command(self, home, operation, *, source=BIN, shell="bash", extra=()):
        argv = [str(self.root / "necessity-review"), operation, *extra]
        if shell == "bash":
            return " ".join(shlex.quote(word) for word in argv)
        return "& " + " ".join("'%s'" % word.replace("'", "''") for word in argv)

    def management_payload(self, command, event="PreToolUse", *, shell="bash", session="recovery"):
        return dict(hook_event_name=event, cwd=str(self.root), session_id=session, turn_id="recovery",
                    tool_name="Bash", tool_use_id="recovery-tool",
                    tool_input={"command": command, "shell": shell})

    def assert_recovery_without_state(self, installed, payload):
        previous_calls = len(self.calls)
        source_parent = Path(json.loads((installed / installer.MANIFEST).read_text())["management"]["source"]).parent
        script_path = [str(installed), str(source_parent)] + [item for item in hook.sys.path if Path(item or ".").resolve() != BIN.resolve()]
        with patch.object(hook, "HERE", installed), patch.object(hook.sys, "path", script_path), patch.object(hook, "Store", side_effect=AssertionError("state opened")):
            self.assertEqual(hook.handle(payload, self.cfg, self.reviewer), {})
        self.assertEqual(len(self.calls), previous_calls)

    def assert_not_recovery(self, installed, payload):
        source_parent = Path(json.loads((installed / installer.MANIFEST).read_text())["management"]["source"]).parent
        script_path = [str(installed), str(source_parent)] + [item for item in hook.sys.path if Path(item or ".").resolve() != BIN.resolve()]
        with patch.object(hook, "HERE", installed), patch.object(hook.sys, "path", script_path), patch.object(hook, "Store", side_effect=RuntimeError("state opened")):
            with self.assertRaisesRegex(RuntimeError, "state opened"):
                hook.handle(payload, self.cfg, self.reviewer)

    def test_owned_management_recovery_needs_no_request_or_state_for_pre_and_post(self):
        home, installed = self.managed_install()
        japanese_evidence = '既存の確認結果: "引用符を含む"。例: `python place.py necessity check`。'
        commands = [
            self.management_command(home, "--help"),
            self.management_command(home, "check", extra=("--codex-home", str(home))),
            self.management_command(home, "status", extra=("--codex-home", str(home))),
            self.management_command(home, "record", extra=("--codex-home", str(home), "--candidate", "candidate-1",
                                                             "--outcome", "deferred", "--evidence", japanese_evidence)),
            self.management_command(home, "remove", extra=("--codex-home", str(home))),
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assert_recovery_without_state(installed, self.management_payload(command))
                self.assert_recovery_without_state(installed, self.management_payload(command, "PostToolUse"))

    @unittest.skipUnless(PWSH, "pwsh is unavailable")
    def test_owned_management_recovery_is_literal_in_powershell(self):
        # A cold native PowerShell parser can exceed this fixture's ordinary
        # two-second review deadline in CI; this test-only allowance matches
        # the selector's native-parser test basis.
        self.cfg["deadline_seconds"] = 10
        home, installed = self.managed_install(shell="pwsh")
        evidence = '日本語の証跡: "引用" と `Get-Date` は単なる記録です。'
        for operation, extra in (
            ("--help", ()),
            ("check", ("--codex-home", str(home))),
            ("status", ("--codex-home", str(home))),
            ("record", ("--codex-home", str(home), "--candidate", "candidate-1", "--outcome", "handled", "--evidence", evidence)),
            ("remove", ("--codex-home", str(home))),
        ):
            command = self.management_command(home, operation, shell="pwsh", extra=extra)
            with self.subTest(operation=operation):
                with patch.object(hook.necessity_select.shutil, "which", return_value=PWSH):
                    self.assert_recovery_without_state(installed, self.management_payload(command, shell="pwsh"))
                    self.assert_recovery_without_state(installed, self.management_payload(command, "PostToolUse", shell="pwsh"))

    def test_management_recovery_bypasses_actual_full_state_budgets(self):
        self.cfg.update(max_sessions=1, reviews_per_session=1)
        self.prompt()
        self.action, self.disposition = "unassessed", "unassessed"
        self.command()
        self.assertEqual(len(self.calls), 1)
        home, installed = self.managed_install()
        command = self.management_command(home, "status", extra=("--codex-home", str(home)))
        # The retained candidate consumes the only candidate budget and a new
        # session would also exceed the actual session capacity.
        self.assert_recovery_without_state(installed, self.management_payload(command, session="different-session"))

    def test_management_recovery_remains_available_after_reviewer_timeout_denial(self):
        self.prompt()
        payload = self.management_payload(self.command.__defaults__[0])
        def timed_out(request, config):
            raise TimeoutError("fixture reviewer timed out")
        denied = hook.handle(payload, self.cfg, timed_out)
        self.assertEqual(denied["hookSpecificOutput"]["permissionDecision"], "deny")
        home, installed = self.managed_install()
        recovery = self.management_command(home, "check", extra=("--codex-home", str(home)))
        self.assert_recovery_without_state(installed, self.management_payload(recovery))

    def test_recovery_refuses_unowned_or_evaluated_management_shapes(self):
        home, installed = self.managed_install()
        good = self.management_command(home, "check", extra=("--codex-home", str(home)))
        other = self.root / "other-source"
        other.mkdir()
        other_place = other / "place.py"
        other_place.write_text("# same name, not the pinned source\n", encoding="utf-8")
        cases = {
            "absolute launcher": str(self.root / "other-launcher") + " check --codex-home " + str(home),
            "wrong home": self.management_command(self.root / "other-home", "check", extra=("--codex-home", str(self.root / "other-home"))),
            "appended command": good + "; echo unexpected",
            "redirect": good + " > recovery.log",
            "evaluation": "eval " + shlex.quote(good),
        }
        for label, command in cases.items():
            with self.subTest(label=label):
                self.assert_not_recovery(installed, self.management_payload(command))

    def test_recovery_refuses_modified_pinned_source_without_mutating_public_source(self):
        copied = self.root / "pinned-source-copy" / "necessity_review"
        copied.parent.mkdir()
        shutil.copytree(BIN, copied)
        home, installed = self.managed_install(source=copied)
        command = self.management_command(home, "check", source=copied, extra=("--codex-home", str(home)))
        self.assert_recovery_without_state(installed, self.management_payload(command))
        (copied / "necessity_install.py").write_text("# modified only in this fixture copy\n", encoding="utf-8")
        self.assert_not_recovery(installed, self.management_payload(command))

    def test_recovery_refuses_symlink_alias_of_pinned_script_with_malicious_sibling(self):
        home, installed = self.managed_install()
        alias = self.root / "script-alias"
        alias.mkdir()
        link = alias / "necessity-review"
        try:
            link.symlink_to(BIN / "necessity_install.py")
        except OSError as exc:
            self.skipTest("symlink creation is unavailable: %s" % exc)
        # This file must remain data in the test: the hook must not allow a
        # recovery call through the link, so it is never imported or executed.
        (alias / "necessity_install.py").write_text("raise RuntimeError('malicious sibling')\n", encoding="utf-8")
        command = str(link) + " status --codex-home " + str(home)
        self.assert_not_recovery(installed, self.management_payload(command))

    @unittest.skipUnless(os.name == "nt", "Windows short-path aliases are unavailable")
    def test_recovery_accepts_pinned_source_and_home_short_path_aliases(self):
        import ctypes
        source = self.root / "public source with spaces"
        home = self.root / "codex home with spaces"
        shutil.copytree(BIN, source)
        settings = self.root / "necessity-settings.json"
        settings.write_text(json.dumps(self.cfg), encoding="utf-8")
        self.assertEqual(installer.install(home, settings, source=source), 0)

        def short_path(path):
            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
            if not length or length >= len(buffer):
                self.skipTest("Windows short-path aliases are disabled")
            return Path(buffer.value)

        short_source, short_home = short_path(source), short_path(home)
        if (os.path.normcase(str(short_source)) == os.path.normcase(str(source)) or
                os.path.normcase(str(short_home)) == os.path.normcase(str(home))):
            self.skipTest("fixture directories have no distinct Windows short-path aliases")
        command = self.management_command(short_home, "status", source=short_source,
                                          extra=("--codex-home", str(short_home)))
        self.assert_recovery_without_state(home / "necessity-review", self.management_payload(command))

    def test_reviewer_child_tool_prohibition_precedes_management_recovery(self):
        home, installed = self.managed_install()
        payload = self.management_payload(self.management_command(home, "status", extra=("--codex-home", str(home))))
        with patch.object(hook, "HERE", installed), patch.dict(os.environ, {"AGENT_RULES_NECESSITY_REVIEWER": "1"}):
            result = hook.handle(payload, self.cfg, self.reviewer)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    @unittest.skipUnless(PWSH, "pwsh is unavailable")
    def test_generated_python_still_reviews_after_powershell_patch_observation(self):
        # Match the existing parser-test allowance for cold PowerShell CI startup.
        self.cfg["deadline_seconds"] = 10
        self.cfg["shell"] = "pwsh"
        self.prompt()
        script = self.root / "generated.py"
        script.write_text("print('generated')\n", encoding="utf-8")
        self.event("PostToolUse", tool_name="apply_patch", tool_use_id="ps-write",
                   tool_input={"command": "*** Begin Patch\n*** Add File: generated.py\n+print('generated')\n*** End Patch"},
                   tool_response={"exit_code": 0})
        command = "python 'generated.py'"
        with patch.object(hook.necessity_select.shutil, "which", return_value=PWSH):
            result = self.event("PreToolUse", tool_name="Bash", tool_use_id="ps-run",
                                tool_input={"command": command, "shell": "pwsh"})
        self.assertNotIn("permissionDecision", result["hookSpecificOutput"])
        self.assertEqual(len(self.calls), 1)

    def test_negative_no_model_and_no_permission_grant(self):
        self.prompt()
        self.assertEqual(self.command("git status --short"), {})
        self.assertEqual(self.command("git commit -m '" + "long literal " * 500 + "'"), {})
        self.assertEqual(self.calls, [])
        result = self.command()
        self.assertNotIn("permissionDecision", result["hookSpecificOutput"])
        self.assertEqual(len(self.calls), 1)

    def test_duplicate_and_changed_contract(self):
        self.prompt()
        self.command()
        self.command()
        self.assertEqual(len(self.calls), 1)
        self.prompt("Only read repository status. Do not construct any fixture.")
        self.command()
        self.assertEqual(len(self.calls), 2)

    def test_missing_or_expired_continuation_does_not_certify_history(self):
        self.assertEqual(self.event("SessionStart", source="startup"), {})
        empty = self.event("SessionStart", source="resume")
        self.assertIn("missing history", empty["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.calls, [])
        self.prompt()
        self.command()
        with patch.object(hook.time, "time", return_value=time.time() + self.cfg["retention_seconds"] + 1):
            expired = self.event("SessionStart", source="compact")
        self.assertIn("unassessed", expired["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(len(self.calls), 1)

    def test_capacity_refuses_new_lane_without_evicting_pending(self):
        self.cfg["max_sessions"] = 1
        self.prompt()
        self.action, self.disposition = "unassessed", "unassessed"
        self.command()
        with self.assertRaisesRegex(ValueError, "capacity"):
            hook.handle(dict(hook_event_name="SessionStart", cwd=str(self.root), session_id="other",
                             source="resume"), self.cfg, self.reviewer)
        restored = self.event("SessionStart", source="resume")
        self.assertIn(self.calls[0]["candidate_id"], restored["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(len(self.calls), 1)

    def test_denial_stop_once_resume_pending(self):
        self.prompt()
        self.action, self.disposition = "unassessed", "unassessed"
        result = self.command()
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(self.event("Stop", stop_hook_active=False)["decision"], "block")
        self.assertEqual(self.event("Stop", stop_hook_active=True), {})
        self.assertEqual(self.event("Stop", stop_hook_active=False), {})
        # A compact/resume must restore the unresolved judgment, but it must not
        # reset the Stop notification and create another Stop loop.
        self.assertIn("additionalContext", self.event("SessionStart", source="compact")["hookSpecificOutput"])
        self.assertEqual(self.event("Stop", stop_hook_active=False), {})

    def test_worker_inherits_unique_parent_request_context(self):
        self.prompt("Parent request: construct the bounded fixture.")
        self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="worker-one",
                        tool_input={"command": self.command.__defaults__[0]})
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["contract"], "Parent request: construct the bounded fixture.")
        self.assertEqual(self.calls[0]["current_prompt"], "Parent request: construct the bounded fixture.")
        self.assertTrue(self.lane_state("worker")["request_origin"].startswith("inherited:"))

    def test_inherited_context_refreshes_when_parent_prompt_changes(self):
        self.prompt("Parent request: first bounded fixture.")
        command = self.command.__defaults__[0]
        self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="worker-one", tool_input={"command": command})
        self.prompt("Parent request: revised bounded fixture requirements.")
        self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="worker-two", tool_input={"command": command})
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[-1]["current_prompt"], "Parent request: revised bounded fixture requirements.")

    def test_cross_family_and_ambiguous_requests_are_unassessed(self):
        self.prompt("Root family request.")
        cross_family = self.lane_event("worker", "PreToolUse", session_id="other-session", tool_name="Bash",
                                       tool_use_id="cross", tool_input={"command": self.command.__defaults__[0]})
        self.assertEqual(cross_family["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(self.calls)
        self.lane_event("other-parent", "UserPromptSubmit", prompt="A different direct request.")
        ambiguous = self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="ambiguous",
                                    tool_input={"command": self.command.__defaults__[0]})
        self.assertEqual(ambiguous["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(self.calls)
        self.assertEqual(self.lane_state("worker")["request_origin"], "ambiguous")

    def test_explicit_child_prompt_supersedes_inherited_context(self):
        self.prompt("Parent request: bounded fixture.")
        command = self.command.__defaults__[0]
        self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="worker-one", tool_input={"command": command})
        self.lane_event("worker", "UserPromptSubmit", prompt="Child request: inspect only this fixture.")
        self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="worker-two", tool_input={"command": command})
        self.prompt("Parent request: changed again.")
        self.lane_event("worker", "PreToolUse", tool_name="Bash", tool_use_id="worker-three", tool_input={"command": command})
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[-1]["contract"], "Child request: inspect only this fixture.")
        self.assertEqual(self.calls[-1]["current_prompt"], "Child request: inspect only this fixture.")
        self.assertEqual(self.lane_state("worker")["request_origin"], "direct")

    def test_missing_contract_secret_and_bad_schema_never_approve(self):
        self.assertEqual(self.command()["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(self.calls)
        self.prompt("Store token=ghp_examplecredential then continue")
        self.assertEqual(self.command()["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(self.calls)
        self.prompt()
        self.disposition = "invented"
        result = self.command()
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertNotIn("ghp_example", json.dumps(result))

    def test_child_and_excluded_scope_do_not_review(self):
        self.prompt()
        with patch.dict(os.environ, {"AGENT_RULES_NECESSITY_REVIEWER": "1"}):
            self.assertEqual(self.command()["hookSpecificOutput"]["permissionDecision"], "deny")
        self.cfg["excludes"] = [str(self.root)]
        self.assertEqual(self.command(), {})
        self.assertEqual(self.calls, [])

    def test_invalid_and_unsupported_are_not_safe(self):
        self.prompt()
        result = self.event("PreToolUse", tool_name="Bash", tool_use_id="bad", tool_input={"command": "unknown syntax", "shell": "unknown-shell"})
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse(self.calls)

    def test_generated_script_and_content_change(self):
        self.prompt()
        script = self.root / "fixture"
        script.write_text("print('hello')")
        self.event("PostToolUse", tool_name="apply_patch", tool_use_id="write1",
                   tool_input={"command": "*** Begin Patch\n*** Add File: fixture\n+print('hello')\n*** End Patch"}, tool_response={"exit_code": 0})
        self.command("python3 fixture")
        self.assertEqual(len(self.calls), 1)
        script.write_text("print('changed')")
        self.command("python3 fixture")
        self.assertEqual(len(self.calls), 2)

    def test_two_concurrent_same_candidates_invoke_once(self):
        self.prompt()
        started, finish = threading.Event(), threading.Event()
        def blocking(request, cfg):
            started.set()
            finish.wait(2)
            return self.reviewer(request, cfg)
        payload = dict(hook_event_name="PreToolUse", cwd=str(self.root), session_id="root", turn_id="turn1", tool_name="Bash", tool_use_id="same", tool_input={"command": "python3 -c 'import subprocess; from pathlib import Path; Path(\"result\").write_text(\"pending\"); subprocess.run([\"true\"]); print(1)'"})
        errors = []
        def first():
            try:
                hook.handle(payload, self.cfg, blocking)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(started.wait(2))
        try:
            second = hook.handle(payload, self.cfg, self.reviewer)
            self.assertEqual(second["hookSpecificOutput"]["permissionDecision"], "deny")
        finally:
            finish.set()
            thread.join(3)
        self.assertFalse(errors)
        self.assertEqual(len(self.calls), 1)

    def test_schema_candidate_and_enum(self):
        value = self.reviewer({"candidate_id": "one"}, {})
        review.validate(value, "one")
        with self.assertRaises(ValueError):
            review.validate(value, "two")

    def test_bounded_subprocess_timeout_and_output(self):
        with self.assertRaisesRegex(ValueError, "deadline"):
            review.bounded_run([sys.executable, "-c", "import time; time.sleep(5)"], "", cwd=self.root, env=os.environ.copy(), deadline=0.1, limit=100)
        with self.assertRaisesRegex(ValueError, "output limit"):
            review.bounded_run([sys.executable, "-c", "print('x'*10000)"], "", cwd=self.root, env=os.environ.copy(), deadline=2, limit=100)

    @unittest.skipUnless(os.environ.get("AGENT_RULES_NECESSITY_LIVE") == "1", "explicit limited Codex connection only")
    @unittest.skipUnless(PWSH, "requires native PowerShell parser")
    def test_live_saved_orientation_review_only(self):
        # Replay reported shapes without executing them or changing native hooks.
        fixture = json.loads((BIN.parent / "tests/fixtures/necessity-orientation.json").read_text())
        self.cfg.update(shell="pwsh", model="gpt-5.6-terra", effort="low",
                        deadline_seconds=24, reviews_per_session=2)
        if os.environ.get("AGENT_RULES_NECESSITY_CODEX_EXECUTABLE"):
            self.cfg["codex_executable"] = os.environ["AGENT_RULES_NECESSITY_CODEX_EXECUTABLE"]
        self.prompt(fixture["contract"])
        results = []
        def live(request, config):
            started = time.monotonic()
            result = review.review(request, config)
            results.append(dict(result))
            print(json.dumps({"kind": "saved-orientation-equivalent-review-not-native-delivery",
                              "source_candidate": case["original_candidate_id"],
                              "request": request, "result": result,
                              "model": config["model"], "elapsed_seconds": time.monotonic() - started}))
            return result
        for case in fixture["cases"]:
            payload = dict(hook_event_name="PreToolUse", cwd=str(self.root), session_id="root", turn_id="turn1",
                           tool_name="Bash", tool_input={"command": case["operation"]})
            before = len(results)
            output = hook.handle(payload, self.cfg, live)
            # Stop at the first failure; do not sample repeatedly for a pass.
            self.assertEqual(before + 1, len(results), output)
            self.assertEqual(("continue", "normal"), (results[-1]["action"], results[-1]["disposition"]), output)
            self.assertNotEqual("deny", output.get("hookSpecificOutput", {}).get("permissionDecision"))

    @unittest.skipUnless(os.environ.get("AGENT_RULES_NECESSITY_LIVE") == "1", "explicit limited Codex connection only")
    def test_live_reviewer_round_trip_not_native_hook_delivery(self):
        # One candidate and the existing review role; this does not execute the
        # candidate, trust hooks, or prove native hook loading/delivery.
        self.cfg.update(model="gpt-5.6-terra", effort="low", deadline_seconds=600, reviews_per_session=1)
        if os.environ.get("AGENT_RULES_NECESSITY_CODEX_EXECUTABLE"):
            self.cfg["codex_executable"] = os.environ["AGENT_RULES_NECESSITY_CODEX_EXECUTABLE"]
        self.prompt("Review a proposed one-off subprocess fixture. No existing fixture was found. The requested acceptance needs creating a disposable result file, running a child once, returning its result and cleanup. Judge the supplied candidate only; do not execute it.")
        payload = dict(hook_event_name="PreToolUse", cwd=str(self.root), session_id="root", turn_id="live",
                       tool_name="Bash", tool_use_id="live-one", tool_input={"command": "python3 -c 'import subprocess; from pathlib import Path; Path(\"result\").write_text(\"pending\"); subprocess.run([\"true\"], check=True); print(\"fixture complete\")'"})
        output = hook.handle(payload, self.cfg, review.review)
        db = sqlite3.connect(self.root / "state" / "necessity.sqlite3")
        record = json.loads(db.execute("SELECT result FROM candidates").fetchone()[0])
        db.close()
        evidence = {"kind": "direct-adapter-real-review-not-native-delivery", "model": self.cfg["model"],
                    "effort": self.cfg["effort"], "result": record, "hook_output": output}
        target = os.environ.get("AGENT_RULES_NECESSITY_LIVE_RESULT")
        if target:
            Path(target).write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.assertIn(record["action"], {"continue", "revise"}, record)
        self.assertIn("candidate_id", record)
        self.assertIsNotNone(record["usage"], "usage unavailable, not zero")


if __name__ == "__main__":
    unittest.main()
