"""The opt-in installer preserves native hook configuration it does not own."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("necessity_install_test", ROOT / "necessity_review" / "necessity_install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class NecessityInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.home = root / "codex"
        self.source = root / "public-bin"
        self.source.mkdir()
        self.launcher = root / "necessity-review"
        self.launcher.write_text("# fixture console launcher\n", encoding="utf-8")
        self.argv_patch = patch.object(installer.sys, "argv", [str(self.launcher)])
        self.argv_patch.start()
        self.addCleanup(self.argv_patch.stop)
        for name in set(installer.FILES) | {"__init__.py", "necessity_install.py"}:
            source = Path(installer.__file__).with_name(name)
            (self.source / name).write_bytes(source.read_bytes())
        self.settings = root / "settings.json"
        self.settings.write_text(json.dumps({
            "version": 1, "scopes": [str(root / "work")], "excludes": [],
            "state_dir": str(root / "state"), "model": "gpt-test", "effort": "low",
            "deadline_seconds": 5, "max_input_bytes": 20, "max_output_bytes": 20,
            "reviews_per_session": 1, "retention_seconds": 20, "max_sessions": 1,
            "shell": "pwsh" if os.name == "nt" else "bash",
        }), encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_windows_pwsh_requirement_precedes_install_mutation_and_check(self):
        settings = json.loads(self.settings.read_text(encoding="utf-8"))
        settings["shell"] = "powershell"
        self.settings.write_text(json.dumps(settings), encoding="utf-8")
        with patch.object(installer, "_is_windows", return_value=True):
            with self.assertRaisesRegex(installer.InstallError, 'shell: "pwsh"'):
                installer.install(self.home, self.settings, source=self.source)
        self.assertFalse(self.home.exists())
        settings["shell"] = "pwsh"
        self.settings.write_text(json.dumps(settings), encoding="utf-8")
        with patch.object(installer, "_is_windows", return_value=True), patch.object(installer.shutil, "which", return_value=None):
            with self.assertRaisesRegex(installer.InstallError, "PowerShell 7"):
                installer.install(self.home, self.settings, source=self.source)
        self.assertFalse(self.home.exists())
        completed = subprocess.CompletedProcess([], 0, "6\n", "")
        with patch.object(installer, "_is_windows", return_value=True), patch.object(installer.shutil, "which", return_value="pwsh"), patch.object(installer.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(installer.InstallError, "PowerShell 7"):
                installer.install(self.home, self.settings, source=self.source)
        self.assertFalse(self.home.exists())
        completed.stdout = "7\n"
        with patch.object(installer, "_is_windows", return_value=True), patch.object(installer.shutil, "which", return_value="pwsh"), patch.object(installer.subprocess, "run", return_value=completed):
            self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
            self.assertEqual(installer.check(self.home, self.settings), 0)
        with patch.object(installer, "_is_windows", return_value=True), patch.object(installer.shutil, "which", return_value=None):
            self.assertEqual(installer.check(self.home), 1)

    def test_status_json_survives_cp932_stdout(self):
        settings = json.loads(self.settings.read_text(encoding="utf-8"))
        settings["max_output_bytes"] = 4096
        self.settings.write_text(json.dumps(settings), encoding="utf-8")
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        state = Path(settings["state_dir"])
        state.mkdir()
        with sqlite3.connect(state / "necessity.sqlite3") as db:
            db.execute("CREATE TABLE candidates (session TEXT, id TEXT, status TEXT, result TEXT, resolution TEXT)")
            db.execute("INSERT INTO candidates VALUES (?,?,?,?,?)", (
                "session", "candidate", "reviewed", json.dumps({"reason": "431\u2013820"}, ensure_ascii=False), None))
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp932", errors="strict")
        with redirect_stdout(stream):
            self.assertEqual(installer.status(self.home), 0)
        stream.flush()
        self.assertTrue(raw.getvalue().isascii())
        self.assertEqual(json.loads(raw.getvalue())["candidates"][0]["result"]["reason"], "431\u2013820")

    def test_install_check_is_idempotent_and_remove_preserves_other_hook(self):
        self.home.mkdir()
        foreign = {"type": "command", "command": "/usr/bin/foreign"}
        original = {"hooks": {"Stop": [{"matcher": "x", "hooks": [foreign]}]}}
        (self.home / "hooks.json").write_text(json.dumps(original), encoding="utf-8")
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        installed = json.loads((self.home / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(installed["hooks"]["Stop"][0], original["hooks"]["Stop"][0])
        self.assertEqual(sum(len(g["hooks"]) for g in installed["hooks"]["Stop"]), 2)
        manifest = json.loads((self.home / "necessity-review" / installer.MANIFEST).read_text())
        for event in installer.EVENTS:
            group = installed["hooks"][event][-1]
            self.assertEqual(group["hooks"][0]["command"], manifest["command"] + " --event " + event)
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        self.assertEqual(installer.check(self.home), 0)
        self.assertEqual(installer.remove(self.home), 0)
        remaining = json.loads((self.home / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(remaining, original)
        self.assertFalse((self.home / "necessity-review" / "necessity_hook.py").exists())

    def test_tampered_owned_file_and_conflicting_config_refuse_overwrite(self):
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        owned = self.home / "necessity-review" / "necessity_hook.py"
        owned.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "differs"):
            installer.install(self.home, self.settings, source=self.source)
        self.assertEqual(owned.read_text(encoding="utf-8"), "changed")
        self.assertEqual(installer.check(self.home), 1)

    def test_rejects_malformed_hooks_and_missing_required_setting(self):
        self.home.mkdir()
        (self.home / "hooks.json").write_text('{"hooks": {"Stop": 5}}', encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "malformed"):
            installer.install(self.home, self.settings, source=self.source)
        data = json.loads(self.settings.read_text(encoding="utf-8"))
        del data["max_sessions"]
        self.settings.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "exactly"):
            installer.install(self.home, self.settings, source=self.source)

    def test_rejects_empty_scope_and_malformed_toml_before_writing(self):
        data = json.loads(self.settings.read_text(encoding="utf-8"))
        data["scopes"] = []
        self.settings.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "at least"):
            installer.install(self.home, self.settings, source=self.source)
        data["scopes"] = [str(self.temporary.name + "/work")]
        self.settings.write_text(json.dumps(data), encoding="utf-8")
        self.home.mkdir()
        (self.home / "config.toml").write_text("[broken", encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "malformed config.toml"):
            installer.install(self.home, self.settings, source=self.source)
        self.assertFalse((self.home / "necessity-review").exists())

    def test_spaces_quote_safely_and_windows_meta_is_rejected(self):
        spaced = Path(self.temporary.name) / "codex home"
        self.assertEqual(installer.install(spaced, self.settings, source=self.source), 0)
        command = json.loads((spaced / "necessity-review" / installer.MANIFEST).read_text())["command"]
        self.assertIn('"' if os.name == "nt" else "'", command)
        with self.assertRaisesRegex(installer.InstallError, "cmd metacharacters"):
            installer._command(Path("C:/bad%name/config.json"), windows=True)

    def test_manifest_pins_existing_management_entry_when_public_sources_are_present(self):
        (self.source / "place.py").write_text("# public entry\n", encoding="utf-8")
        (self.source / "necessity_install.py").write_text("# public installer\n", encoding="utf-8")
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        manifest = json.loads((self.home / "necessity-review" / installer.MANIFEST).read_text(encoding="utf-8"))
        management = manifest["management"]
        self.assertTrue(Path(management["launcher"]).is_absolute())
        self.assertEqual(management["home"], str(self.home))
        self.assertEqual(management["source"], str(self.source.resolve()))
        self.assertEqual(management["files"], {
            name: installer._digest(self.source / name)
            for name in ("__init__.py", "necessity_install.py", "necessity_hook.py", "necessity_review.py", "necessity_select.py", "necessity_parse.ps1")
        })
        (self.source / "necessity_install.py").write_text("# tampered public entry\n", encoding="utf-8")
        self.assertEqual(installer.check(self.home), 1)
        self.assertEqual(installer.remove(self.home), 0)

    def test_public_necessity_help_does_not_import_unrelated_placement_modules(self):
        for name in ("__init__.py", "necessity_install.py", "necessity_hook.py", "necessity_review.py", "necessity_select.py", "necessity_parse.ps1"):
            shutil.copyfile(ROOT / "necessity_review" / name, self.source / name)
        marker = "managed-entry-must-not-be-imported"
        (self.source / "managed_entry.py").write_text("raise RuntimeError(%r)\n" % marker, encoding="utf-8")
        completed = subprocess.run([sys.executable, str(self.source / "necessity_install.py"), "--help"],
                                   cwd=self.source, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage:", completed.stdout)
        self.assertNotIn(marker, completed.stderr)

    def test_corrupt_state_does_not_block_check_or_remove_and_status_record_report_errors(self):
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        state = Path(json.loads(self.settings.read_text(encoding="utf-8"))["state_dir"])
        state.mkdir()
        (state / "necessity.sqlite3").write_bytes(b"not a sqlite database")
        self.assertEqual(installer.check(self.home), 0)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(installer.main(["status", "--codex-home", str(self.home)]), 1)
            self.assertEqual(installer.main(["record", "--codex-home", str(self.home), "--candidate", "candidate-1",
                                            "--outcome", "handled", "--evidence", "real database error"]), 1)
        self.assertEqual(installer.remove(self.home), 0)

    def test_modified_hook_refuses_remove_and_preserves_scripts_and_state(self):
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        hooks_path = self.home / "hooks.json"
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
        stop = hooks["hooks"]["Stop"][-1]
        stop["hooks"].append({"type": "command", "command": "/usr/bin/other"})
        hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
        self.assertEqual(installer.check(self.home), 1)
        state = Path(json.loads(self.settings.read_text())["state_dir"])
        state.mkdir()
        marker = state / "keep"
        marker.write_text("state", encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "incomplete removal"):
            installer.remove(self.home)
        remaining = json.loads(hooks_path.read_text(encoding="utf-8"))
        self.assertIn(stop, remaining["hooks"]["Stop"])
        self.assertTrue(marker.exists())
        self.assertTrue((self.home / "necessity-review" / "necessity_hook.py").exists())
        self.assertTrue((self.home / "necessity-review" / installer.MANIFEST).exists())

    def test_manifest_cannot_name_files_outside_owned_whitelist(self):
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        manifest = self.home / "necessity-review" / installer.MANIFEST
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"]["../outside"] = "0" * 64
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "unsafe file"):
            installer.remove(self.home)

    def test_duplicate_owned_group_refuses_remove_without_mutation(self):
        installer.install(self.home, self.settings, source=self.source)
        path = self.home / "hooks.json"
        hooks = json.loads(path.read_text(encoding="utf-8"))
        hooks["hooks"]["Stop"].append(hooks["hooks"]["Stop"][-1])
        path.write_text(json.dumps(hooks), encoding="utf-8")
        before = path.read_bytes()
        with self.assertRaises(installer.InstallError):
            installer.remove(self.home)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue((self.home / "necessity-review" / "necessity_hook.py").is_file())

    def test_legacy_base_commands_remain_removable_but_do_not_pass_check(self):
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        hooks_path = self.home / "hooks.json"
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
        manifest = json.loads((self.home / "necessity-review" / installer.MANIFEST).read_text())
        for event in installer.EVENTS:
            hooks["hooks"][event][-1]["hooks"][0]["command"] = manifest["command"]
        hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
        self.assertEqual(installer.check(self.home), 1)
        with self.assertRaisesRegex(installer.InstallError, "differs"):
            installer.install(self.home, self.settings, source=self.source)
        self.assertEqual(installer.remove(self.home), 0)

    def test_remove_keeps_foreign_events_and_bound_check_rejects_base_duplicate(self):
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        hooks_path = self.home / "hooks.json"
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
        hooks["hooks"]["ForeignEvent"] = [{"hooks": [{"type": "command", "command": "/usr/bin/foreign"}]}]
        hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
        self.assertEqual(installer.remove(self.home), 0)
        remaining = json.loads(hooks_path.read_text(encoding="utf-8"))
        self.assertIn("ForeignEvent", remaining["hooks"])

        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
        manifest = json.loads((self.home / "necessity-review" / installer.MANIFEST).read_text())
        hooks["hooks"]["Stop"].append({"hooks": [installer._entry(manifest["command"], manifest["timeout"])]})
        hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
        self.assertEqual(installer.check(self.home), 1)

    def test_status_reads_bounded_diagnostics_without_candidates(self):
        settings = json.loads(self.settings.read_text(encoding="utf-8"))
        settings["max_output_bytes"] = 4096
        self.settings.write_text(json.dumps(settings), encoding="utf-8")
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        state = Path(settings["state_dir"])
        state.mkdir()
        db = sqlite3.connect(state / "necessity.sqlite3")
        try:
            db.execute("CREATE TABLE diagnostics (id TEXT PRIMARY KEY, touched REAL NOT NULL, data TEXT NOT NULL)")
            db.execute("INSERT INTO diagnostics VALUES(?,?,?)", (
                "diagnostic-1", 1.0, json.dumps({"reason_code": "invalid-input", "event": "PostToolUse",
                "tool": "Bash", "scope": "in", "input_bytes": 12, "review_limit_bytes": 20,
                "evidence_sha256": "a" * 64, "status": "unassessed", "prompt": "must not report"})))
            db.commit()
        finally:
            db.close()
        capture = io.StringIO()
        with redirect_stdout(capture):
            self.assertEqual(installer.status(self.home), 0)
        report = json.loads(capture.getvalue())
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["diagnostics"][0]["diagnostic_id"], "diagnostic-1")
        self.assertNotIn("prompt", report["diagnostics"][0]["data"])
        self.assertEqual(report["diagnostics_omitted"], 0)

    def test_status_reads_candidate_state_without_prompts_and_reports_missing_db(self):
        settings = json.loads(self.settings.read_text(encoding="utf-8"))
        settings["max_output_bytes"] = 4096
        self.settings.write_text(json.dumps(settings), encoding="utf-8")
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        capture = io.StringIO()
        with redirect_stdout(capture):
            self.assertEqual(installer.status(self.home), 0)
        self.assertEqual(json.loads(capture.getvalue())["state"], "no persisted candidate events")
        state = Path(json.loads(self.settings.read_text())["state_dir"])
        state.mkdir()
        database = state / "necessity.sqlite3"
        db = sqlite3.connect(database)
        try:
            db.execute("CREATE TABLE candidates (session TEXT, id TEXT, status TEXT, result TEXT, notified INTEGER, resolution TEXT)")
            db.execute("INSERT INTO candidates VALUES(?,?,?,?,?,?)", ("session with private prompt", "candidate-1", "reviewed", json.dumps({"reason": "bounded", "elapsed_seconds": .2, "usage": {"input": 1}}), 1, None))
            db.commit()
        finally:
            db.close()
        capture = io.StringIO()
        with redirect_stdout(capture):
            self.assertEqual(installer.main(["status", "--codex-home", str(self.home)]), 0)
        report = json.loads(capture.getvalue())
        self.assertEqual(report["candidates"][0]["candidate_id"], "candidate-1")
        self.assertEqual(report["candidates"][0]["elapsed_seconds"], .2)
        self.assertNotIn("private prompt", capture.getvalue())

    def test_record_updates_only_exact_candidate_resolution(self):
        settings = json.loads(self.settings.read_text(encoding="utf-8"))
        settings["max_output_bytes"] = 4096
        self.settings.write_text(json.dumps(settings), encoding="utf-8")
        self.assertEqual(installer.install(self.home, self.settings, source=self.source), 0)
        state = Path(settings["state_dir"])
        state.mkdir()
        database = state / "necessity.sqlite3"
        verdict = json.dumps({"action": "unassessed", "reason": "original verdict"})
        db = sqlite3.connect(database)
        try:
            db.execute("CREATE TABLE candidates (session TEXT, id TEXT, status TEXT, result TEXT, notified INTEGER, resolution TEXT, PRIMARY KEY(session,id))")
            db.execute("INSERT INTO candidates VALUES(?,?,?,?,?,?)", ("one", "candidate-1", "reviewed", verdict, 1, None))
            db.execute("INSERT INTO candidates VALUES(?,?,?,?,?,?)", ("two", "candidate-2", "reviewed", verdict, 1, None))
            db.commit()
        finally:
            db.close()
        self.assertEqual(installer.main(["record", "--codex-home", str(self.home), "--candidate", "candidate-1",
                                        "--outcome", "deferred", "--evidence", "awaiting maintainer decision"]), 0)
        db = sqlite3.connect(database)
        try:
            rows = db.execute("SELECT id,result,resolution FROM candidates ORDER BY id").fetchall()
        finally:
            db.close()
        self.assertEqual(rows[0][1], verdict)
        self.assertEqual(json.loads(rows[0][2]), {"outcome": "deferred", "evidence": "awaiting maintainer decision"})
        self.assertIsNone(rows[1][2])
        with self.assertRaisesRegex(installer.InstallError, "not found"):
            installer.record(self.home, "missing", "handled", "verified")
        with self.assertRaisesRegex(installer.InstallError, "credential"):
            installer.record(self.home, "candidate-2", "handled", "token=secret")

    def test_main_exercises_cli(self):
        old_here = installer.HERE
        installer.HERE = self.source
        try:
            self.assertEqual(installer.main(["install", "--codex-home", str(self.home), "--settings", str(self.settings)]), 0)
            self.assertEqual(installer.main(["check", "--codex-home", str(self.home)]), 0)
            self.assertEqual(installer.main(["remove", "--codex-home", str(self.home)]), 0)
        finally:
            installer.HERE = old_here


if __name__ == "__main__":
    unittest.main()
