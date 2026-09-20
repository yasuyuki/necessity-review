"""Focused regression tests for bounded command selection facts."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("necessity_select", ROOT / "necessity_review" / "necessity_select.py")
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)


class NecessitySelectTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("pwsh"), "requires native PowerShell parser")
    def test_saved_orientation_grouping_remains_semantic_review_not_exemption(self):
        fixture = json.loads((ROOT / "tests/fixtures/necessity-orientation.json").read_text())
        for case in fixture["cases"]:
            with self.subTest(candidate=case["original_candidate_id"]):
                facts = selector.analyze(case["operation"], shell="pwsh", parser_timeout=10)
                self.assertEqual([], facts["coverage"])
                self.assertEqual([], facts["writes"])
                self.assertEqual(["multiple-responsibilities"], facts["features"])
                self.assertTrue({"state", "process"}.issubset(facts["responsibilities"]))

    @unittest.skipUnless(shutil.which("pwsh"), "requires native PowerShell parser")
    def test_orientation_does_not_hide_other_candidate_or_coverage_grounds(self):
        orientation = "git status --short; Get-Content AGENTS.md; Get-Content README.md; "
        cases = [
            ("Set-Content result.txt 'data'", "writes", "result.txt"),
            ("Set-Content run.py 'print(1)'; python run.py", "features", "generated-file-execution"),
            ("Remove-Item result.txt", "responsibilities", "cleanup"),
            ("Start-Sleep 1", "responsibilities", "wait"),
            ("Invoke-Expression $code", "coverage", "powershell:unassessed (dynamic invoke-expression)"),
            ("& $command", "coverage", "powershell:unassessed (dynamic command)"),
            ("[IO.File]::ReadAllText('unknown.txt')", "coverage", "powershell:unassessed (method invocation)"),
        ]
        for suffix, field, expected in cases:
            with self.subTest(suffix=suffix):
                facts = selector.analyze(orientation + suffix, shell="pwsh", parser_timeout=10)
                self.assertIn(expected, facts[field])
                self.assertIn("multiple-responsibilities", facts["features"])

    def test_ordinary_process_and_completion_message_is_negative(self):
        self.assertEqual(selector.analyze("pytest -q; echo done")["features"], [])
        self.assertEqual(selector.analyze("import subprocess; subprocess.run(['pytest']); print('done')", shell="python")["features"], [])
    def test_funkot_shape_tracks_state_process_and_report(self):
        command = '''
from pathlib import Path
import json, subprocess
state = json.loads(Path("state.json").read_text())
Path("state.json").write_text(json.dumps(state))
subprocess.run(["funkot", "reconstruct", "state.json"], check=True)
print("reported")
'''
        facts = selector.analyze(command, shell="python")
        self.assertEqual([], facts["coverage"])
        self.assertIn("state.json", facts["writes"])
        self.assertIn("funkot", facts["executes"])
        self.assertTrue({"state", "process", "report"}.issubset(facts["responsibilities"]))
        self.assertIn("multiple-responsibilities", facts["features"])

    def test_scheduler_shape_tracks_setup_wait_process_result_and_cleanup(self):
        command = '''
from pathlib import Path
import subprocess, time
Path("run.py").write_text("print('job')")
job = subprocess.Popen(["python", "run.py"])
time.sleep(1)
job.wait()
Path("result.json").write_text("{}")
Path("run.py").unlink()
print("result")
'''
        facts = selector.analyze(command, shell="python")
        self.assertTrue({"state", "wait", "process", "cleanup", "report"}.issubset(facts["responsibilities"]))
        self.assertIn("run.py", facts["writes"])
        self.assertIn("run.py", facts["executes"])
        self.assertIn("generated-file-execution", facts["features"])

    def test_legitimate_single_operation_and_long_literal_are_not_candidates(self):
        literal = "x" * 10000
        facts = selector.analyze(
            f"from pathlib import Path\nPath('guide.md').write_text({literal!r})",
            shell="python",
        )
        self.assertEqual(["state"], facts["responsibilities"])
        self.assertEqual([], facts["features"])

    def test_bash_literal_commit_is_not_a_candidate(self):
        facts = selector.analyze('git commit -m "' + "long literal " * 1000 + '"')
        self.assertTrue(
            facts["coverage"] == []
            or facts["coverage"] == ["bash:unassessed (bashlex unavailable)"],
            facts,
        )
        self.assertEqual([], facts["features"])

    def test_unknown_python_syntax_is_not_certified(self):
        facts = selector.analyze("if:", shell="python")
        self.assertEqual(["python:unassessed (syntax error)"], facts["coverage"])

    def test_bash_tracks_generated_script_nested_commands_and_cleanup(self):
        command = "printf 'x' > run; python run; bash -c 'sleep 1; rm run; echo done'"
        facts = selector.analyze(command)
        if facts["coverage"]:
            self.assertIn("bashlex unavailable", facts["coverage"][0])
            return
        self.assertIn("run", facts["writes"])
        self.assertIn("run", facts["executes"])
        self.assertIn("generated-file-execution", facts["features"])
        self.assertTrue({"state", "process", "wait", "cleanup", "report"}.issubset(facts["responsibilities"]))

    def test_bash_heredoc_and_substitution_are_observed(self):
        command = "python <<EOF\nimport subprocess\nsubprocess.run(['echo', 'ok'])\nEOF\necho $(date)"
        facts = selector.analyze(command)
        if facts["coverage"]:
            self.assertIn("bash", facts["coverage"][0])
            return
        self.assertIn("echo", facts["executes"])
        self.assertIn("command-substitution", facts["features"])

    def test_quoted_heredoc_document_write_stays_single_responsibility(self):
        facts = selector.analyze("cat <<'DOC' > guide.md\nlong literal $(not run)\nDOC\n")
        if facts["coverage"]:
            self.assertIn("bash", facts["coverage"][0])
            return
        self.assertEqual(["state"], facts["responsibilities"])
        self.assertEqual([], facts["features"])

    def test_shell_path_and_python_module_flag_do_not_claim_file_execution(self):
        self.assertEqual([], selector.analyze("echo ok", shell="/bin/bash")["coverage"])
        facts = selector.analyze("python -m compileall", shell="/bin/bash")
        self.assertIn("python:unassessed (module execution)", facts["coverage"])
        self.assertNotIn("-m", facts["executes"])

    def test_powershell_parser_receives_source_on_stdin(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout='{"errors": 0, "writes": [], "executes": [], "responsibilities": []}'))
        with mock.patch.object(selector.shutil, "which", return_value="pwsh"), mock.patch.object(selector.subprocess, "run", runner):
            facts = selector.analyze("Write-Output '$not executed'", shell="pwsh", parser_timeout=7)
        self.assertEqual([], facts["coverage"])
        args, kwargs = runner.call_args
        self.assertIn("-File", args[0])
        self.assertNotIn("-Command", args[0])
        self.assertEqual("Write-Output '$not executed'", kwargs["input"])
        self.assertEqual(7, kwargs["timeout"])

    def test_powershell_parser_child_opts_out_without_changing_parent_or_deadline(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout='{"errors": 0, "static_argv": ["git", "status"]}'))
        with mock.patch.dict(os.environ, {"POWERSHELL_TELEMETRY_OPTOUT": "0"}), mock.patch.object(selector.shutil, "which", return_value="pwsh"), mock.patch.object(selector.subprocess, "run", runner):
            self.assertEqual([], selector.analyze("git status", shell="pwsh", parser_timeout=7)["coverage"])
            self.assertEqual(["git", "status"], selector.static_argv("git status", shell="pwsh", parser_timeout=7))
            self.assertEqual("0", os.environ["POWERSHELL_TELEMETRY_OPTOUT"])
            for call in runner.call_args_list:
                self.assertEqual(dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT="1"), call.kwargs["env"])
                self.assertEqual(7, call.kwargs["timeout"])
            runner.side_effect = subprocess.TimeoutExpired("pwsh", 7)
            self.assertIn("powershell:unassessed (parser timeout)", selector.analyze("git status", shell="pwsh", parser_timeout=7)["coverage"])
            self.assertIsNone(selector.static_argv("git status", shell="pwsh", parser_timeout=7))

    @unittest.skipUnless(os.name == "posix" and shutil.which("pwsh"), "requires pwsh and an isolated POSIX mutex session")
    def test_native_powershell_cold_parser_does_not_wait_for_telemetry_mutex(self):
        # .NET's unqualified named mutexes are POSIX-session scoped. Both the
        # holder and parser run in this new session, never a user's live session.
        probe = textwrap.dedent('''
            import os, subprocess, sys
            sys.path.insert(0, sys.argv[1])
            import necessity_select as selector
            code = "$m=[Threading.Mutex]::new($false,'CreateUniqueUserId'); $null=$m.WaitOne(); [Console]::Out.WriteLine('ready'); $null=[Console]::In.ReadLine(); $m.ReleaseMutex(); $m.Dispose()"
            holder = subprocess.Popen([sys.argv[2], '-NoProfile', '-NonInteractive', '-Command', code],
                env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1'),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert holder.stdout.readline().strip() == 'ready'
                facts = selector.analyze("python 'generated.py'", shell='pwsh', parser_timeout=10)
                assert facts['coverage'] == [], facts
                assert facts['executes'] == ['python', 'generated.py'], facts
                assert selector.static_argv("python 'generated.py'", shell='pwsh', parser_timeout=10) == ['python', 'generated.py']
            finally:
                holder.communicate('\\n', timeout=10)
        ''')
        with tempfile.TemporaryDirectory() as temp:
            completed = subprocess.run([sys.executable, "-c", probe, str(ROOT / "necessity_review"), shutil.which("pwsh")],
                env=dict(os.environ, XDG_CACHE_HOME=temp, POWERSHELL_TELEMETRY_OPTOUT="0"),
                start_new_session=True, capture_output=True, text=True, timeout=24)
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_static_python_version_only_is_negative(self):
        for command in ("python --version", "python3 -V", "py --version"):
            with self.subTest(command=command):
                facts = selector.analyze(command)
                self.assertEqual([], facts["coverage"], facts)
                self.assertEqual([], facts["features"], facts)
        for command in ("python -v", "python --version extra", "python -m unittest", "python --version > result.txt"):
            with self.subTest(command=command):
                self.assertTrue(selector.analyze(command)["coverage"])
        facts = selector.analyze("python --version $(touch unexpected)")
        self.assertIn("command-substitution", facts["features"])
        self.assertTrue(facts["coverage"])

    @unittest.skipUnless(importlib.util.find_spec("bashlex"), "bashlex is unavailable")
    def test_static_argv_accepts_literal_bash_words_and_rejects_expansion(self):
        command = "git commit -m 'long evidence: bash -c example; $not_expanded is data'"
        self.assertEqual(["git", "commit", "-m", "long evidence: bash -c example; $not_expanded is data"], selector.static_argv(command))
        for command in ("git status; echo done", "git status | cat", "git status > status.txt", "git $branch", "git *", "git ~", "eval 'git status'", ". ./command"):
            with self.subTest(command=command):
                self.assertIsNone(selector.static_argv(command))

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is unavailable")
    def test_native_powershell_static_python_version_and_counterexamples(self):
        for command in ("python --version", "python -V", "py --version", "python.exe '--version'"):
            with self.subTest(command=command):
                facts = selector.analyze(command, shell="pwsh", parser_timeout=24)
                self.assertEqual([], facts["coverage"], facts)
                self.assertEqual([], facts["features"], facts)
        for command in ("python -v", "python --version extra", "python -c 'print(1)'",
                        "python -m unittest", "python $version", "python --version $(Get-Date)", "python --version > result.txt",
                        "python -"):
            with self.subTest(command=command):
                facts = selector.analyze(command, shell="pwsh", parser_timeout=24)
                self.assertIn("powershell:unassessed (nested interpreter or evaluation alias)", facts["coverage"], facts)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is unavailable")
    def test_native_powershell_static_python_script_tracks_executable_script_and_generated_file(self):
        executable = r"C:\Program Files\Python\python.exe"
        script = r"C:\証拠 フォルダー\collect.py"
        command = f"& '{executable}' '{script}' --evidence 'bash -c example; $not_expanded is evidence data'"
        facts = selector.analyze(command, shell="pwsh", parser_timeout=24)
        self.assertEqual([], facts["coverage"], facts)
        self.assertEqual([executable, script], facts["executes"], facts)
        self.assertEqual([executable, script, "--evidence", "bash -c example; $not_expanded is evidence data"], selector.static_argv(command, shell="pwsh", parser_timeout=24))

        generated = selector.analyze("Set-Content -Path run.py -Value 'print(1)'; python run.py --evidence 'long literal'", shell="pwsh", parser_timeout=24)
        self.assertIn("run.py", generated["writes"], generated)
        self.assertIn("python", generated["executes"], generated)
        self.assertIn("run.py", generated["executes"], generated)
        self.assertIn("generated-file-execution", generated["features"], generated)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is unavailable")
    def test_static_argv_rejects_powershell_non_simple_or_dynamic_input(self):
        for command in (
            "git status; Write-Output done", "git status | Out-Host", "git status > status.txt",
            "$name = 'status'; git $name", "& { git status }", "Invoke-Expression 'git status'",
            ". ./command.ps1", "python -c 'print(1)'", "python -",
            "using module ./untrusted.psm1\ngit status", "#requires -Modules ./untrusted.psm1\ngit status",
        ):
            with self.subTest(command=command):
                self.assertIsNone(selector.static_argv(command, shell="pwsh", parser_timeout=24))

    def test_powershell_requires_deadline(self):
        with mock.patch.object(selector.shutil, "which", return_value="pwsh"):
            facts = selector.analyze("Write-Output ok", shell="powershell.exe")
        self.assertIn("powershell:unassessed (missing parser timeout)", facts["coverage"])

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is unavailable")
    def test_native_powershell_ast_does_not_execute_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "must-not-exist-from-parser"
            facts = selector.analyze(
                f"Set-Content -Path 'guide.md' -Value 'long literal'; Invoke-Expression \"Set-Content -Path '{marker}' -Value x\"",
                shell="pwsh", parser_timeout=24,
            )
            self.assertFalse(marker.exists())
            self.assertIn("guide.md", facts["writes"], facts)
            self.assertIn(str(marker), facts["writes"])
        ordinary = selector.analyze("git status --short; Write-Output 'done'", shell="pwsh", parser_timeout=24)
        self.assertEqual(ordinary["features"], [])
        self.assertEqual(ordinary["coverage"], [])


if __name__ == "__main__":
    unittest.main()
