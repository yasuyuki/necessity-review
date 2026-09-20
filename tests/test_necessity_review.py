"""Restricted reviewer process behavior, with no Codex invocation."""
import json
import os
import errno
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
from necessity_review import necessity_review as review


class NecessityReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = {"model": "fixture", "effort": "low", "deadline_seconds": 1,
                    "max_output_bytes": 4096, "max_input_bytes": 4096}
        self.request = {"candidate_id": "candidate-1"}

    def test_blocking_stdin_obeys_single_deadline(self):
        payload = "x" * (2 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "deadline"):
            review.bounded_run([sys.executable, "-c", "import time; time.sleep(10)"], payload,
                               cwd=self.root, env=os.environ.copy(), deadline=.1, limit=100)

    def test_output_budget_is_shared_between_pipes(self):
        code = "import sys; sys.stdout.write('x'*80); sys.stderr.write('y'*80)"
        with self.assertRaisesRegex(ValueError, "output limit"):
            review.bounded_run([sys.executable, "-c", code], "", cwd=self.root,
                               env=os.environ.copy(), deadline=1, limit=100)

    @unittest.skipUnless(os.name == "posix", "process groups are POSIX-specific")
    def test_descendant_holding_pipe_is_killed_within_deadline(self):
        pid_file = self.root / "descendant.pid"
        code = (
            "import pathlib, subprocess, sys; "
            "p=subprocess.Popen([sys.executable, '-c', 'import signal; signal.pause()']); "
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid))"
        )
        popen = review.subprocess.Popen

        def exited_leader(*args, **kwargs):
            process = popen(*args, **kwargs)
            self.addCleanup(review.terminate_owned, process, self.cfg["deadline_seconds"])
            # Fixture setup is not the pipe-drain deadline. Observe actual exit
            # before returning the real process/pipes, even on a cold interpreter.
            process.wait()
            self.assertEqual(process.returncode, 0)
            self.assertTrue(pid_file.exists())
            return process

        with mock.patch.object(review.subprocess, "Popen", side_effect=exited_leader), \
             self.assertRaisesRegex(ValueError, "output remained"):
            review.bounded_run([sys.executable, "-c", code, str(pid_file)], "", cwd=self.root,
                               env=os.environ.copy(), deadline=.15, limit=100)
        pid = int(pid_file.read_text())
        state = Path("/proc") / str(pid) / "stat"

        def running():
            try:
                return state.read_text().rsplit(")", 1)[1].split()[0] != "Z"
            except OSError as exc:
                # procfs can disappear on open *or read* when the child is reaped.
                if exc.errno in (errno.ENOENT, errno.ESRCH):
                    return False
                raise

        # A killed process may briefly remain as a zombie, but cannot still run.
        until = time.monotonic() + .3
        while running() and time.monotonic() < until:
            time.sleep(.01)
        self.assertFalse(running())

    def test_pipe_waits_share_deadline_and_bounded_cleanup(self):
        # Check the time budget independently of host scheduling/startup speed.
        now = [0.0]
        readers = [mock.Mock(), mock.Mock()]
        writer = mock.Mock()
        for thread in readers + [writer]:
            thread.join.side_effect = lambda timeout: now.__setitem__(0, now[0] + timeout)
        writer.is_alive.return_value = False
        process = mock.Mock()
        process.poll.return_value = 0
        with mock.patch.object(review.subprocess, "Popen", return_value=process), \
             mock.patch.object(review.threading, "Thread", side_effect=readers + [writer]), \
             mock.patch.object(review.time, "monotonic", side_effect=lambda: now[0]), \
             mock.patch.object(review, "terminate_owned", return_value=True) as terminate, \
             self.assertRaisesRegex(ValueError, "output remained"):
            review.bounded_run(["fixture"], "", cwd=self.root, env={}, deadline=.15, limit=100)
        self.assertEqual(writer.join.call_args_list[0], mock.call(timeout=.15))
        self.assertEqual(readers[0].join.call_args_list[0], mock.call(timeout=0))
        self.assertEqual(readers[1].join.call_args_list[0], mock.call(timeout=0))
        terminate.assert_called_once_with(process, timeout=.15 / 4)
        self.assertAlmostEqual(now[0], .15 + .15 / 4)

    def test_environment_has_startup_essentials_without_ambient_secret(self):
        with mock.patch.dict(os.environ, {"PATH": "/bin", "HOME": "/home/test", "CODEX_HOME": "/codex",
                                          "PRODUCT_TOKEN": "never-pass-this"}, clear=True):
            env = review._review_env()
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["CODEX_HOME"], "/codex")
        self.assertNotIn("PRODUCT_TOKEN", env)
        self.assertEqual(env["AGENT_RULES_NECESSITY_REVIEWER"], "1")

    def test_invocation_retains_hooks_and_disables_listed_mcp_only(self):
        calls = []
        verdict = {"candidate_id": "candidate-1", "action": "continue", "disposition": "normal",
                   "reason": "normal edit", "protections": "keep tests", "owner_or_entry": "",
                   "next_step": "continue"}

        def run(argv, text, **kwargs):
            calls.append((argv, text, kwargs))
            if argv[-3:] == ["mcp", "list", "--json"]:
                return json.dumps({"mcp_servers": [{"name": "node_repl"}, {"name": "safe-name"}]}), ""
            return json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(verdict)}}) + "\n", ""

        with mock.patch.object(review.shutil, "which", return_value="codex.exe"), \
             mock.patch.object(review, "bounded_run", side_effect=run):
            result = review.review(self.request, self.cfg)
        self.assertEqual(result["candidate_id"], "candidate-1")
        argv = calls[1][0]
        self.assertNotIn("--ignore-user-config", argv)
        self.assertIn("--sandbox", argv)
        configs = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "-c"]
        self.assertIn('mcp_servers.node_repl.enabled=false', configs)
        self.assertIn('mcp_servers.safe-name.enabled=false', configs)
        self.assertIn("features.plugins=false", configs)
        self.assertIn("features.multi_agent=false", configs)
        self.assertIn("web_search=\"disabled\"", configs)
        self.assertEqual(calls[0][0][-3:], ["mcp", "list", "--json"])
        self.assertEqual(calls[0][0][1], "-c")
        self.assertNotIn("--strict-config", calls[0][0])
        self.assertNotIn("-C", calls[0][0])

    def test_unsupported_mcp_name_does_not_launch_reviewer(self):
        for name in ('x.y', 'quoted"name', 'x&echo injected'):
            with self.subTest(name=name), \
                 mock.patch.object(review.shutil, "which", return_value="codex.exe"), \
                 mock.patch.object(review, "mcp_names", return_value=(name,)), \
                 mock.patch.object(review, "bounded_run") as run:
                with self.assertRaisesRegex(ValueError, "cannot be safely disabled"):
                    review.review(self.request, self.cfg)
                run.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows batch launch boundary")
    def test_windows_batch_rejected_before_any_child_launch(self):
        for suffix in (".cmd", ".BAT"):
            shim = self.root / ("codex" + suffix)
            shim.write_text("@echo should-not-run\n")
            for configured in (False, True):
                cfg = dict(self.cfg, codex_executable=str(shim)) if configured else self.cfg
                with self.subTest(suffix=suffix, configured=configured), \
                     mock.patch.object(review.shutil, "which", return_value=str(shim)), \
                     mock.patch.object(review, "mcp_names", return_value=("x&echo injected",)), \
                     mock.patch.object(review, "bounded_run") as run:
                    with self.assertRaisesRegex(ValueError, "native Codex .exe"):
                        review.review(self.request, cfg)
                    run.assert_not_called()

    def test_schema_invalid_or_invalid_mcp_json_withholds_verdict(self):
        bad = {"candidate_id": "candidate-1", "action": "continue", "disposition": "normal"}
        with self.assertRaises(ValueError):
            review.validate(bad, "candidate-1")
        with mock.patch.object(review, "bounded_run", return_value=("not-json", "")):
            with self.assertRaisesRegex(ValueError, "MCP list emitted invalid JSON"):
                review.mcp_names("codex", self.cfg, self.root, {})


if __name__ == "__main__":
    unittest.main()
