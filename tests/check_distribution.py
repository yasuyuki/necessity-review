"""Exercise an installed wheel from a neutral cwd; never load checkout modules."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    args = parser.parse_args()
    python = Path(args.python).absolute()
    launcher = python.parent / ("necessity-review.exe" if os.name == "nt" else "necessity-review")
    assert launcher.is_file(), launcher
    with tempfile.TemporaryDirectory(prefix="necessity-distribution-", dir=python.parent.parent) as temporary:
        root = Path(temporary).resolve()
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env["PATH"] = str(launcher.parent) + os.pathsep + env.get("PATH", "")

        def run(argv, *, data=None, expected=0, environment=None):
            result = subprocess.run([str(x) for x in argv], cwd=root,
                                    env=environment or env, input=data, text=True,
                                    encoding="utf-8", capture_output=True)
            assert result.returncode == expected, (argv, result.returncode, result.stdout, result.stderr)
            return result.stdout

        source = Path(run([python, "-B", "-c",
                           "import pathlib, necessity_review.necessity_hook as h; "
                           "from necessity_review import necessity_install as i; "
                           "assert callable(h.handle); "
                           "assert (i.HERE/'necessity_parse.ps1').is_file(); "
                           "print(i.HERE)"]).strip())
        assert source != Path(__file__).resolve().parents[1] / "necessity_review"
        run([launcher, "--help"])
        home, state = root / "codex", root / "state"
        home.mkdir()
        state.mkdir()
        unrelated = {"SessionStart": [{"hooks": [{"type": "command", "command": "unrelated-hook", "timeout": 5}]}]}
        (home / "hooks.json").write_text(json.dumps({"hooks": unrelated}), encoding="utf-8")
        (home / "config.toml").write_text("# untouched native settings\n", encoding="utf-8")
        settings = root / "settings.json"
        settings.write_text(json.dumps({
            "version": 1, "scopes": [str(root)], "excludes": [],
            "state_dir": str(state), "model": "fixture-no-model", "effort": "low",
            "deadline_seconds": 4, "max_input_bytes": 65536, "max_output_bytes": 65536,
            "reviews_per_session": 2, "retention_seconds": 60, "max_sessions": 2,
            "shell": "bash",
        }), encoding="utf-8")
        other_bin = root / "other-bin"
        other_bin.mkdir()
        other_launcher = other_bin / launcher.name
        other_launcher.write_text("not the executing console", encoding="utf-8")
        other_launcher.chmod(0o755)
        other_env = dict(env, PATH=str(other_bin) + os.pathsep + env["PATH"])
        run([launcher, "install", "--codex-home", home, "--settings", settings], environment=other_env)
        ownership = json.loads((home / "necessity-review/.necessity-install.json").read_text())
        assert Path(ownership["management"]["launcher"]) == launcher
        run([launcher, "check", "--codex-home", home, "--settings", settings])
        assert json.loads(run([launcher, "status", "--codex-home", home]))["candidates"] == []
        database = state / "necessity.sqlite3"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE candidates (session TEXT,id TEXT,status TEXT,result TEXT,resolution TEXT)")
            db.execute("INSERT INTO candidates VALUES (?,?,?,?,?)",
                       ("fixture", "candidate", "reviewed", '{"action":"unassessed"}', None))
        db.close()
        run([launcher, "record", "--codex-home", home, "--candidate", "candidate",
             "--outcome", "deferred", "--evidence", "Artifact fixture remains unassessed."])
        candidate = json.loads(run([launcher, "status", "--codex-home", home]))["candidates"][0]
        assert candidate["result"]["action"] == "unassessed"
        assert candidate["resolution"]["outcome"] == "deferred"
        database.write_bytes(b"broken state for management recovery fixture")
        installed = home / "necessity-review"

        def hook(command, event="PreToolUse", environment=None, cwd=None):
            payload = {"hook_event_name": event, "cwd": str(cwd or root),
                       "session_id": "fixture", "tool_name": "exec_command",
                       "tool_input": {"cmd": command, "workdir": str(root), "shell": "bash"}}
            output = run([python, "-B", installed / "necessity_hook.py", "--config",
                          installed / "config.json", "--event", event],
                         data=json.dumps(payload), environment=environment)
            return json.loads(output) if output.strip() else {}

        for entry in (str(launcher), "necessity-review"):
            for operation in ("--help", "check", "status", "record", "remove"):
                command = shlex.quote(entry) + " " + operation
                if operation != "--help":
                    command += " --codex-home " + shlex.quote(str(home))
                if operation == "check":
                    command += " --settings " + shlex.quote(str(settings))
                if operation == "record":
                    command += " --candidate candidate --outcome deferred --evidence 'fixture only'"
                for event in ("PreToolUse", "PostToolUse"):
                    assert hook(command, event) == {}, (command, event)
        command = shlex.quote(str(launcher)) + " status --codex-home " + shlex.quote(str(home))
        relative_entry = os.path.relpath(launcher.parent, root)
        ordered_path = str(other_bin) + os.pathsep + relative_entry + os.pathsep + env["PATH"]
        bare_command = "necessity-review status --codex-home " + shlex.quote(str(home))
        decision = hook(bare_command, environment=dict(env, PATH=ordered_path)).get("hookSpecificOutput", {}).get("permissionDecision")
        assert decision == "deny", "a later relative PATH owner must not outrank an earlier executable"
        for bad in (command + " --unknown --help", command + " ; echo not-management"):
            decision = hook(bad).get("hookSpecificOutput", {}).get("permissionDecision")
            assert decision == "deny", (bad, decision)
        shadow = root / "shadow"
        fake = shadow / "necessity_review"
        fake.mkdir(parents=True)
        marker = root / "untrusted-import-executed"
        (fake / "__init__.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n", encoding="utf-8")
        (fake / "necessity_install.py").write_text("def main(): pass\n", encoding="utf-8")
        for operation in ("--help", "status", "remove"):
            shadow_command = shlex.quote(str(launcher)) + " " + operation
            if operation != "--help":
                shadow_command += " --codex-home " + shlex.quote(str(home))
            decision = hook(shadow_command, environment=dict(env, PYTHONPATH=str(shadow))).get("hookSpecificOutput", {}).get("permissionDecision")
            assert decision == "deny", (operation, decision)
        assert not marker.exists(), "inspection imported the shadow package"
        assert hook("x" * 200000, "PostToolUse", cwd=root.parent) == {}
        run([launcher, "remove", "--codex-home", home])
        assert json.loads((home / "hooks.json").read_text())["hooks"] == unrelated
        assert database.read_bytes() == b"broken state for management recovery fixture"
        assert (home / "config.toml").read_text() == "# untouched native settings\n"
        assert not (installed / ".necessity-install.json").exists()
    print("installed wheel: import, install/check/status/record/remove, recovery, shadow refusal and scope transparency passed")


if __name__ == "__main__":
    main()
