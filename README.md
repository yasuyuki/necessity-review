# Necessity review

Opt-in bounded command necessity review for native Codex hooks. It never grants a tool permission or changes tool input.

```bash
python -m pip install .
necessity-review --help
```

Install it in the Python environment that will execute the hooks; keep that interpreter fixed after native trust is accepted. See [hook setup and boundaries](docs/necessity-hooks.md). Extracted from [agent-rules](https://github.com/yasuyuki/agent-rules) at `40d16b03b2fb0eeea9273f718f6a26f85202ce19` under MIT; its original history remains there.
