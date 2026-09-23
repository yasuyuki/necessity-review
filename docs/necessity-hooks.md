# Necessity review hooks

`necessity-review` optionally selects commands for a restricted Codex review through native hooks. It does not grant permissions or change tool input.

Install the package in the Python environment that executes hooks, and keep that interpreter fixed. Prepare a private JSON settings file; `necessity_review.necessity_install._settings` is the exact schema authority. It requires absolute scopes, excludes, and state directory; explicit reviewer model and effort; and positive limits. The optional absolute `codex_executable` is needed when the normal runtime wrapper cannot provide the restricted reviewer invocation. Windows production requires `"shell": "pwsh"` and PowerShell 7 or newer; install and check verify the executable and major version. Bash parsing uses the declared `bashlex` dependency, Python uses the standard-library AST, and PowerShell parsing uses `pwsh -NoProfile -NonInteractive -File necessity_parse.ps1`. Native hook and status JSON output uses ASCII escapes so Unicode values survive CP932 stdout and are restored by JSON parsing.

Use the single console entry:

- `necessity-review install --codex-home PATH --settings FILE`
- `necessity-review check|status|remove --codex-home PATH`
- `necessity-review record --codex-home PATH --candidate ID --outcome handled|deferred|unassessed --evidence TEXT`

The installer preserves unrelated hooks and records its source and launcher identity. To change a package, remove the intact owned installation, update the package, then install and check it. Use Codex's official hook UI to inspect and trust definitions; install, trust, loading, and delivery are separate and no step approves trust automatically.

A static exact management command can reach status, record, check, or removal when state is broken. It must use the pinned launcher and package identity; dynamic commands, unknown flags, altered sources, or another launcher are reviewed normally. Installation is never exempt.

The reviewer receives supplied evidence in a neutral temporary cwd, a read-only sandbox, and no-approval mode, with project instructions, tools, plugins, collaboration, Web search, and configured MCP disabled. This is a workflow review, not a same-user security boundary. Missing request context, malformed evidence, unavailable parsers, or credential-like input are unassessed. Keep private state outside Git.
