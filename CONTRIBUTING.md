# Contributing

Thanks for taking the time to improve Server MCP.

## Before you start

- For security issues, do **not** open a public issue. See [SECURITY.md](SECURITY.md).
- For larger changes, open an issue first so the design can be discussed.
- By contributing you agree that your work is licensed under the MIT license.

## Setup

```bash
uv sync --all-packages --all-extras
pre-commit install
```

## Checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q
env -u VIRTUAL_ENV pre-commit run --all-files
```

All of these must pass. Coverage gates are enforced by pytest; do not lower them.

## Guidelines

- Keep the tool catalog small and explicit. No generic command execution.
- Build commands as argv vectors; never concatenate shell strings.
- Validate every input before use and return actionable errors.
- Add tests for command construction, validation and failure paths.
- Update the docs when a tool, config key or behavior changes.
- Keep docs client-agnostic; client-specific instructions belong in
  [docs/harnesses.md](docs/harnesses.md).
- Do not commit `config.yaml`, `.env`, keys, tokens or captured credentials.

## Commits

Conventional commits are appreciated:

```text
feat: add compose status operation
fix: validate device before database lookup
docs: document the local executor
test: cover SFTP symlink escape
```

Keep commits focused. The repository uses signed commits; configure `commit.gpgsign` if you
contribute regularly.

## Pull requests

- Describe the problem and the chosen approach.
- Mention user-visible behavior changes and security implications.
- Link related issues.
- Confirm the full check suite passes.

## Documentation

Markdown is linted and relative links are checked. If you move a file, update links in the
README, `AGENTS.md`, `docs/` and package READMEs.
