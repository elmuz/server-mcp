# Pull request

## Summary

Describe the change in a few sentences.

## Scope

- [ ] `server-management-lib`
- [ ] `remote-server-mcp`
- [ ] `disk-health-mcp`
- [ ] documentation
- [ ] packaging / CI

## Safety review

- [ ] New commands are operations in `operations.py` (no shell strings, no `shell=True`).
- [ ] Inputs are validated with `SecurityValidator`.
- [ ] File access stays below `services_path` and respects the sensitive-file policy.
- [ ] State-changing tools keep `ToolAnnotations` and require `confirm=true` where destructive.
- [ ] Output remains bounded and sanitized.
- [ ] Credentials, tokens and secrets are not logged, returned or committed.

## Tests

- [ ] New behavior has unit tests.
- [ ] Security-relevant behavior has a `test_security*.py` case.
- [ ] Coverage gates still pass.

```text
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q
```

## Documentation

- [ ] README and/or `docs/` updated for user-facing changes.
- [ ] `CHANGELOG.md` updated.
- [ ] `docs/modernization-plan.md` updated when a tracked item is completed.
