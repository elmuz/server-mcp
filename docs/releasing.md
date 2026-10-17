# Releasing and Migration

## Recommendation: new repository, archive the old ones

Use a new repository, `elmuz/server-mcp`, as the canonical home. It gives the monorepo a
clean name and URL, keeps the three old repositories intact as read-only archives, and avoids
force-pushing over the history of `remote-server-mcp`.

The monorepo already contains the full commit history of all three repositories, imported
with `git subtree` (merge commits per import). The old repositories do not need to be
rewritten.

### 1. Verify the monorepo

```bash
cd ~/code/server-mcp
uv sync --locked --all-packages --all-extras
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q
env -u VIRTUAL_ENV pre-commit run --all-files
```

### 2. Create and push the new repository

```bash
gh repo create elmuz/server-mcp --public --source=. --remote=origin \
  --description "Security-first MCP servers for Docker service management and disk health"
git push -u origin main
git tag -a v0.2.0 -m "v0.2.0: monorepo, MCP 2.x, security hardening, local executor"
git push origin v0.2.0
```

Then set topics and the description:

```bash
gh repo edit elmuz/server-mcp \
  --add-topic mcp \
  --add-topic model-context-protocol \
  --add-topic homelab \
  --add-topic docker \
  --add-topic smart \
  --add-topic security
```

### 3. Deprecate the old repositories

Add a short notice to the top of each old README, commit, and archive:

```markdown
> **Moved:** this project is now part of the
> [server-mcp](https://github.com/elmuz/server-mcp) monorepo.
> This repository is archived and will not receive further updates.
```

```bash
for repo in remote-server-mcp disk-health-mcp server-management-lib; do
  gh repo archive "elmuz/$repo" --yes
done
```

Archived repositories stay readable and keep their stars; the monorepo history contains
their commits.

## Alternative: reuse `remote-server-mcp`

If keeping the existing stars and URL matters more than a clean name:

1. Rename the GitHub repository to `server-mcp`.
2. Push the monorepo tree to it. The imported history already contains every commit, so a
   force push is safe for the code but replaces the refs; make a mirror first if you want
   to be cautious.
3. Archive `disk-health-mcp` and `server-management-lib` as above.

This works, but the new repository will show the imported merge commits and the old name in
some links. The new-repository path is cleaner.

## PyPI releases

Publish the library first; the apps depend on `server-management-lib>=0.2,<0.3`.

```bash
# Build all workspace packages
uv build --all-packages

# Publish in dependency order (glob the exact files so only one package is sent)
uv publish "dist/server_management_lib-0.2.0*"
uv publish "dist/remote_server_mcp-0.2.0*"
uv publish "dist/disk_health_mcp-0.2.0*"
```

`uv publish` reads credentials from `UV_PUBLISH_TOKEN` (or `~/.pypirc`). The package names
`remote-server-mcp`, `disk-health-mcp` and `server-management-lib` are the published names.

After publishing, the short install commands work:

```bash
uvx remote-server-mcp
uvx disk-health-mcp
```

Until then, use the workspace command from [harnesses.md](harnesses.md):

```bash
uv run --project /path/to/server-mcp --package remote-server-mcp remote-server-mcp
```

## Versioning

- The three packages share the suite version (`0.2.0`).
- Tag releases as `v0.2.0`, `v0.2.1`, ...
- Keep [CHANGELOG.md](../CHANGELOG.md) up to date.
- Breaking config or tool changes require a minor bump while the suite is pre-1.0.

## Checklist

- [ ] Tests and hooks pass
- [ ] `CHANGELOG.md` updated
- [ ] Version bumped in all three `pyproject.toml` files and `__version__`
- [ ] `uv lock` regenerated
- [ ] Tag created and pushed
- [ ] Library published before the apps
- [ ] Old repositories archived with a pointer to the monorepo
