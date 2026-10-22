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

The three packages are published separately but share one version. **Publish the library
first:** the apps depend on `server-management-lib>=0.4,<0.5`, so an app that is uploaded
before its library resolves to nothing and cannot be installed.

| PyPI project | Source directory |
|---|---|
| `server-management-lib` | `packages/server-management-lib` |
| `remote-server-mcp` | `apps/remote-server-mcp` |
| `disk-health-mcp` | `apps/disk-health-mcp` |

`0.2.0` is published on PyPI, so steps 1–4 are the one-off bootstrap that was used for it
and §5 is the steady state for every later release. Released versions install with `uvx`;
an unreleased commit still runs from the workspace as described in
[harnesses.md](harnesses.md):

```bash
uv run --project /path/to/server-mcp --package remote-server-mcp remote-server-mcp
```

### 1. Pre-flight

The release version did **not** change between the pre-remediation builds and the tagged
commit, so `uv build` will happily reuse a stale `dist/` and publish pre-fix wheels as
`0.2.0`. Always confirm the tree and rebuild from scratch:

```bash
git status --short                     # must print nothing
git describe --tags --exact-match      # must print v0.2.0
rm -rf dist
uv build --all-packages
uv publish --dry-run "dist/*"          # metadata check; uploads nothing
```

`--dry-run` validates every artifact against `https://upload.pypi.org/legacy/` and needs no
credentials, so it catches malformed metadata and name conflicts before the real upload.

### 2. Account prerequisites

PyPI requires 2FA on every account; token creation is blocked without it.

A **project-scoped** token can only be created once the project exists, so the first upload
of a new project needs one of two paths:

- **Account-scoped token, revoked immediately** — the shortest path, described in step 3.
  Use it when the version has to be published now.
- **A pending trusted publisher** — no token at all, described in step 5. Add it before the
  first upload if you want the very first release to go through CI.

### 3. First upload of a new project (account-scoped token)

In the PyPI web UI: *Account settings* → *API tokens* → *Add API token*, scope *Entire
account (all projects)*, named for example `server-mcp 0.2.0 bootstrap`. The token is
shown once and cannot be read again.

```bash
read -rs UV_PUBLISH_TOKEN && export UV_PUBLISH_TOKEN    # paste; keeps it out of history
uv publish "dist/server_management_lib-0.2.0*"
uv publish "dist/remote_server_mcp-0.2.0*"
uv publish "dist/disk_health_mcp-0.2.0*"
unset UV_PUBLISH_TOKEN
```

- Publish sequentially and **stop at the first failure**. A partial release is recoverable;
  a version that half-exists on PyPI and cannot be installed is not.
- If a run fails after some files were accepted, retry with
  `--check-url https://pypi.org/simple/` so already-uploaded files are skipped instead of
  rejected as duplicates.
- `--token "$UV_PUBLISH_TOKEN"` is equivalent; `uv` derives the username from the token, so
  no `~/.pypirc` is required.
- The token is a publishing credential. Never write it into the repository, a
  `pyproject.toml`, or the runtime `.env` files used by the MCP servers.
- Revoke the bootstrap token in the UI as soon as all three uploads succeed.

### 4. Verify the release

```bash
uvx remote-server-mcp --help
uvx disk-health-mcp --help
```

Both must resolve `server-management-lib` from PyPI instead of a workspace checkout. Then
re-run the live smoke checks in
[section 6.3 of the plan](modernization-plan.md#63-live-smoke-checks-read-only).

A published version cannot be replaced. If an artifact is wrong, yank the files in the PyPI
UI and ship `0.2.1`; do not delete and re-upload a version that someone may already have
installed.

### 5. Trusted publishing for later releases

`0.2.0` needed a bootstrap token because the projects did not exist yet. From now on no
token has to exist at all: PyPI trusts one specific workflow in a public repository through
OIDC, and [`.github/workflows/publish.yml`](../.github/workflows/publish.yml) implements it.
Keep the manual path only as a fallback (§6).

**Verified with `v0.2.1`** (run `39507146796`), **`v0.3.0`** (run `39852335149`) **and
`v0.4.0`** (run `39869621919`): pushing the signed tag was the only manual step, the job
passed the tag/version check, tests and all three uploads, and no `UV_PUBLISH_TOKEN` existed
on the runner or in the repository.

**Register the publisher** (once per project) in PyPI → the project → *Publishing* → *Add a
publisher*, configured as:

| Field | Value |
|---|---|
| PyPI Project Name | `server-management-lib`, `remote-server-mcp`, `disk-health-mcp` |
| Owner | `elmuz` |
| Repository name | `server-mcp` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

**Create the environment** in GitHub: *Settings* → *Environments* → *New environment* named
`pypi`. It must match the PyPI configuration and the `environment:` key in the workflow.
Adding *Required reviewers* makes every publish wait for a manual approval, which is the
cheapest guard against an accidental release tag.

**Trigger the workflow** — both paths end in the same job:

- push a release tag: `git tag -s v0.2.1 -m "v0.2.1" && git push origin v0.2.1`;
- or publish a tag that already exists: *Actions* → *Publish* → *Run workflow*, branch
  `main`, `tag` = `v0.2.0`.

The job checks out the tag, verifies that the tag equals the version in all four
`pyproject.toml` files (so a mistyped tag fails before any upload), runs the test suite,
then publishes the library and the two apps in that order with `--check-url` so a re-run
skips files that were already uploaded.

**No token is stored.** The job requests an OIDC token (`id-token: write`) and PyPI returns
an upload token scoped to that single run; `uv publish --trusted-publishing always` uses it
and attaches signed attestations automatically (`--no-attestations` opts out). Never retag a
released version: bump the version instead.

### 6. Fallback: publishing with a stored token

Use this when trusted publishing is unavailable (private repository, fork, local machine).
Now that the projects exist, mint a **project-scoped** token per package — PyPI → the
project → *Settings* → *API tokens* → *Add API token*, scope = that single project.

Store it where it cannot leak, in order of preference:

1. **GitHub environment secret** `PYPI_API_TOKEN` on the `pypi` environment, passed to the
   publish step as `--token "$UV_PUBLISH_TOKEN"` (or
   `UV_PUBLISH_TOKEN: ${{ secrets.PYPI_API_TOKEN }}`) and **without**
   `--trusted-publishing`. Environment secrets are not exposed to pull-request runs from
   forks and can require approval.
2. **A local shell only**, never a file: `read -rs UV_PUBLISH_TOKEN && export
   UV_PUBLISH_TOKEN`, as in step 3.
3. `~/.pypirc` with mode `0600`, if a tool insists. Never a repository file, a
   `pyproject.toml`, or the MCP runtime `.env` files.

Delete the account-scoped bootstrap token from step 3 once trusted publishing works: an
account-wide token can overwrite every project you own.

## Versioning

- The three packages share the suite version (`0.4.0`). The workspace root
  `pyproject.toml` carries the same version for `uv` output and should not drift.
- **`0.2.0` is the first published release.** It was never tagged when the monorepo
  consolidation landed (`50de082`, commit message `… (v0.2.0)`), so the P0/P1/P2
  remediation that followed was folded into `0.2.0` instead of bumping to `0.3.0`.
  Bumping would have implied that a `0.2.0` artifact already exists, which it does not, and
  the folding lets the defects fixed after `50de082` (fabricated disk health, missing
  container health, permissive command policy) stay out of the first PyPI upload.
- Because the fixes were folded in, the version string did **not** change with them. Clean
  `dist/` before building; a stale pre-fix wheel would otherwise be published as `0.2.0`.
- Tag releases as `v0.2.0`, `v0.2.1`, `v0.3.0`, ... The next change after this release gets
  a new version: `v0.3.1` for fixes, `v0.4.0` for features or breaking config/tool changes
  while the suite is pre-1.0.
- **The `v` belongs to the tag, not to the version.** The tag is `v0.2.1` and the packaged
  version is `0.2.1`; PEP 440 does not allow a `v` prefix in `project.version`, so `0.2.1`
  is what `pip`/`uvx` resolve and what PyPI lists. The workflow depends on both forms: the
  `on.push.tags` filter matches `v*` only, and the guard compares the tag with
  `v${version}`. A bare `0.2.1` tag would neither trigger the workflow nor pass the check.
- Keep [CHANGELOG.md](../CHANGELOG.md) up to date. Released sections (`## [0.2.0]`,
  `## [0.2.1]`) are dated with their release date and stay unchanged; new work goes under
  `## [Unreleased]`.

## Checklist

- [ ] Tests and hooks pass (`env -u VIRTUAL_ENV pre-commit run --all-files`)
- [ ] `CHANGELOG.md` updated, `[Unreleased]` emptied into a dated release section
- [ ] Version consistent in the four `pyproject.toml` files (three packages plus the
      workspace root), the three `__version__` values and the newest `CHANGELOG.md` section
- [ ] `uv lock` regenerated
- [ ] Tag created and pushed, signed and annotated (`git tag -s`)
- [ ] `git describe --tags --exact-match` on the release commit prints the tag
- [ ] `rm -rf dist && uv build --all-packages`, then `uv publish --dry-run "dist/*"`
- [ ] Library published before the apps, uploads not interleaved
- [ ] `uvx remote-server-mcp --help` and `uvx disk-health-mcp --help` resolve from PyPI
- [ ] Live smoke checks re-run with the installed packages
- [ ] Old repositories archived with a pointer to the monorepo
