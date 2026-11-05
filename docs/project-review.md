# Server MCP: Project Review

**Reviewed revision:** `d8340a8` (`origin/main`)
**Scope:** Static review of the source, deployment files, workflows, and docs. No server
or services were started, and no tests were run.

## Bottom line

This is a capable, unusually security-conscious homelab project. Its narrow tool surface,
shared policy/execution library, SSH host-key checking, container hardening, and candid
documentation are all strong foundations. The v0.5.0 container work is a meaningful
improvement over running the services directly on the host.

The main caveat is that the **end-to-end trust boundary is not finished or fully tested**.
The MCP containers are hardened, but the author sandbox and isolation checks remain
roadmap items, and the separate egress network does not itself restrict destinations.
Until that work lands, treat this as privileged automation for a trusted, single-user
environment—not as a complete containment boundary for hostile agent code.

## What is working well

- There is no general-purpose shell tool. Tool inputs are validated and translated into
  constrained operations; local execution uses argv rather than a shell.
- Shared execution, validation, redaction, audit, and HTTP-client code avoids duplicating
  security-sensitive behavior across the two servers.
- The container setup uses non-root processes, read-only filesystems and secret mounts,
  dropped capabilities, token-protected HTTP, and a separate writable audit mount.
- The docs do a good job stating residual risks, including model-supplied confirmation,
  shared credentials, writable workspaces, and the host-kernel boundary.
- CI builds and smoke-tests the image; release guidance recommends deploying its digest,
  and image publishing includes provenance and an SBOM.

## Highest-priority improvements

### 1. Complete and verify the trust boundary

The docs describe `mcp-egress` as providing access to target SSH and metrics endpoints,
but `deploy/quadlet/mcp-egress.network` only sets `NetworkName=mcp-egress`; it contains no
destination allowlist or other egress restriction. The author is not attached to this
network, which is useful separation, but the network does not limit where a compromised
MCP process or dependency can connect.

The modernization plan also leaves the author sandbox, workspace isolation, and end-to-end
verification incomplete (`docs/modernization-plan.md:1269-1294`). The current container
smoke test checks startup and bearer-token middleware; it does not prove that the author
cannot read MCP secrets or that the MCP cannot access the author workspace. Add explicit
egress controls and automated cross-boundary tests, and make the paired author/MCP setup
easy to deploy and verify before recommending it for untrusted agents.

**Example and implementation direction:** allow the MCP to reach only the configured SSH
target and metrics endpoints, on their configured ports; deny other destinations by
default. Enforce that with a host firewall or an egress proxy rather than relying on the
network name. Account for DNS changes and IPv6 when translating endpoint names to policy.
Extend the smoke test so an allowed endpoint is reachable, an unrelated endpoint is
blocked, and the author container cannot reach `mcp-egress` or read the mounted key/config.

### 2. Bound output while collecting it

The output cap is applied after full capture: the local executor uses
`process.communicate()` before sanitizing (`packages/server-management-lib/src/
server_management_lib/local_executor.py:95-110`), SSH collects the full result from
`connection.run()` first (`ssh_manager.py:269-286`), and HTTP clients decode JSON before
sanitizing it (`http_clients.py:202-227`). This limits what reaches the model, but not
peak memory use. A large command result or metrics response can still exhaust the MCP
process. For example, a command that emits hundreds of megabytes is fully retained by
`communicate()` even if the tool returns only the first 64 KiB.

**Implementation direction:** retain at most the configured byte budget while reading
stdout and stderr concurrently, and mark the response as truncated. For SSH, use a
streaming process/channel API with the same bound; for HTTP, enforce a response-byte limit
while consuming chunks, before JSON decoding. On reaching the cap, either safely drain
without retaining more data or cancel the operation. Keep timeouts and SQL row limits as
separate controls. Add tests for oversized stdout, stderr, SSH output, and JSON responses.

### 3. Treat redaction as best-effort—or close its known gaps

The shared redactor deliberately skips comment lines (`redaction.py:162-168`), and a test
asserts that `# token=comment` remains unchanged (`tests/test_redaction.py:136-140`).
Commented-out credentials in service files or logs can therefore be returned verbatim.
Line-oriented matching can also miss secret values represented across multiple lines.
Either mask secret-looking comments and support the relevant multiline formats, or make
the best-effort limitation unmistakable wherever these outputs are described. Do not
promise that arbitrary configuration and logs cannot disclose credentials.

For example, `# API_TOKEN=example-placeholder` is returned intact today. A YAML block such
as `api_token: |` followed by an indented value also needs format-aware handling; masking
only the key line does not mask the following value lines. A practical fix is to redact
recognized secret keys even in comments, parse supported config formats where multiline
values are possible, and conservatively handle unsupported formats. Update the existing
comment-preservation test to assert that the secret value is hidden while ordinary comments
remain readable.

### 4. Authenticate SSH host keys at bootstrap

The setup docs recommend appending `ssh-keyscan` output directly to `known_hosts`
(`docs/container.md:89`; also `docs/getting-started.md:156`). `ssh-keyscan` retrieves a
key but does not authenticate it. Explain how to compare the fingerprint against a
trusted, out-of-band source before accepting it; otherwise a first-connection
man-in-the-middle can establish the key that later connections will trust.

For example, scan to a temporary file, inspect it with `ssh-keygen -lf`, compare the
displayed fingerprint with one obtained from a trusted console or host inventory, and only
then add the verified key to `known_hosts`. Keep host-key checking enabled for subsequent
connections.

## Lower-priority improvements

- **Make installer force behavior safer.** `deploy/install.sh:44-50` applies `--force`
  to every file passed through `install_if_missing`, including configs, `known_hosts`,
  the SSH-key placeholder, and units. A force install can replace operator configuration
  with examples. Back up or preview overwritten files, or separate config replacement
  from unit refresh. For instance, refreshing units should not replace
  `~/.config/server-mcp/remote.yaml` or `~/.config/server-mcp/ssh/id_ed25519`. The script
  also suppresses `daemon-reload` errors at line 93, which can make a failed install look
  successful; report the error and stop when reload is required.
- **Improve build reproducibility.** `container/Dockerfile:12` uses the mutable
  `python:3.13-slim` tag. Use an approved multi-platform digest, for example
  `python:3.13-slim@sha256:<approved-digest>`, and update it through a reviewed dependency
  update so rebuilding the same source revision does not silently change its OS/Python base.
- **Keep app modules maintainable as the tool surface grows.** The server modules have
  grown to thousands of lines and mix tool handlers, orchestration, and output shaping.
  When adding features, extract domain handlers (for example, service lifecycle, metrics,
  and disk diagnostics) behind the existing MCP registration layer rather than moving
  policy into each handler. Gradually raise the application coverage floors (currently
  60% and 65%) to make behavior changes safer.

## Improvements since the previous review

Several issues from the earlier review are fixed in this revision and should not be
carried forward as current findings: scalar environment overrides are handled correctly;
known command families receive argument-shape validation; file reads check regular-file
type and the SSH path check canonicalizes both paths; SFTP operations have timeouts;
InfluxDB top-level limits are parsed and clamped; and state-changing tools now use
confirmation and rate limiting. Redaction has also been extended to service configuration
and host output, though the limitations above remain.

## Suggested order

1. Finish egress policy and automated author/MCP isolation verification.
2. Bound memory use during subprocess, SSH, and HTTP response collection.
3. Close the redaction gaps or clearly narrow the security claims.
4. Harden host-key bootstrap and installer overwrite behavior.
5. Improve reproducibility and split app modules as the project continues to grow.
