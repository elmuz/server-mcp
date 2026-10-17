# Security Policy

## Supported versions

The latest release on the `main` branch receives security fixes. The project is pre-1.0, so
older minor versions may not be patched.

## Reporting a vulnerability

Please report security issues privately, not in a public issue or pull request.

- Use GitHub's private vulnerability reporting for this repository, or
- Email the maintainer listed in the repository profile.

Include:

- affected version or commit
- a description of the issue and its impact
- reproduction steps or a proof of concept
- any suggested fix or mitigation

You can expect an initial response within a few days. Please give us reasonable time to
release a fix before public disclosure.

## Scope

In scope:

- bypassing the operation catalog or input validation
- command injection or path escape in the SSH or local executor
- host key verification bypass
- reading files outside `security.services_path`
- write access through the read-only database clients
- output-limit or audit-log bypass

Out of scope:

- a compromised target host or Docker daemon
- the MCP process running with more privileges than it needs
- prompt injection in logs or files (mitigated by sanitization and limits, but unavoidable)
- vulnerabilities in Docker, smartctl, InfluxDB or Prometheus themselves

## Safe defaults

- Host key verification is enabled by default.
- Generic command execution does not exist.
- The audit log is opt-in; enable it on production hosts.
- Use read-only database tokens.
- Run the MCP as a dedicated, unprivileged user where possible.

See [docs/security-model.md](docs/security-model.md) for the full model and known
limitations.
