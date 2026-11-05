# Container Deployment

The container deployment separates the privileged MCP process from the coding-agent
sandbox. The MCP servers run as a systemd user service (Quadlet), on an internal Podman
network, with read-only configuration and credentials. The author container reaches only
the MCP endpoint over that internal network.

This is a blast-radius boundary, not a multi-tenant authorization system. It is designed
for one operator who may run a compromised model. It does not prevent a compromised model
from calling the destructive tools that the catalog exposes; see
[Residual risks](#residual-risks).

## Components

```text
~/.config/server-mcp/
├── remote.yaml                 remote-server-mcp config
├── disk.yaml                   disk-health-mcp config
├── .env                        optional metric credentials
├── known_hosts                 target SSH host keys
├── ssh/id_ed25519              target SSH private key
└── secrets/http-token          shared Streamable HTTP bearer token

~/.local/state/server-mcp/
└── audit/                      only writable mount
    ├── remote.jsonl
    └── disk.jsonl
```

Both services use the same image. The image contains the `remote-server-mcp` and
`disk-health-mcp` console scripts.

## Build the image

From the repository root:

```bash
podman build \
  -f container/Dockerfile \
  --build-arg VERSION=dev \
  --build-arg REVISION="$(git rev-parse --short HEAD)" \
  -t localhost/server-mcp:dev .
```

The build uses the locked uv workspace. It never resolves dependencies at runtime. The
runtime image is non-root, has no Docker socket and no host home. CI builds the same
Dockerfile with Docker; the image is OCI and runs under rootless Podman.

Podman builds OCI images by default, so it prints `HEALTHCHECK is not supported for OCI
image format and will be ignored`. That is expected: container health is defined by
`HealthCmd=` in the Quadlet units, not by the image. Build with
`podman build --format docker` only if you need the Dockerfile health check embedded in
the image.

Release images are published to GHCR by `.github/workflows/image.yml`, from the same tag that
publishes the PyPI packages; `.github/workflows/publish.yml` runs the same build and smoke
test before its first upload, so a broken image blocks the release. The workflow prints the
image digest. Pin that digest in the Quadlet `Image=` lines instead of using a mutable
tag:

```ini
Image=ghcr.io/elmuz/server-mcp@sha256:<digest>
```

## Install

```bash
deploy/install.sh
```

The installer:

- creates `~/.config/server-mcp` and `~/.local/state/server-mcp/audit` with private modes;
- installs the example configs, `.env`, `known_hosts` and SSH-key placeholder if missing;
- generates `secrets/http-token` if missing;
- renders `egress-policy.conf` from the installed configs when it is missing;
- installs the Quadlet units (`.container`, `.network`) under
  `~/.config/containers/systemd/` and the `server-mcp.target` user unit under
  `~/.config/systemd/user/` (Quadlet ignores plain `.target` files).

It never overwrites existing configuration, keys or tokens unless `--force` is given.

After installing:

1. Set `ssh.host` and `ssh.username` in `remote.yaml` and `disk.yaml`.
2. Replace `~/.config/server-mcp/ssh/id_ed25519` with the target key.
3. Populate `~/.config/server-mcp/known_hosts` with a verified host key. Do not
   append `ssh-keyscan` output blindly: scan to a temporary file, inspect the
   fingerprint with `ssh-keygen -lf`, and compare it with the value from the
   host console or inventory before appending.

   ```bash
   ssh-keyscan -H catafalco.example.com > /tmp/catafalco.hostkey
   ssh-keygen -lf /tmp/catafalco.hostkey
   # Compare the SHA256 fingerprint with the host console, then:
   cat /tmp/catafalco.hostkey >> ~/.config/server-mcp/known_hosts
   ```

4. Review `~/.config/server-mcp/egress-policy.conf`. It is default-deny and is
   rendered from `remote.yaml`/`disk.yaml` when first installed. Add only the
   destinations the tools need.
5. Set the image in the `.container` units, preferably by digest.
6. Start the stack:

   ```bash
   systemctl --user daemon-reload
   systemctl --user enable --now server-mcp.target
   ```

The target starts at login. To start it at boot without a login session, enable lingering:

```bash
loginctl enable-linger "$USER"
```

On a laptop, login start is the safer default: the MCP holds the target SSH key.

## Configuration

The container examples are in `deploy/examples/catafalco/`. The important differences from a
host installation are:

- `executor: ssh`; `local` is rejected inside the container;
- `key_path: /run/secrets/ssh_key`;
- `known_hosts: /etc/server-mcp/known_hosts`;
- `ssh.proxy_command` points at `server-mcp-connect`, `mcp-egress-proxy`, port `3128`,
  and the same target host/port as `ssh.host`/`ssh.port`;
- `transport.token_file: /run/secrets/mcp_token`;
- `audit.path: /var/lib/server-mcp/<service>.jsonl`.

When you change `ssh.host` or `ssh.port`, update the matching `proxy_command` arguments
and re-render the egress policy (the installer renders it only when it is missing):

```bash
uv run --frozen --no-dev --all-packages python deploy/render-egress-policy.py \
  --remote ~/.config/server-mcp/remote.yaml \
  --disk ~/.config/server-mcp/disk.yaml \
  --output ~/.config/server-mcp/egress-policy.conf
```

`SERVER_MCP_CONTAINER=1` is baked into the image. It makes startup reject
`executor: local` and require the audit directory to be mounted.

Validate a mounted configuration without starting the server:

```bash
podman run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev \
  --mount "type=bind,src=$HOME/.config/server-mcp/remote.yaml,dst=/etc/server-mcp/config.yaml,ro" \
  --mount "type=bind,src=$HOME/.config/server-mcp/secrets/http-token,dst=/run/secrets/mcp_token,ro" \
  --mount "type=bind,src=$HOME/.config/server-mcp/ssh/id_ed25519,dst=/run/secrets/ssh_key,ro" \
  --mount "type=bind,src=$HOME/.config/server-mcp/known_hosts,dst=/etc/server-mcp/known_hosts,ro" \
  --mount "type=bind,src=$HOME/.local/state/server-mcp/audit,dst=/var/lib/server-mcp,rw" \
  localhost/server-mcp:dev \
  remote-server-mcp --check-config --config /etc/server-mcp/config.yaml
```

Use `disk-health-mcp` for the disk service.

## Networks

The Quadlet units own three networks:

| Network | Purpose |
|---|---|
| `pi-control` | Internal, no gateway. Author container to MCP only. |
| `mcp-egress` | Internal, no gateway. MCP to the policy proxy only. |
| `mcp-egress-uplink` | The proxy's route to the allowed destinations. |

The MCP services listen on `0.0.0.0:8000` inside the container but publish no host port.
They are reachable by DNS name `mcp-remote` and `mcp-disk` on `pi-control`. The author
container must not join `mcp-egress`; the MCP must not join the author's egress network.

`mcp-egress` is internal and has no direct route out. The only member with an uplink is
`mcp-egress-proxy`, which applies `~/.config/server-mcp/egress-policy.conf` (default deny).
The MCP containers use the proxy for HTTP(S) and for SSH through
`ssh.proxy_command`/`server-mcp-connect`. The policy file is mounted read-only into the
proxy and is not visible to the MCP containers. The policy syntax is shared with
pi-sandbox: `default deny`, `allow <host|IP|CIDR> [port]`, `deny ...`.

The proxy resolves hostnames at request time, so DNS changes and multiple A/AAAA records
are handled by the same policy. IPv6 is subject to the same rules; there is no separate
IPv4-only path. If a destination is not explicitly allowed, the proxy returns 403 and logs
the decision.

## Token

One bearer token is shared by both MCP services. It is generated by the installer at:

```text
~/.config/server-mcp/secrets/http-token
```

The file must be mode `0600` (or `0400`). The server refuses to start with a
group/other-readable token file. The Pi sandbox reads the same file with `MCP_TOKEN_FILE`
and sends it as `Authorization: Bearer <token>`.

Rotate the token by replacing the file and restarting the target:

```bash
systemctl --user restart server-mcp.target
```

## Verification

Check the units and logs:

```bash
systemctl --user status server-mcp.target
journalctl --user -u mcp-remote -f
journalctl --user -u mcp-disk -f
```

No host port is published. Check the HTTP boundary from a temporary container attached to
`pi-control`, or run the CI smoke test locally:

```bash
scripts/container-smoke.sh localhost/server-mcp:dev
```

That script starts both console scripts with the read-only hardening, verifies that a
request without the token gets `401`, and verifies that an authenticated request is not
rejected by the middleware. It uses Docker in CI and Podman on a rootless host; set
`CONTAINER_ENGINE=docker|podman` to force one.

The boundary checks are separate because they need a real container runtime:

```bash
scripts/isolation-smoke.sh localhost/server-mcp:dev
scripts/egress-smoke.sh localhost/server-mcp:dev
```

`isolation-smoke.sh` proves the author cannot reach `mcp-egress`, read the MCP
config/key/known_hosts/token or a runtime socket, and that the MCP cannot read an author
workspace path. `egress-smoke.sh` proves an allowed target is reachable through the proxy,
an unrelated target is refused, direct routes fail, and the policy file is not visible to
the MCP container. Both fail if the corresponding boundary is removed.

## Residual risks

- **Destructive tools remain available.** `confirm=true` is a model-supplied safety
  interlock, not a human approval. A compromised model with the token can still restart or
  stop allowed services within the rate limit. The container boundary prevents host access,
  credential leakage and bypassing the catalog; it does not prevent bounded service
  disruption. If that is not acceptable, use a read-only tool profile or an approval helper
  outside both containers.
- **The author can exfiltrate its own credentials.** Provider and GitHub tokens are mounted
  into the author sandbox by design. Use disposable, narrowly scoped tokens.
- **The egress proxy is a policy boundary, not a sandbox escape.** A compromised MCP
  process can still use any destination the policy allows, and the proxy itself runs on
  the same host. Keep the policy narrow and review it when a target changes.
- **A shared writable workspace is not a trust boundary.** The sandbox mounts the project
  read-write. If the operator runs host `pi`, tests, build, deploy or git hooks in that same
  checkout later, files written by the agent execute on the host. This includes
  `.pi/mcp.json`, `.pi/extensions`, `AGENTS.md`, `.git/hooks`, build metadata and scripts;
  ignored files such as `.pi/` do not appear in `git diff`. Use a separate sandbox clone and
  approved commits until workspace isolation is implemented.
- **Docker/Podman shares the host kernel.** A runtime or kernel escape defeats the split.
  Use a VM or a separate machine for fully hostile code.
- **The transport has one shared token.** It is not a multi-user auth system and has no
  per-tool authorization.
- **`executor: local` is not supported in the container.** It would run commands inside the
  MCP container, not on the target. A future local mode would need a restricted socket
  proxy, not the raw Docker socket.
