#!/usr/bin/env bash
#
# Verify the author/MCP isolation boundary with a real container runtime.
#
# Usage:
#   scripts/isolation-smoke.sh IMAGE
#
# This is the repeatable form of the 3.8 Phase 5 manual check. It proves:
#   - an author container on pi-control cannot reach a listener on mcp-egress;
#   - the author cannot read the MCP config, key, known_hosts or token, or a
#     container runtime socket;
#   - the MCP container cannot read an author workspace path;
#   - the audit volume is writable while the config mount and root filesystem
#     stay read-only.
#
# The checks are opt-in because they need Docker or Podman. CI can run them on
# a runner with a container engine; a rootless host can run them with Podman.
# If a boundary is removed, the corresponding probe succeeds and the script
# fails.

set -euo pipefail

image="${1:?usage: $0 IMAGE}"

engine="${CONTAINER_ENGINE:-}"
if [[ -z "$engine" ]]; then
  if command -v docker >/dev/null 2>&1; then
    engine=docker
  elif command -v podman >/dev/null 2>&1; then
    engine=podman
  else
    echo "❌ neither docker nor podman is installed" >&2
    exit 2
  fi
fi
if ! command -v "$engine" >/dev/null 2>&1; then
  echo "❌ container engine not found: $engine" >&2
  exit 2
fi

engine_opts=()
if [[ "$engine" == "podman" ]]; then
  engine_opts+=(--userns=keep-id)
fi

tmp="$(mktemp -d)"
suffix="$$"
control_net="pi-control-isolation-${suffix}"
egress_net="mcp-egress-isolation-${suffix}"
listener="mcp-listener-isolation-${suffix}"
names=("$listener")

cleanup() {
  for name in "${names[@]}"; do
    "$engine" rm -f "$name" >/dev/null 2>&1 || true
  done
  "$engine" network rm "$control_net" "$egress_net" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
  echo "❌ $*" >&2
  exit 1
}

pass() {
  echo "✅ $*"
}

"$engine" network create --internal "$control_net" >/dev/null
"$engine" network create --internal "$egress_net" >/dev/null

printf 'dummy-token\n' > "$tmp/token"
chmod 0600 "$tmp/token"
printf 'dummy-private-key\n' > "$tmp/ssh_key"
chmod 0600 "$tmp/ssh_key"
: > "$tmp/known_hosts"
chmod 0644 "$tmp/known_hosts"
mkdir -p "$tmp/audit" "$tmp/author"
chmod 0700 "$tmp/audit" "$tmp/author"
printf 'author-secret-do-not-read\n' > "$tmp/author/secret.txt"

cat > "$tmp/config.yaml" <<'YAML'
executor: ssh
ssh:
  host: "127.0.0.1"
  port: 1
  key_path: "/run/secrets/ssh_key"
  known_hosts: "/etc/server-mcp/known_hosts"
  connect_timeout: 1
security:
  services_path: "/srv"
transport:
  type: streamable-http
  host: "0.0.0.0"
  port: 8000
  path: "/mcp"
  token_file: "/run/secrets/mcp_token"
audit:
  enabled: true
  path: "/var/lib/server-mcp/audit.jsonl"
YAML

# A listener on mcp-egress is the target the author must not reach.
"$engine" run -d --name "$listener" \
  --network "$egress_net" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  "${engine_opts[@]}" \
  --entrypoint python \
  "$image" -c 'import socket, time; s = socket.socket(); s.bind(("0.0.0.0", 19000)); s.listen(); time.sleep(300)' \
  >/dev/null

listener_ip="$("$engine" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$listener")"
[[ -n "$listener_ip" ]] || fail "could not determine the mcp-egress listener address"

# 1. The author is on pi-control only and cannot reach the mcp-egress listener.
if "$engine" run --rm \
  --network "$control_net" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  "${engine_opts[@]}" \
  --entrypoint python \
  "$image" -c "import socket; socket.create_connection(('$listener_ip', 19000), 2).close()" \
  >/dev/null 2>&1; then
  fail "author on pi-control reached the mcp-egress listener"
fi
pass "author on pi-control cannot reach mcp-egress"

# 2. The author cannot read MCP secrets or a container runtime socket.
"$engine" run --rm \
  --network "$control_net" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  "${engine_opts[@]}" \
  --entrypoint python \
  "$image" -c '
import os
import sys
for path in (
    "/etc/server-mcp/config.yaml",
    "/etc/server-mcp/known_hosts",
    "/run/secrets/mcp_token",
    "/run/secrets/ssh_key",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
):
    if os.path.exists(path):
        print(f"author can see {path}", file=sys.stderr)
        sys.exit(1)
' >/dev/null || fail "author can read an MCP secret or runtime socket"
pass "author cannot read MCP secrets or a runtime socket"

# 3. The MCP container cannot read the author workspace.
"$engine" run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user "$(id -u):$(id -g)" \
  "${engine_opts[@]}" \
  --mount "type=bind,src=$tmp/config.yaml,dst=/etc/server-mcp/config.yaml,ro" \
  --mount "type=bind,src=$tmp/token,dst=/run/secrets/mcp_token,ro" \
  --mount "type=bind,src=$tmp/ssh_key,dst=/run/secrets/ssh_key,ro" \
  --mount "type=bind,src=$tmp/known_hosts,dst=/etc/server-mcp/known_hosts,ro" \
  --mount "type=bind,src=$tmp/audit,dst=/var/lib/server-mcp" \
  --entrypoint python \
  "$image" -c '
import os
import sys
if os.path.exists("/author/secret.txt"):
    print("MCP can see the author workspace", file=sys.stderr)
    sys.exit(1)
' >/dev/null || fail "MCP can read the author workspace"
pass "MCP cannot read the author workspace"

# 4. The audit volume is writable; the config mount and root stay read-only.
"$engine" run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user "$(id -u):$(id -g)" \
  "${engine_opts[@]}" \
  --mount "type=bind,src=$tmp/config.yaml,dst=/etc/server-mcp/config.yaml,ro" \
  --mount "type=bind,src=$tmp/token,dst=/run/secrets/mcp_token,ro" \
  --mount "type=bind,src=$tmp/ssh_key,dst=/run/secrets/ssh_key,ro" \
  --mount "type=bind,src=$tmp/known_hosts,dst=/etc/server-mcp/known_hosts,ro" \
  --mount "type=bind,src=$tmp/audit,dst=/var/lib/server-mcp" \
  --entrypoint python \
  "$image" -c '
import pathlib
import sys
pathlib.Path("/var/lib/server-mcp/probe").write_text("ok\n")
try:
    pathlib.Path("/etc/server-mcp/probe").write_text("bad\n")
except OSError:
    pass
else:
    print("config mount is writable", file=sys.stderr)
    sys.exit(1)
try:
    pathlib.Path("/probe").write_text("bad\n")
except OSError:
    pass
else:
    print("root filesystem is writable", file=sys.stderr)
    sys.exit(1)
' >/dev/null || fail "audit/config/root write boundary is wrong"
[[ -f "$tmp/audit/probe" ]] || fail "audit volume did not receive the probe file"
pass "audit volume is writable; config and root are read-only"

echo "All author/MCP isolation checks passed."
