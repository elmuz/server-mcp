#!/usr/bin/env bash
#
# Smoke-test a built Server MCP image with plain Docker.
#
# Usage:
#   scripts/container-smoke.sh localhost/server-mcp:ci
#
# The script verifies both console scripts, the token file, the read-only
# container hardening and the Streamable HTTP bearer-token middleware.

set -euo pipefail

image="${1:?usage: $0 IMAGE}"
tmp="$(mktemp -d)"
token="$(head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1)"
names=()

cleanup() {
  for name in "${names[@]}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  rm -rf "$tmp"
}
trap cleanup EXIT

printf '%s\n' "$token" > "$tmp/token"
chmod 0600 "$tmp/token"
printf 'dummy-private-key\n' > "$tmp/ssh_key"
chmod 0600 "$tmp/ssh_key"
: > "$tmp/known_hosts"
chmod 0644 "$tmp/known_hosts"
mkdir -p "$tmp/audit"
chmod 0700 "$tmp/audit"

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

# ShellCheck sees commas inside --tmpfs/--mount values as array separators.
# shellcheck disable=SC2054
common=(
  --rm
  --read-only
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --tmpfs /tmp:rw,nosuid,nodev
  --user "$(id -u):$(id -g)"
  --mount "type=bind,src=$tmp/config.yaml,dst=/etc/server-mcp/config.yaml,ro"
  --mount "type=bind,src=$tmp/token,dst=/run/secrets/mcp_token,ro"
  --mount "type=bind,src=$tmp/ssh_key,dst=/run/secrets/ssh_key,ro"
  --mount "type=bind,src=$tmp/known_hosts,dst=/etc/server-mcp/known_hosts,ro"
  --mount "type=bind,src=$tmp/audit,dst=/var/lib/server-mcp,rw"
)

docker run "${common[@]}" "$image" \
  remote-server-mcp --check-config --config /etc/server-mcp/config.yaml
docker run "${common[@]}" "$image" \
  disk-health-mcp --check-config --config /etc/server-mcp/config.yaml

start_and_check() {
  local name="$1"
  local port="$2"
  local command="$3"
  local container_name="server-mcp-smoke-${name}-$$"

  names+=("$container_name")
  docker run -d --name "$container_name" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --pids-limit=256 \
    --memory=512m \
    --tmpfs /tmp:rw,nosuid,nodev \
    --user "$(id -u):$(id -g)" \
    --publish "127.0.0.1:${port}:8000" \
    --mount "type=bind,src=$tmp/config.yaml,dst=/etc/server-mcp/config.yaml,ro" \
    --mount "type=bind,src=$tmp/token,dst=/run/secrets/mcp_token,ro" \
    --mount "type=bind,src=$tmp/ssh_key,dst=/run/secrets/ssh_key,ro" \
    --mount "type=bind,src=$tmp/known_hosts,dst=/etc/server-mcp/known_hosts,ro" \
    --mount "type=bind,src=$tmp/audit,dst=/var/lib/server-mcp,rw" \
    "$image" "$command" \
      --config /etc/server-mcp/config.yaml \
      --transport streamable-http \
      --http-host 0.0.0.0 \
      --http-port 8000 \
    >/dev/null

  local code="000"
  for _ in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:${port}/mcp" || true)"
    if [[ "$code" != "000" ]]; then
      break
    fi
    sleep 1
  done

  if [[ "$code" == "000" ]]; then
    docker logs "$container_name" >&2 || true
    echo "❌ ${command} did not start listening" >&2
    return 1
  fi
  if [[ "$code" != "401" ]]; then
    docker logs "$container_name" >&2 || true
    echo "❌ ${command}: expected 401 without a token, got ${code}" >&2
    return 1
  fi

  local auth_code
  auth_code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    "http://127.0.0.1:${port}/mcp")"

  if [[ "$auth_code" == "401" ]]; then
    docker logs "$container_name" >&2 || true
    echo "❌ ${command}: authenticated request was rejected" >&2
    return 1
  fi

  echo "✅ ${command}: unauthenticated=401 authenticated=${auth_code}"
}

start_and_check remote 18000 remote-server-mcp
start_and_check disk 18001 disk-health-mcp
