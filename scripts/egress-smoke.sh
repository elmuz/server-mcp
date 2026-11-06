#!/usr/bin/env bash
#
# Verify the mcp-egress default-deny policy with a real container runtime.
#
# Usage:
#   scripts/egress-smoke.sh IMAGE
#
# The test creates an internal egress network and a separate uplink network.
# Two HTTP targets listen on the uplink. The policy proxy is dual-homed and
# allows only the first target. A probe on the internal network must:
#   - reach the allowed target through the proxy;
#   - be refused (403) for the second target;
#   - have no direct route to either target;
#   - not see the host-owned policy file.
#
# This is opt-in because it needs Docker or Podman. If the proxy is removed or
# the network is not internal, the direct-route probe succeeds and the script
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
egress_net="mcp-egress-smoke-${suffix}"
uplink_net="mcp-egress-uplink-smoke-${suffix}"
proxy="mcp-egress-proxy-smoke-${suffix}"
allowed="mcp-target-allowed-${suffix}"
blocked="mcp-target-blocked-${suffix}"
echo_target="mcp-target-echo-${suffix}"
names=("$proxy" "$allowed" "$blocked" "$echo_target")

cleanup() {
  for name in "${names[@]}"; do
    "$engine" rm -f "$name" >/dev/null 2>&1 || true
  done
  "$engine" network rm "$egress_net" "$uplink_net" >/dev/null 2>&1 || true
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

"$engine" network create --internal "$egress_net" >/dev/null
"$engine" network create "$uplink_net" >/dev/null

start_target() {
  local name="$1"
  local port="$2"
  "$engine" run -d --name "$name" \
    --network "$uplink_net" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    "${engine_opts[@]}" \
    --entrypoint python \
    "$image" -m http.server "$port" \
    >/dev/null
}

start_target "$allowed" 18080
start_target "$blocked" 18081

"$engine" run -d --name "$echo_target" \
  --network "$uplink_net" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  "${engine_opts[@]}" \
  --entrypoint python \
  "$image" -c '
import socketserver

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)

socketserver.ThreadingTCPServer(("0.0.0.0", 19000), Handler).serve_forever()
' >/dev/null

allowed_ip="$("$engine" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$allowed")"
blocked_ip="$("$engine" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$blocked")"
echo_ip="$("$engine" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$echo_target")"
[[ -n "$allowed_ip" && -n "$blocked_ip" && -n "$echo_ip" ]] \
  || fail "could not determine target addresses"

cat > "$tmp/egress-policy.conf" <<POLICY
default deny
allow $allowed_ip 18080
allow $echo_ip 19000
POLICY
chmod 0600 "$tmp/egress-policy.conf"

# Docker accepts only one --network at creation time, so attach the proxy to
# the internal network first and connect the uplink afterwards. Podman accepts
# both forms; using network connect keeps the two engines on one path.
"$engine" run -d --name "$proxy" \
  --network "$egress_net" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  "${engine_opts[@]}" \
  --mount "type=bind,src=$tmp/egress-policy.conf,dst=/etc/server-mcp/egress-policy.conf,ro" \
  --entrypoint python \
  "$image" /usr/local/bin/egress-proxy.py \
    --listen 0.0.0.0 --port 3128 \
    --policy /etc/server-mcp/egress-policy.conf \
  >/dev/null
"$engine" network connect "$uplink_net" "$proxy" >/dev/null

# Wait for the proxy to listen. A proxy that never starts must fail here with
# its logs, not later as an opaque DNS error in the probe.
proxy_ready=0
for _ in $(seq 1 30); do
  if "$engine" exec "$proxy" python -c \
    "import socket; socket.create_connection(('127.0.0.1', 3128), 1).close()" \
    >/dev/null 2>&1; then
    proxy_ready=1
    break
  fi
  sleep 1
done
if [[ "$proxy_ready" -ne 1 ]]; then
  "$engine" logs "$proxy" >&2 || true
  fail "egress proxy did not start listening"
fi

# Address the proxy by its internal-network IP. Container-name DNS is not
# guaranteed on every engine/network combination, and the probe only needs
# the internal side.
proxy_ip="$("$engine" inspect -f "{{(index .NetworkSettings.Networks \"$egress_net\").IPAddress}}" "$proxy")"
[[ -n "$proxy_ip" ]] || fail "could not determine the proxy address on $egress_net"

probe="$(cat <<'PY'
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request

proxy = os.environ["PROXY"]
allowed = os.environ["ALLOWED"]
blocked = os.environ["BLOCKED"]
echo = os.environ["ECHO"]
proxy_host = os.environ["PROXY_HOST"]


def via_proxy(url):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    return opener.open(url, timeout=10).status


if via_proxy(f"http://{allowed}/") != 200:
    print("allowed target did not return 200", file=sys.stderr)
    sys.exit(1)

try:
    via_proxy(f"http://{blocked}/")
except urllib.error.HTTPError as exc:
    if exc.code != 403:
        print(f"blocked target returned {exc.code}, expected 403", file=sys.stderr)
        sys.exit(1)
except Exception as exc:
    print(f"blocked target failed with the wrong error: {exc}", file=sys.stderr)
    sys.exit(1)
else:
    print("blocked target was not refused", file=sys.stderr)
    sys.exit(1)

for target in (allowed, blocked):
    host, port = target.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=3).close()
    except OSError:
        continue
    print(f"direct connection unexpectedly succeeded: {target}", file=sys.stderr)
    sys.exit(1)

# IPv6 uses the same policy path; an unlisted IPv6 literal must be denied,
# not fall through as an implicit bypass.
try:
    via_proxy("http://[2001:db8::1]/")
except urllib.error.HTTPError as exc:
    if exc.code != 403:
        print(f"unlisted IPv6 target returned {exc.code}, expected 403", file=sys.stderr)
        sys.exit(1)
except Exception as exc:
    print(f"unlisted IPv6 target failed with the wrong error: {exc}", file=sys.stderr)
    sys.exit(1)
else:
    print("unlisted IPv6 target was not refused", file=sys.stderr)
    sys.exit(1)

# The SSH ProxyCommand helper uses the same CONNECT policy for a raw TCP
# tunnel, not only for HTTP requests.
result = subprocess.run(
    [
        "/usr/local/bin/server-mcp-connect",
        proxy_host,
        "3128",
        echo.rsplit(":", 1)[0],
        echo.rsplit(":", 1)[1],
    ],
    input=b"hello-through-connect\n",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=15,
)
if result.returncode != 0 or b"hello-through-connect" not in result.stdout:
    print(
        f"SSH CONNECT helper failed: rc={result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}",
        file=sys.stderr,
    )
    sys.exit(1)

if os.path.exists("/etc/server-mcp/egress-policy.conf"):
    print("probe can see the host-owned policy file", file=sys.stderr)
    sys.exit(1)
PY
)"

"$engine" run --rm \
  --network "$egress_net" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  "${engine_opts[@]}" \
  --env "PROXY=http://$proxy_ip:3128" \
  --env "PROXY_HOST=$proxy_ip" \
  --env "ALLOWED=$allowed_ip:18080" \
  --env "BLOCKED=$blocked_ip:18081" \
  --env "ECHO=$echo_ip:19000" \
  --entrypoint python \
  "$image" -c "$probe" \
  || fail "egress policy probes failed"

pass "allowed target reachable through the proxy; blocked target and direct routes fail"
echo "All egress policy checks passed."
