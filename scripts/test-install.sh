#!/usr/bin/env bash
#
# Test deploy/install.sh against a temporary HOME/XDG tree.
#
# Usage:
#   scripts/test-install.sh
#
# The test stubs systemctl and uv so it never touches the real user manager or
# resolves the workspace. It verifies that --force refreshes units only,
# --replace-config backs up and replaces configuration, and a failed
# daemon-reload makes the installer fail.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

BIN_DIR="${TMP_DIR}/bin"
mkdir -p "${BIN_DIR}"

cat > "${BIN_DIR}/systemctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SYSTEMCTL_LOG:?}"
if [[ "${SYSTEMCTL_FAIL:-0}" -eq 1 && "${1:-}" == "--user" && "${2:-}" == "daemon-reload" ]]; then
  echo "simulated daemon-reload failure" >&2
  exit 1
fi
exit 0
STUB

cat > "${BIN_DIR}/uv" <<'STUB'
#!/usr/bin/env bash
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="${2:-}"
      shift 2
      ;;
    *) shift ;;
  esac
done
if [[ -n "${output}" ]]; then
  printf 'default deny\n' > "${output}"
fi
STUB

chmod +x "${BIN_DIR}/systemctl" "${BIN_DIR}/uv"

export PATH="${BIN_DIR}:${PATH}"
export SYSTEMCTL_LOG="${TMP_DIR}/systemctl.log"
export SYSTEMCTL_FAIL=0

fail() {
  echo "❌ $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "expected file: $1"
}

assert_contains() {
  grep -Fq -- "$2" "$1" || fail "expected '$2' in $1"
}

assert_not_contains() {
  if grep -Fq -- "$2" "$1"; then
    fail "did not expect '$2' in $1"
  fi
}

assert_no_backups() {
  local directory="$1"
  if find "${directory}" -maxdepth 1 -name '*.bak.*' -print -quit | grep -q .; then
    fail "unexpected backup in ${directory}"
  fi
}

new_home() {
  local name="$1"
  export HOME="${TMP_DIR}/${name}/home"
  export XDG_CONFIG_HOME="${TMP_DIR}/${name}/xdg-config"
  export XDG_STATE_HOME="${TMP_DIR}/${name}/xdg-state"
  mkdir -p "${HOME}" "${XDG_CONFIG_HOME}" "${XDG_STATE_HOME}"
}

# Fresh install creates the config, token, policy and units.
new_home fresh
"${REPO_DIR}/deploy/install.sh" > "${TMP_DIR}/fresh.log"
CONFIG_DIR="${HOME}/.config/server-mcp"
UNIT_DIR="${HOME}/.config/containers/systemd"
assert_file "${CONFIG_DIR}/remote.yaml"
assert_file "${CONFIG_DIR}/disk.yaml"
assert_file "${CONFIG_DIR}/.env"
assert_file "${CONFIG_DIR}/known_hosts"
assert_file "${CONFIG_DIR}/ssh/id_ed25519"
assert_file "${CONFIG_DIR}/secrets/http-token"
assert_file "${CONFIG_DIR}/egress-policy.conf"
assert_file "${UNIT_DIR}/mcp-remote.container"
assert_file "${HOME}/.config/systemd/user/server-mcp.target"
assert_contains "${SYSTEMCTL_LOG}" "daemon-reload"

# --force refreshes units but leaves configuration, secrets and the token alone.
printf 'operator-config\n' >> "${CONFIG_DIR}/remote.yaml"
printf 'operator-env\n' >> "${CONFIG_DIR}/.env"
printf 'operator-known-host\n' >> "${CONFIG_DIR}/known_hosts"
printf 'operator-key\n' >> "${CONFIG_DIR}/ssh/id_ed25519"
printf 'operator-unit\n' >> "${UNIT_DIR}/mcp-remote.container"
token_before="$(sha256sum "${CONFIG_DIR}/secrets/http-token")"

"${REPO_DIR}/deploy/install.sh" --force > "${TMP_DIR}/force.log"

assert_contains "${CONFIG_DIR}/remote.yaml" "operator-config"
assert_contains "${CONFIG_DIR}/.env" "operator-env"
assert_contains "${CONFIG_DIR}/known_hosts" "operator-known-host"
assert_contains "${CONFIG_DIR}/ssh/id_ed25519" "operator-key"
assert_not_contains "${UNIT_DIR}/mcp-remote.container" "operator-unit"
cmp -s "${UNIT_DIR}/mcp-remote.container" \
  "${REPO_DIR}/deploy/quadlet/mcp-remote.container" \
  || fail "--force did not refresh the unit from the repository"
[[ "$(sha256sum "${CONFIG_DIR}/secrets/http-token")" == "${token_before}" ]] \
  || fail "--force changed the bearer token"
assert_no_backups "${CONFIG_DIR}"

# --replace-config replaces configuration with a timestamped backup, but does
# not refresh units.
printf 'operator-unit\n' >> "${UNIT_DIR}/mcp-remote.container"
"${REPO_DIR}/deploy/install.sh" --replace-config > "${TMP_DIR}/replace.log"

assert_not_contains "${CONFIG_DIR}/remote.yaml" "operator-config"
assert_not_contains "${CONFIG_DIR}/.env" "operator-env"
assert_not_contains "${CONFIG_DIR}/known_hosts" "operator-known-host"
assert_not_contains "${CONFIG_DIR}/ssh/id_ed25519" "operator-key"
assert_contains "${UNIT_DIR}/mcp-remote.container" "operator-unit"
[[ "$(sha256sum "${CONFIG_DIR}/secrets/http-token")" == "${token_before}" ]] \
  || fail "--replace-config changed the bearer token"

for file in remote.yaml .env known_hosts ssh/id_ed25519; do
  backup="$(find "${CONFIG_DIR}" -name "$(basename "${file}").bak.*" -print -quit)"
  [[ -n "${backup}" ]] || fail "missing backup for ${file}"
  case "${file}" in
    remote.yaml) assert_contains "${backup}" "operator-config" ;;
    .env) assert_contains "${backup}" "operator-env" ;;
    known_hosts) assert_contains "${backup}" "operator-known-host" ;;
    ssh/id_ed25519) assert_contains "${backup}" "operator-key" ;;
  esac
done

# A failed daemon-reload is reported and makes the installer fail.
new_home reload-failure
export SYSTEMCTL_FAIL=1
if "${REPO_DIR}/deploy/install.sh" > "${TMP_DIR}/reload-failure.log" 2>&1; then
  fail "installer succeeded despite a failed daemon-reload"
fi
assert_contains "${TMP_DIR}/reload-failure.log" "daemon-reload failed"
export SYSTEMCTL_FAIL=0

echo "✅ installer tests passed"
