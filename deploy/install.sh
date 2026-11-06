#!/usr/bin/env bash
#
# Install the Server MCP Quadlet units and user state.
#
# Usage:
#   deploy/install.sh [--enable] [--force] [--replace-config]
#
# The install is idempotent. Existing configuration, keys and tokens are never
# overwritten unless --replace-config is given; replaced files are backed up
# with a timestamp. --force refreshes installed units only.
# The egress policy is rendered from the installed configs when it is missing.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${HOME}/.config/server-mcp"
STATE_DIR="${HOME}/.local/state/server-mcp"
UNIT_DIR="${HOME}/.config/containers/systemd"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
ENABLE=0
FORCE_UNITS=0
REPLACE_CONFIG=0
UNITS_CHANGED=0
BACKUP_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable) ENABLE=1; shift ;;
    --force) FORCE_UNITS=1; shift ;;
    --replace-config) REPLACE_CONFIG=1; shift ;;
    -h|--help)
      sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

install -d -m 0700 \
  "${CONFIG_DIR}" \
  "${CONFIG_DIR}/secrets" \
  "${CONFIG_DIR}/ssh" \
  "${STATE_DIR}" \
  "${STATE_DIR}/audit"
install -d -m 0755 "${UNIT_DIR}" "${SYSTEMD_USER_DIR}"

backup_file() {
  local destination="$1"
  local backup

  backup="${destination}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ -e "${backup}" ]]; then
    backup="${backup}.$$"
  fi
  cp -p -- "${destination}" "${backup}"
  BACKUP_PATH="${backup}"
}

install_config() {
  local source="$1"
  local destination="$2"
  local mode="$3"

  if [[ ! -e "${destination}" ]]; then
    install -m "${mode}" "${source}" "${destination}"
  elif [[ "${REPLACE_CONFIG}" -eq 1 ]]; then
    backup_file "${destination}"
    install -m "${mode}" "${source}" "${destination}"
    echo "Replaced ${destination} (backup: ${BACKUP_PATH})"
  fi
}

install_unit() {
  local source="$1"
  local destination="$2"
  local mode="$3"

  if [[ ! -e "${destination}" || "${FORCE_UNITS}" -eq 1 ]]; then
    install -m "${mode}" "${source}" "${destination}"
    UNITS_CHANGED=1
  fi
}

install_config \
  "${REPO_DIR}/deploy/examples/catafalco/remote.yaml" \
  "${CONFIG_DIR}/remote.yaml" 0600
install_config \
  "${REPO_DIR}/deploy/examples/catafalco/disk.yaml" \
  "${CONFIG_DIR}/disk.yaml" 0600
install_config \
  "${REPO_DIR}/deploy/examples/catafalco/.env.example" \
  "${CONFIG_DIR}/.env" 0600
install_config \
  "${REPO_DIR}/deploy/examples/catafalco/known_hosts.example" \
  "${CONFIG_DIR}/known_hosts" 0644
install_config \
  "${REPO_DIR}/deploy/examples/catafalco/ssh/id_ed25519.example" \
  "${CONFIG_DIR}/ssh/id_ed25519" 0600

# The egress proxy policy is host-owned and read-only in the proxy container.
# Derive it from the same configs the MCP services use when it is missing.
if [[ ! -e "${CONFIG_DIR}/egress-policy.conf" ]]; then
  if command -v uv >/dev/null 2>&1; then
    uv run --frozen --no-dev --all-packages --directory "${REPO_DIR}" \
      python "${REPO_DIR}/deploy/render-egress-policy.py" \
      --remote "${CONFIG_DIR}/remote.yaml" \
      --disk "${CONFIG_DIR}/disk.yaml" \
      --output "${CONFIG_DIR}/egress-policy.conf" >/dev/null
  else
    install -m 0600 \
      "${REPO_DIR}/deploy/examples/catafalco/egress-policy.conf" \
      "${CONFIG_DIR}/egress-policy.conf"
  fi
fi

if [[ ! -e "${CONFIG_DIR}/secrets/http-token" ]]; then
  umask 077
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' \
    > "${CONFIG_DIR}/secrets/http-token"
  printf '\n' >> "${CONFIG_DIR}/secrets/http-token"
  chmod 0600 "${CONFIG_DIR}/secrets/http-token"
fi

for unit in \
  pi-control.network \
  mcp-egress.network \
  mcp-egress-uplink.network \
  mcp-egress-proxy.container \
  mcp-remote.container \
  mcp-disk.container; do
  install_unit "${REPO_DIR}/deploy/quadlet/${unit}" "${UNIT_DIR}/${unit}" 0644
done

# Quadlet ignores plain .target files, so the aggregation target is a regular
# systemd user unit.
install_unit \
  "${REPO_DIR}/deploy/quadlet/server-mcp.target" \
  "${SYSTEMD_USER_DIR}/server-mcp.target" 0644

if [[ "${UNITS_CHANGED}" -eq 1 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl --user daemon-reload; then
      echo "❌ systemctl --user daemon-reload failed; installed units were not reloaded." >&2
      exit 1
    fi
  else
    echo "⚠️ systemctl not found; run 'systemctl --user daemon-reload' before starting the target." >&2
  fi
fi

echo "Installed Server MCP:"
echo "  config: ${CONFIG_DIR}"
echo "  state:  ${STATE_DIR}"
echo "  units:  ${UNIT_DIR}"
echo "  target: ${SYSTEMD_USER_DIR}/server-mcp.target"
echo
echo "Next steps:"
echo "  1. Set ssh.host in ${CONFIG_DIR}/remote.yaml and disk.yaml."
echo "  2. Replace ${CONFIG_DIR}/ssh/id_ed25519 and populate known_hosts with a"
echo "     verified key (check the fingerprint before appending)."
echo "  3. Review ${CONFIG_DIR}/egress-policy.conf; it is default-deny."
echo "  4. Build or pull the image and set Image= in the .container units."
echo "  5. Start the stack:"
echo "       systemctl --user enable --now server-mcp.target"
echo
echo "The bearer token is ${CONFIG_DIR}/secrets/http-token."

if [[ "${ENABLE}" -eq 1 ]]; then
  systemctl --user enable --now server-mcp.target
fi
