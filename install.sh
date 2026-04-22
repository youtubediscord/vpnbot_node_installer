#!/usr/bin/env bash
set -euo pipefail

# Latest bootstrap for VPnBot node installers.
# It downloads the current installer script from this repository and lets that
# script fetch its own helper assets.

VPNBOT_NODE_INSTALLER_REF="${VPNBOT_NODE_INSTALLER_REF:-main}"
VPNBOT_NODE_INSTALLER_BASE_URL="${VPNBOT_NODE_INSTALLER_BASE_URL:-https://github.com/youtubediscord/vpnbot_node_installer/raw/${VPNBOT_NODE_INSTALLER_REF}}"

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cache_bust="${VPNBOT_NODE_INSTALLER_CACHE_BUST:-$(date +%s)}"

curl -fsSL --retry 3 --connect-timeout 10 \
    -H "Cache-Control: no-cache" \
    -o "${tmp_dir}/install_vray.sh" \
    "${VPNBOT_NODE_INSTALLER_BASE_URL%/}/scripts/install_vray.sh?ts=${cache_bust}"

chmod 755 "${tmp_dir}/install_vray.sh"
export VPNBOT_NODE_INSTALLER_REF
export VPNBOT_NODE_INSTALLER_BASE_URL
exec bash "${tmp_dir}/install_vray.sh" "$@"
