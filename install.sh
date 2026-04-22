#!/usr/bin/env bash
set -euo pipefail

# Latest bootstrap for VPnBot node installers.
# It fetches a fresh archive of the main branch from codeload.github.com and
# runs scripts/install_vray.sh from that extracted tree. Helper assets are then
# installed from the same extracted tree, so normal installs do not depend on
# branch-file raw CDN freshness after this bootstrap file is loaded.

VPNBOT_NODE_INSTALLER_REF="${VPNBOT_NODE_INSTALLER_REF:-main}"
VPNBOT_NODE_INSTALLER_REPO="${VPNBOT_NODE_INSTALLER_REPO:-youtubediscord/vpnbot_node_installer}"
VPNBOT_NODE_INSTALLER_CACHE_BUST="${VPNBOT_NODE_INSTALLER_CACHE_BUST:-$(date +%s)}"
VPNBOT_NODE_INSTALLER_BASE_URL="${VPNBOT_NODE_INSTALLER_BASE_URL:-https://raw.githubusercontent.com/${VPNBOT_NODE_INSTALLER_REPO}/refs/heads/${VPNBOT_NODE_INSTALLER_REF}}"

_tmp_dir="$(mktemp -d)"
_cleanup() {
    rm -rf "${_tmp_dir}"
}
trap _cleanup EXIT

_archive="${_tmp_dir}/installer.tar.gz"
_repo_dir=""

curl -fsSL --retry 3 --connect-timeout 10     -H "Cache-Control: no-cache"     -o "${_archive}"     "https://codeload.github.com/${VPNBOT_NODE_INSTALLER_REPO}/tar.gz/refs/heads/${VPNBOT_NODE_INSTALLER_REF}?ts=${VPNBOT_NODE_INSTALLER_CACHE_BUST}"

tar -xzf "${_archive}" -C "${_tmp_dir}"
_repo_dir="$(find "${_tmp_dir}" -maxdepth 1 -mindepth 1 -type d -name '*vpnbot_node_installer*' | head -n 1)"
if [[ -z "${_repo_dir}" || ! -f "${_repo_dir}/scripts/install_vray.sh" ]]; then
    echo "[x] Failed to locate scripts/install_vray.sh in downloaded installer archive" >&2
    exit 1
fi

export VPNBOT_NODE_INSTALLER_REF
export VPNBOT_NODE_INSTALLER_REPO
export VPNBOT_NODE_INSTALLER_CACHE_BUST
export VPNBOT_NODE_INSTALLER_BASE_URL
export VPNBOT_NODE_INSTALLER_LOCAL_ROOT="${_repo_dir}"
exec bash "${_repo_dir}/scripts/install_vray.sh" "$@"
