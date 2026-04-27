#!/usr/bin/env bash
set -euo pipefail

# ===== 3x-ui / Xray installer for VPnBot =====
# Source of truth:
#   https://github.com/youtubediscord/vpnbot_node_installer
# Usage:
#   bash <(curl -fsSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/youtubediscord/vpnbot_node_installer/refs/heads/main/install.sh?ts=$(date +%s)")
#
# Important: install.sh fetches the latest branch archive through codeload.github.com; raw fallback downloads use refs/heads/main plus cache busting.
# Supported backend modes:
# - 3x-ui    -> current panel-based workflow for VPnBot
# - xray-core -> standalone official Xray-core in a dedicated folder, without x-ui
# Architecture:
# - AWG keeps UDP/443
# - nginx stream owns shared TCP entry ports
# - shared-port inbounds are published automatically based on remark/tag markers
# - direct inbounds keep their real port without multiplexing
#
# Publication mode markers:
#   [443] or [shared:443]    -> publish via shared TCP/443
#   [8443] or [shared:8443]  -> publish via shared TCP/8443
#   [direct]                 -> keep direct port, do not publish via shared mux
#
# Shared TCP port split:
# - raw TLS / REALITY -> nginx stream (SNI routing)
# - ws / grpc / http-like -> local HTTPS frontend behind nginx http

VPNBOT_NODE_INSTALLER_REF="${VPNBOT_NODE_INSTALLER_REF:-main}"
VPNBOT_NODE_INSTALLER_REPO="${VPNBOT_NODE_INSTALLER_REPO:-youtubediscord/vpnbot_node_installer}"
VPNBOT_NODE_INSTALLER_BASE_URL="${VPNBOT_NODE_INSTALLER_BASE_URL:-https://raw.githubusercontent.com/${VPNBOT_NODE_INSTALLER_REPO}/refs/heads/${VPNBOT_NODE_INSTALLER_REF}}"

XUI_UPSTREAM_INSTALL_URL="${XUI_UPSTREAM_INSTALL_URL:-https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh}"
XUI_MAIN_FOLDER="${XUI_MAIN_FOLDER:-/usr/local/x-ui}"
XUI_BIN_CONFIG="${XUI_BIN_CONFIG:-${XUI_MAIN_FOLDER}/bin/config.json}"
XUI_DB_PATH="${XUI_DB_PATH:-/etc/x-ui/x-ui.db}"
XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"
XUI_PANEL_WEBBASEPATH="${XUI_PANEL_WEBBASEPATH:-}"
XUI_PANEL_USERNAME="${XUI_PANEL_USERNAME:-}"
XUI_PANEL_PASSWORD="${XUI_PANEL_PASSWORD:-}"
XUI_XRAY_LOG_DIR="${XUI_XRAY_LOG_DIR:-/var/log/xray}"
XUI_XRAY_ACCESS_LOG="${XUI_XRAY_ACCESS_LOG:-${XUI_XRAY_LOG_DIR}/access.log}"
XUI_XRAY_ERROR_LOG="${XUI_XRAY_ERROR_LOG:-${XUI_XRAY_LOG_DIR}/error.log}"
XUI_XRAY_LOGLEVEL="${XUI_XRAY_LOGLEVEL:-warning}"
XUI_XRAY_DNS_LOG="${XUI_XRAY_DNS_LOG:-false}"
XRAY_LOGROTATE_FILE="${XRAY_LOGROTATE_FILE:-/etc/logrotate.d/vpnbot-xray}"
XRAY_LOGROTATE_DAYS="${XRAY_LOGROTATE_DAYS:-7}"
XRAY_LOGROTATE_MAXSIZE="${XRAY_LOGROTATE_MAXSIZE:-100M}"
APP_DOMAIN="${APP_DOMAIN:-}"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
MT_DOMAIN="${MT_DOMAIN:-}"
PUBLIC_DOMAIN="${PUBLIC_DOMAIN:-}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-}"
ENABLE_CERTBOT="${ENABLE_CERTBOT:-1}"
SELF_SIGNED_CERT_NAME="${SELF_SIGNED_CERT_NAME:-}"
DDNS_PROVIDER="${DDNS_PROVIDER:-}"
DDNS_ZONE="${DDNS_ZONE:-}"
DDNS_TOKEN="${DDNS_TOKEN:-}"
DDNS_INSTRUCTIONS_TEXT="${DDNS_INSTRUCTIONS_TEXT:-}"
DDNS_HOST_LABEL="${DDNS_HOST_LABEL:-}"
DDNS_LABEL_SUFFIX="${DDNS_LABEL_SUFFIX:-tls}"
DDNS_WAIT_TIMEOUT="${DDNS_WAIT_TIMEOUT:-180}"
DDNS_WAIT_INTERVAL="${DDNS_WAIT_INTERVAL:-5}"
VPNBOT_SERVER_ID="${VPNBOT_SERVER_ID:-}"
SHARED_HTTP_DOMAIN="${SHARED_HTTP_DOMAIN:-}"
HTTP_FRONTEND_LOCAL_PORT="${HTTP_FRONTEND_LOCAL_PORT:-10443}"
HTTP_FRONTEND_PROXY_LOCAL_PORT="${HTTP_FRONTEND_PROXY_LOCAL_PORT:-10444}"
NGINX_SERVER_NAME="${NGINX_SERVER_NAME:-}"
NGINX_PANEL_LOCATION="${NGINX_PANEL_LOCATION:-}"
NGINX_SSL_CERT="${NGINX_SSL_CERT:-/etc/nginx/ssl/vpnbot/fullchain.pem}"
NGINX_SSL_KEY="${NGINX_SSL_KEY:-/etc/nginx/ssl/vpnbot/privkey.pem}"
XUI_INSTALLER_STATE_FILE="${XUI_INSTALLER_STATE_FILE:-/etc/vpnbot-xui-installer-state.json}"
XUI_ROLLOUT_BUNDLE_FILE="${XUI_ROLLOUT_BUNDLE_FILE:-/etc/vpnbot-xui-rollout-bundle.json}"
XUI_INSTALLER_DEFAULTS_FILE="${XUI_INSTALLER_DEFAULTS_FILE:-/etc/vpnbot-xui-defaults.env}"
XUI_PRESET_HELPER="${XUI_PRESET_HELPER:-/usr/local/bin/vpnbot-xui-presets}"
VPNBOT_VLESS_PRESET_HELPER="${VPNBOT_VLESS_PRESET_HELPER:-/usr/local/bin/vpnbot-vless-presets}"
VPNBOT_ASSET_LIB_DIR="${VPNBOT_ASSET_LIB_DIR:-/usr/local/lib/vpnbot}"
VPNBOT_ASSET_SHARE_DIR="${VPNBOT_ASSET_SHARE_DIR:-/usr/local/share/vpnbot}"
VPNBOT_REALITY_SNI_POOL_FILE="${VPNBOT_REALITY_SNI_POOL_FILE:-${VPNBOT_ASSET_SHARE_DIR}/reality_sni_pool.json}"
VPNBOT_NGINX_AUTOSTART="${VPNBOT_NGINX_AUTOSTART:-1}"
XUI_PRESET_AUTORUN="${XUI_PRESET_AUTORUN:-auto}"
XUI_DEFAULTS_LOADED=0
NGINX_HTTP_SITE_FILE="/etc/nginx/sites-available/vpnbot_vray_http.conf"
NGINX_HTTP_LOCATION_DIR="/etc/nginx/vpnbot-http-locations.d"
NGINX_STREAM_ROOT_FILE="/etc/nginx/vpnbot-stream-root.conf"
NGINX_STREAM_INCLUDE_DIR="/etc/nginx/vpnbot-stream.d"
NGINX_STREAM_MAP_FILE="${NGINX_STREAM_INCLUDE_DIR}/vpnbot_stream_map.conf"
NGINX_STREAM_SERVER_FILE="${NGINX_STREAM_INCLUDE_DIR}/vpnbot_stream_server.conf"
NGINX_WS_HELPER="/usr/local/bin/vpnbot-nginx-add-ws-route"
NGINX_GRPC_HELPER="/usr/local/bin/vpnbot-nginx-add-grpc-route"
NGINX_ROUTE_LIST_HELPER="/usr/local/bin/vpnbot-nginx-list-routes"
XUI_SYNC_SCRIPT="/usr/local/bin/vpnbot-xui-sync-routes"
XUI_SYNC_SERVICE="/etc/systemd/system/vpnbot-xui-sync-routes.service"
XUI_SYNC_PATH="/etc/systemd/system/vpnbot-xui-sync-routes.path"
XUI_SYNC_TIMER="/etc/systemd/system/vpnbot-xui-sync-routes.timer"
XUI_SYNC_STATE_DIR="/var/lib/vpnbot-xui-sync"
XUI_UPSTREAM_TMP="/tmp/install_3xui_upstream.sh"
XUI_SOURCED_TMP="/tmp/install_3xui_upstream_sourced.sh"
VPNBOT_VLESS_BACKEND_EXPLICIT=0
if [[ -n "${VPNBOT_VLESS_BACKEND:-}" ]]; then
    VPNBOT_VLESS_BACKEND_EXPLICIT=1
fi
VPNBOT_VLESS_BACKEND="${VPNBOT_VLESS_BACKEND:-3x-ui}"
XRAY_CORE_ROOT="${XRAY_CORE_ROOT:-/opt/vpnbot/xray-core}"
XRAY_CORE_BIN="${XRAY_CORE_BIN:-${XRAY_CORE_ROOT}/bin/xray}"
XRAY_CORE_CONFIG_DIR="${XRAY_CORE_CONFIG_DIR:-${XRAY_CORE_ROOT}/config}"
XRAY_CORE_SHARE_DIR="${XRAY_CORE_SHARE_DIR:-${XRAY_CORE_ROOT}/share}"
XRAY_CORE_LOG_DIR="${XRAY_CORE_LOG_DIR:-${XRAY_CORE_ROOT}/logs}"
XRAY_CORE_MANAGED_INBOUNDS_FILE="${XRAY_CORE_MANAGED_INBOUNDS_FILE:-${XRAY_CORE_CONFIG_DIR}/50_vpnbot_managed_inbounds.json}"
XRAY_CORE_SERVICE_NAME="${XRAY_CORE_SERVICE_NAME:-vpnbot-xray.service}"
XRAY_CORE_SERVICE_FILE="${XRAY_CORE_SERVICE_FILE:-/etc/systemd/system/${XRAY_CORE_SERVICE_NAME}}"
XRAY_CORE_INSTALLER_STATE_FILE="${XRAY_CORE_INSTALLER_STATE_FILE:-/etc/vpnbot-xray-installer-state.json}"
XRAY_CORE_ROLLOUT_BUNDLE_FILE="${XRAY_CORE_ROLLOUT_BUNDLE_FILE:-/etc/vpnbot-xray-rollout-bundle.json}"
XRAY_CORE_API_SERVER="${XRAY_CORE_API_SERVER:-127.0.0.1:10085}"
XRAY_CTL_SCRIPT="${XRAY_CTL_SCRIPT:-/usr/local/bin/vpnbot-xrayctl}"
XRAY_RESERVED_PORTS_SCRIPT="${XRAY_RESERVED_PORTS_SCRIPT:-/usr/local/bin/vpnbot-xray-reserve-ports}"
XRAY_ONLINE_TRACKER_CANONICAL_SCRIPT="/usr/local/bin/vpnbot-xray-online-tracker"
XRAY_ONLINE_TRACKER_LEGACY_SCRIPT="/root/vpnbot-xray-online-tracker"
XRAY_ONLINE_TRACKER_SCRIPT="${XRAY_ONLINE_TRACKER_SCRIPT:-${XRAY_ONLINE_TRACKER_CANONICAL_SCRIPT}}"
if [[ "${XRAY_ONLINE_TRACKER_SCRIPT}" == "${XRAY_ONLINE_TRACKER_LEGACY_SCRIPT}" ]]; then
    XRAY_ONLINE_TRACKER_SCRIPT="${XRAY_ONLINE_TRACKER_CANONICAL_SCRIPT}"
fi
XRAY_ONLINE_TRACKER_SERVICE_NAME="${XRAY_ONLINE_TRACKER_SERVICE_NAME:-vpnbot-xray-online.service}"
XRAY_ONLINE_TRACKER_SERVICE_FILE="${XRAY_ONLINE_TRACKER_SERVICE_FILE:-/etc/systemd/system/${XRAY_ONLINE_TRACKER_SERVICE_NAME}}"
XRAY_ONLINE_TRACKER_BIND="${XRAY_ONLINE_TRACKER_BIND:-127.0.0.1}"
XRAY_ONLINE_TRACKER_PORT="${XRAY_ONLINE_TRACKER_PORT:-10086}"
XRAY_ONLINE_TRACKER_WINDOW_SECONDS="${XRAY_ONLINE_TRACKER_WINDOW_SECONDS:-180}"
XRAY_ONLINE_TRACKER_BOOTSTRAP_BYTES="${XRAY_ONLINE_TRACKER_BOOTSTRAP_BYTES:-524288}"
XRAY_ONLINE_TRACKER_STATS_INTERVAL_SECONDS="${XRAY_ONLINE_TRACKER_STATS_INTERVAL_SECONDS:-60}"
XRAY_ONLINE_TRACKER_URL="${XRAY_ONLINE_TRACKER_URL:-http://${XRAY_ONLINE_TRACKER_BIND}:${XRAY_ONLINE_TRACKER_PORT}/online}"
XRAY_ABUSE_AUDIT_WINDOW_SECONDS="${XRAY_ABUSE_AUDIT_WINDOW_SECONDS:-86400}"
XRAY_ABUSE_AUDIT_MAX_EVENTS="${XRAY_ABUSE_AUDIT_MAX_EVENTS:-50000}"
XRAY_ABUSE_AUDIT_TOP_LIMIT="${XRAY_ABUSE_AUDIT_TOP_LIMIT:-20}"
XRAY_ABUSE_AUDIT_URL="${XRAY_ABUSE_AUDIT_URL:-http://${XRAY_ONLINE_TRACKER_BIND}:${XRAY_ONLINE_TRACKER_PORT}/abuse}"
XRAY_ABUSE_MULTI_IP_OBSERVE_IPS="${XRAY_ABUSE_MULTI_IP_OBSERVE_IPS:-2}"
XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS="${XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS:-4}"
XRAY_ABUSE_MULTI_IP_HIGH_IPS="${XRAY_ABUSE_MULTI_IP_HIGH_IPS:-8}"
XRAY_ABUSE_MULTI_IP_CRITICAL_IPS="${XRAY_ABUSE_MULTI_IP_CRITICAL_IPS:-12}"
XRAY_ABUSE_MULTI_IP_MIN_PREFIXES="${XRAY_ABUSE_MULTI_IP_MIN_PREFIXES:-3}"
XRAY_ABUSE_MULTI_IP_TOP_LIMIT="${XRAY_ABUSE_MULTI_IP_TOP_LIMIT:-30}"
XRAY_ABUSE_MULTI_IP_WINDOWS="${XRAY_ABUSE_MULTI_IP_WINDOWS:-30,60,180}"
XRAY_ABUSE_MULTI_IP_HISTORY_FILE="${XRAY_ABUSE_MULTI_IP_HISTORY_FILE:-/var/lib/vpnbot-xray-online/multi_ip_history.json}"
XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS="${XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS:-1209600}"
XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS="${XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS:-86400}"
XRAY_ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS="${XRAY_ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS:-120}"
XRAY_ABUSE_MULTI_IP_CACHE_TTL_SECONDS="${XRAY_ABUSE_MULTI_IP_CACHE_TTL_SECONDS:-10}"
XRAY_ABUSE_MULTI_IP_URL="${XRAY_ABUSE_MULTI_IP_URL:-http://${XRAY_ONLINE_TRACKER_BIND}:${XRAY_ONLINE_TRACKER_PORT}/abuse/multi-ip}"
XRAY_SYNC_SCRIPT="${XRAY_SYNC_SCRIPT:-/usr/local/bin/vpnbot-xray-sync-routes}"
XRAY_SYNC_SERVICE="${XRAY_SYNC_SERVICE:-/etc/systemd/system/vpnbot-xray-sync-routes.service}"
XRAY_SYNC_PATH="${XRAY_SYNC_PATH:-/etc/systemd/system/vpnbot-xray-sync-routes.path}"
XRAY_SYNC_TIMER="${XRAY_SYNC_TIMER:-/etc/systemd/system/vpnbot-xray-sync-routes.timer}"
XRAY_SYNC_STATE_DIR="${XRAY_SYNC_STATE_DIR:-/var/lib/vpnbot-xray-sync}"
XRAY_CORE_RELEASE_CHANNEL="${XRAY_CORE_RELEASE_CHANNEL:-stable}"
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-latest}"
XRAY_CORE_RELEASES_API_URL="${XRAY_CORE_RELEASES_API_URL:-https://api.github.com/repos/XTLS/Xray-core/releases}"
XRAY_CORE_SMOKE_ENABLE="${XRAY_CORE_SMOKE_ENABLE:-0}"
# Keep TCP/443 free for shared production inbounds by default.
XRAY_CORE_SMOKE_PORT="${XRAY_CORE_SMOKE_PORT:-8443}"
XRAY_CORE_SMOKE_DOMAIN="${XRAY_CORE_SMOKE_DOMAIN:-www.cloudflare.com}"
XRAY_CORE_SMOKE_UUID="${XRAY_CORE_SMOKE_UUID:-}"
XRAY_CORE_INSTALLED_VERSION=""
XRAY_CORE_PUBLIC_ENDPOINT=""
XRAY_CORE_SMOKE_PORT_EFFECTIVE=""
XRAY_CORE_SMOKE_PUBLIC_KEY=""
XRAY_CORE_SMOKE_SHORT_ID=""
XRAY_CORE_SMOKE_LINK=""
INSTALL_VRAY_CURL_COMMAND='bash <(curl -fsSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/youtubediscord/vpnbot_node_installer/refs/heads/main/install.sh?ts=$(date +%s)")'
VPNBOT_NETWORK_SYSCTL_FILE="${VPNBOT_NETWORK_SYSCTL_FILE:-/etc/sysctl.d/99-vpnbot-network.conf}"
VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE="${VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE:-/etc/sysctl.d/99-vpnbot-xray-reserved-ports.conf}"
VPNBOT_NF_CONNTRACK_MAX="${VPNBOT_NF_CONNTRACK_MAX:-1048576}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
info() { echo -e "${CYAN}[i]${NC} $*"; }


check_root() {
    [[ ${EUID} -eq 0 ]] || { err "Run this script as root"; exit 1; }
}


is_interactive_terminal() {
    [[ -t 0 && -t 1 ]]
}


gen_random_string() {
    local length="$1"
    openssl rand -base64 $(( length * 2 )) | tr -dc 'a-zA-Z0-9' | head -c "$length"
}


trim_dot_domain() {
    local value="${1:-}"
    value="${value#.}"
    value="${value%.}"
    printf '%s' "${value}"
}


slugify_host_label() {
    local value="${1:-}"
    value="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-{2,}/-/g')"
    printf '%s' "${value}"
}


normalize_vpnbot_server_id_value() {
    local value="${1:-}"
    value="$(printf '%s' "${value}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    value="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]')"
    printf '%s' "${value}"
}


normalize_vpnbot_server_id() {
    local original normalized
    original="${VPNBOT_SERVER_ID:-}"
    normalized="$(normalize_vpnbot_server_id_value "${original}")"
    if [[ -n "${original}" && "${normalized}" != "${original}" ]]; then
        warn "Normalized VPNBOT_SERVER_ID to lowercase: ${normalized}"
    fi
    VPNBOT_SERVER_ID="${normalized}"
}


normalize_vless_backend_mode() {
    local raw normalized
    raw="${VPNBOT_VLESS_BACKEND:-3x-ui}"
    normalized="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
    case "${normalized}" in
        3x-ui|3xui|x-ui|xui)
            VPNBOT_VLESS_BACKEND="3x-ui"
            ;;
        xray-core|xraycore|pure-xray|pure_xray|core)
            VPNBOT_VLESS_BACKEND="xray-core"
            ;;
        *)
            err "Unsupported VPNBOT_VLESS_BACKEND=${raw}. Supported values: 3x-ui, xray-core"
            exit 1
            ;;
    esac
}


is_3xui_backend() {
    [[ "${VPNBOT_VLESS_BACKEND}" == "3x-ui" ]]
}


is_xray_core_backend() {
    [[ "${VPNBOT_VLESS_BACKEND}" == "xray-core" ]]
}


env_is_true() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}


get_primary_ipv4() {
    local ip=""
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
    if [[ -z "${ip}" ]]; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    printf '%s' "${ip}"
}


is_ipv4_literal() {
    local value="${1:-}"
    IPV4_LITERAL_TO_CHECK="${value}" python3 - <<'PY'
import ipaddress
import os
import sys

value = os.environ.get("IPV4_LITERAL_TO_CHECK", "").strip()
try:
    ip = ipaddress.ip_address(value)
except ValueError:
    sys.exit(1)
sys.exit(0 if ip.version == 4 else 1)
PY
}


wait_for_host_resolution_to_ipv4() {
    local host="$1"
    local expected_ipv4="$2"
    local host_role="${3:-host}"
    local timeout="${DDNS_WAIT_TIMEOUT}"
    local interval="${DDNS_WAIT_INTERVAL}"

    if [[ -z "${host}" || -z "${expected_ipv4}" ]]; then
        return 0
    fi

    if is_ipv4_literal "${host}"; then
        if [[ "${host}" == "${expected_ipv4}" ]]; then
            return 0
        fi
        err "${host_role^} ${host} does not match this server IP ${expected_ipv4}."
        return 1
    fi

    DOMAIN_TO_CHECK="${host}" EXPECTED_IPV4="${expected_ipv4}" WAIT_TIMEOUT="${timeout}" WAIT_INTERVAL="${interval}" python3 - <<'PY'
import os
import socket
import sys
import time

domain = os.environ["DOMAIN_TO_CHECK"]
expected = os.environ["EXPECTED_IPV4"]
timeout = int(os.environ["WAIT_TIMEOUT"])
interval = max(1, int(os.environ["WAIT_INTERVAL"]))
deadline = time.time() + timeout
last_seen = []

while time.time() < deadline:
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in infos if item and item[4]})
        last_seen = addresses
        if expected in addresses:
            sys.exit(0)
    except Exception:
        last_seen = []
    time.sleep(interval)

msg = ", ".join(last_seen) if last_seen else "<nothing>"
print(f"Domain {domain} did not resolve to {expected} within {timeout}s. Last seen: {msg}", file=sys.stderr)
sys.exit(1)
PY
}


get_default_ddns_host_label() {
    local base suffix host_short label
    base="${VPNBOT_SERVER_ID:-}"
    if [[ -z "${base}" ]]; then
        host_short="$(hostname -s 2>/dev/null || true)"
        base="${host_short:-node}"
    fi
    label="$(slugify_host_label "${base}")"
    if [[ -z "${label}" ]]; then
        label="node"
    fi
    suffix="$(slugify_host_label "${DDNS_LABEL_SUFFIX}")"
    if [[ -n "${suffix}" && "${suffix}" != "none" ]]; then
        case "${label}" in
            *-"${suffix}"|"${suffix}")
                ;;
            *)
                label="${label}-${suffix}"
                ;;
        esac
    fi
    printf '%s' "${label}"
}


load_installer_defaults() {
    if [[ -f "${XUI_INSTALLER_DEFAULTS_FILE}" ]]; then
        # shellcheck disable=SC1090
        source "${XUI_INSTALLER_DEFAULTS_FILE}"
        XUI_DEFAULTS_LOADED=1
    fi
}


save_installer_defaults() {
    umask 077
    cat > "${XUI_INSTALLER_DEFAULTS_FILE}" <<EOF
DDNS_PROVIDER=${DDNS_PROVIDER@Q}
DDNS_ZONE=${DDNS_ZONE@Q}
DDNS_TOKEN=${DDNS_TOKEN@Q}
DDNS_LABEL_SUFFIX=${DDNS_LABEL_SUFFIX@Q}
EOF
    chmod 600 "${XUI_INSTALLER_DEFAULTS_FILE}"
}


prompt_plain_value() {
    local prompt="$1"
    local default_value="${2:-}"
    local value=""
    if [[ -n "${default_value}" ]]; then
        read -r -p "${prompt} [${default_value}]: " value
        printf '%s' "${value:-${default_value}}"
        return 0
    fi
    while [[ -z "${value}" ]]; do
        read -r -p "${prompt}: " value
    done
    printf '%s' "${value}"
}


prompt_secret_value() {
    local prompt="$1"
    local value=""
    while [[ -z "${value}" ]]; do
        read -r -s -p "${prompt}: " value
        echo
    done
    printf '%s' "${value}"
}


prompt_multiline_value() {
    local prompt="$1"
    local line=""
    local value=""
    echo "${prompt}"
    echo "Finish input with an empty line."
    while IFS= read -r line; do
        [[ -z "${line}" ]] && break
        value+="${value:+$'\n'}${line}"
    done
    printf '%s' "${value}"
}


prompt_yes_no() {
    local prompt="$1"
    local default_answer="${2:-y}"
    local answer="" hint="" normalized=""
    case "${default_answer}" in
        y|Y|yes|YES)
            hint="[Y/n]"
            default_answer="y"
            ;;
        n|N|no|NO)
            hint="[y/N]"
            default_answer="n"
            ;;
        *)
            hint="[y/n]"
            default_answer=""
            ;;
    esac

    while true; do
        if [[ -n "${hint}" ]]; then
            read -r -p "${prompt} ${hint}: " answer
        else
            read -r -p "${prompt}: " answer
        fi
        if [[ -z "${answer}" && -n "${default_answer}" ]]; then
            answer="${default_answer}"
        fi
        normalized="$(printf '%s' "${answer}" | tr '[:upper:]' '[:lower:]')"
        case "${normalized}" in
            y|yes)
                return 0
                ;;
            n|no)
                return 1
                ;;
        esac
        warn "Please answer yes or no."
    done
}


prompt_domain_setup_mode() {
    local answer=""
    while true; do
        printf '%s\n' "Domain setup mode:" >&2
        printf '%s\n' "  1) I already have a ready domain/subdomain" >&2
        printf '%s\n' "  2) Configure Dynv6 automatically" >&2
        read -r -p "Choose [1/2]: " answer
        case "${answer}" in
            1)
                printf 'ready'
                return 0
                ;;
            2)
                printf 'dynv6'
                return 0
                ;;
        esac
        printf '%s\n' "[!] Please choose 1 or 2." >&2
    done
}


prompt_vless_backend_mode_if_needed() {
    local answer=""

    if [[ "${VPNBOT_VLESS_BACKEND_EXPLICIT}" == "1" ]]; then
        normalize_vless_backend_mode
        info "VLESS backend mode from env: ${VPNBOT_VLESS_BACKEND}"
        return 0
    fi

    if ! is_interactive_terminal; then
        normalize_vless_backend_mode
        info "VLESS backend mode: ${VPNBOT_VLESS_BACKEND} (non-interactive default; set VPNBOT_VLESS_BACKEND=xray-core to override)"
        return 0
    fi

    while true; do
        printf '%s\n' "VLESS backend mode:" >&2
        printf '%s\n' "  1) Standalone Xray-core (recommended for new servers)" >&2
        printf '%s\n' "  2) 3x-ui panel (legacy/current bot production mode)" >&2
        read -r -p "Choose [1/2, default 1]: " answer
        answer="${answer:-1}"
        case "${answer}" in
            1)
                VPNBOT_VLESS_BACKEND="xray-core"
                info "Selected VLESS backend mode: ${VPNBOT_VLESS_BACKEND}"
                return 0
                ;;
            2)
                VPNBOT_VLESS_BACKEND="3x-ui"
                info "Selected VLESS backend mode: ${VPNBOT_VLESS_BACKEND}"
                return 0
                ;;
        esac
        printf '%s\n' "[!] Please choose 1 or 2." >&2
    done
}


clear_dynv6_runtime_values() {
    DDNS_PROVIDER=""
    DDNS_ZONE=""
    DDNS_TOKEN=""
    DDNS_INSTRUCTIONS_TEXT=""
    DDNS_HOST_LABEL=""
}


strip_wrapping_quotes() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ ${#value} -ge 2 ]]; then
        if [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "${value:0:1}" == "\"" && "${value: -1}" == "\"" ]]; then
            value="${value:1:${#value}-2}"
        fi
    fi
    printf '%s' "${value}"
}


PARSED_DYNV6_TOKEN=""
PARSED_DYNV6_ZONE=""


parse_dynv6_instructions_blob() {
    local blob="${1:-}"
    local parsed=""
    PARSED_DYNV6_TOKEN=""
    PARSED_DYNV6_ZONE=""
    [[ -n "${blob}" ]] || return 0

    parsed="$(
        DYNV6_INSTRUCTIONS_BLOB="${blob}" python3 - <<'PY'
import os
import re

text = os.environ.get("DYNV6_INSTRUCTIONS_BLOB", "").replace("\r", "")
token = ""
zone = ""
loose_lines = []

for raw in text.splitlines():
    line = raw.strip()
    if not line:
        continue
    if "=" in line:
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip().strip("'\"")
        if key == "password" and value and value.lower() != "none":
            token = value
        elif key == "zone" and value:
            zone = value
    else:
        loose_lines.append(line.strip().strip("'\""))

if not token:
    compact = [line for line in loose_lines if "=" not in line and "/" not in line]
    if len(compact) == 1 and "." not in compact[0]:
        token = compact[0]

if not zone:
    for item in reversed(loose_lines):
        candidate = item.strip().strip(".")
        if re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", candidate):
            zone = candidate
            break

print(token)
print(zone)
PY
    )"

    PARSED_DYNV6_TOKEN="$(printf '%s' "${parsed}" | sed -n '1p')"
    PARSED_DYNV6_ZONE="$(printf '%s' "${parsed}" | sed -n '2p')"
}


normalize_dynv6_credentials() {
    local blob=""

    if [[ -n "${DDNS_INSTRUCTIONS_TEXT}" ]]; then
        parse_dynv6_instructions_blob "${DDNS_INSTRUCTIONS_TEXT}"
        if [[ -z "${DDNS_TOKEN}" && -n "${PARSED_DYNV6_TOKEN}" ]]; then
            DDNS_TOKEN="${PARSED_DYNV6_TOKEN}"
        fi
        if [[ -z "${DDNS_ZONE}" && -n "${PARSED_DYNV6_ZONE}" ]]; then
            DDNS_ZONE="${PARSED_DYNV6_ZONE}"
        fi
    fi

    blob="${DDNS_TOKEN}"
    if [[ "${blob}" == *$'\n'* || "${blob}" == *"password="* || "${blob}" == *"protocol="* || "${blob}" == *"server="* ]]; then
        parse_dynv6_instructions_blob "${blob}"
        if [[ -n "${PARSED_DYNV6_TOKEN}" ]]; then
            DDNS_TOKEN="${PARSED_DYNV6_TOKEN}"
        fi
        if [[ -z "${DDNS_ZONE}" && -n "${PARSED_DYNV6_ZONE}" ]]; then
            DDNS_ZONE="${PARSED_DYNV6_ZONE}"
        fi
    fi

    DDNS_TOKEN="$(strip_wrapping_quotes "${DDNS_TOKEN}")"
    DDNS_ZONE="$(trim_dot_domain "$(strip_wrapping_quotes "${DDNS_ZONE}")")"
}


collect_interactive_defaults() {
    local domain_mode=""
    local dynv6_blob=""

    if ! is_interactive_terminal; then
        return 0
    fi

    normalize_dynv6_credentials

    if [[ -n "${PUBLIC_DOMAIN}" ]]; then
        return 0
    fi

    if [[ ${XUI_DEFAULTS_LOADED} -eq 1 && ( -n "${DDNS_ZONE}" || -n "${DDNS_TOKEN}" || -n "${DDNS_PROVIDER}" ) ]]; then
        info "Found saved Dynv6 defaults in ${XUI_INSTALLER_DEFAULTS_FILE}."
        if ! prompt_yes_no "Use saved Dynv6 settings for this run?" "y"; then
            clear_dynv6_runtime_values
        fi
    fi

    if [[ -z "${PUBLIC_DOMAIN}" && -z "${DDNS_PROVIDER}" && -z "${DDNS_ZONE}" && -z "${DDNS_TOKEN}" ]]; then
        info "This installer can either use an existing public domain or configure Dynv6 for you."
        domain_mode="$(prompt_domain_setup_mode)"
        if [[ "${domain_mode}" == "ready" ]]; then
            PUBLIC_DOMAIN="$(trim_dot_domain "$(prompt_plain_value "App/public domain" "")")"
            APP_DOMAIN="${PUBLIC_DOMAIN}"
            prompt_domain_roles_if_needed
            return 0
        fi
        DDNS_PROVIDER="dynv6"
    fi

    if [[ "${DDNS_PROVIDER}" == "dynv6" || ( -z "${PUBLIC_DOMAIN}" && ( -n "${DDNS_ZONE}" || -n "${DDNS_TOKEN}" ) ) ]]; then
        DDNS_PROVIDER="dynv6"
        if [[ -z "${DDNS_ZONE}" && -z "${DDNS_TOKEN}" ]]; then
            info "Paste the full Dynv6 Instructions block if you have it."
            info "Leave it empty and press Enter twice if you want to enter zone/password separately."
            dynv6_blob="$(prompt_multiline_value "Dynv6 Instructions block")"
            if [[ -n "${dynv6_blob}" ]]; then
                DDNS_INSTRUCTIONS_TEXT="${dynv6_blob}"
                normalize_dynv6_credentials
            fi
        fi
        if [[ -z "${DDNS_ZONE}" ]]; then
            DDNS_ZONE="$(trim_dot_domain "$(prompt_plain_value "Dynv6 zone" "")")"
        fi
        if [[ -z "${DDNS_TOKEN}" ]]; then
            DDNS_TOKEN="$(prompt_secret_value "Dynv6 password from Instructions (password='...')")"
        fi
        normalize_dynv6_credentials
        if [[ -z "${VPNBOT_SERVER_ID}" && -z "${DDNS_HOST_LABEL}" && -z "${PUBLIC_DOMAIN}" ]]; then
            VPNBOT_SERVER_ID="$(prompt_plain_value "Server id for hostname" "$(hostname -s 2>/dev/null || echo node)")"
            normalize_vpnbot_server_id
        fi
        save_installer_defaults
        log "Saved shared Dynv6 defaults to ${XUI_INSTALLER_DEFAULTS_FILE}"
        prompt_domain_roles_if_needed
        return 0
    fi
}


suggest_related_domain() {
    local role="$1"
    local source="${2:-}"
    local base=""

    source="$(trim_dot_domain "${source}")"
    if [[ -z "${source}" ]]; then
        printf ''
        return 0
    fi

    if [[ "${source}" == app.* ]]; then
        base="${source#app.}"
    elif [[ "${source}" == panel.* ]]; then
        base="${source#panel.}"
    elif [[ "${source}" == mt.* ]]; then
        base="${source#mt.}"
    else
        base="${source}"
    fi

    printf '%s.%s' "${role}" "${base}"
}


suggest_mt_domain() {
    local source="${1:-}"
    suggest_related_domain "mt" "${source}"
}


dynv6_rest_api_request() {
    local method="$1"
    local url="$2"
    local body="${3:-}"
    local status_file="${4:-}"
    local response_file status
    response_file="$(mktemp)"
    local curl_args=(
        -sS
        -o "${response_file}"
        -w "%{http_code}"
        -X "${method}"
        -H "Authorization: Bearer ${DDNS_TOKEN}"
        -H "Accept: application/json"
    )
    if [[ -n "${body}" ]]; then
        curl_args+=(-H "Content-Type: application/json" --data "${body}")
    fi
    status="$(curl "${curl_args[@]}" "${url}" || true)"
    if [[ -n "${status_file}" ]]; then
        printf '%s' "${status}" > "${status_file}"
    fi
    cat "${response_file}"
    rm -f "${response_file}"
    [[ "${status}" =~ ^2[0-9][0-9]$ ]]
}


dynv6_update_api_request() {
    local hostname="$1"
    local ipv4_value="$2"
    local status_file="${3:-}"
    local response_file status
    response_file="$(mktemp)"
    status="$(
        curl -sSG \
        -o "${response_file}" \
        -w "%{http_code}" \
        "https://dynv6.com/api/update" \
        --data-urlencode "hostname=${hostname}" \
        --data-urlencode "token=${DDNS_TOKEN}" \
        --data-urlencode "ipv4=${ipv4_value}" || true
    )"
    if [[ -n "${status_file}" ]]; then
        printf '%s' "${status}" > "${status_file}"
    fi
    cat "${response_file}"
    rm -f "${response_file}"
    [[ "${status}" =~ ^2[0-9][0-9]$ ]]
}


dynv6_try_update_api_fallback() {
    local hostname="$1"
    local ipv4_value="$2"
    local reason="${3:-unknown}"
    local update_response=""
    local update_status_file=""
    local update_status=""

    warn "Dynv6 REST API is unavailable for this token (${reason}). Falling back to Dynv6 Update API."
    warn "This is normal when DDNS_TOKEN is the value from Dynv6 Instructions: password='...'."
    warn "That value is an update token for Dynv6 Update API, not a full REST API bearer token."

    update_status_file="$(mktemp)"
    update_response="$(dynv6_update_api_request "${hostname}" "${ipv4_value}" "${update_status_file}" || true)"
    update_status="$(cat "${update_status_file}" 2>/dev/null || true)"
    rm -f "${update_status_file}"

    if [[ -z "${update_status}" || ! "${update_status}" =~ ^2[0-9][0-9]$ ]]; then
        if [[ "${update_status}" == "401" || "${update_status}" == "403" ]]; then
            err "Dynv6 Update API rejected the provided password/token (HTTP ${update_status}) for ${hostname}."
            err "The value from Dynv6 Instructions line password='...' is the update token. There is no separate extra HTTP token."
            err "But this update token is not a full REST bearer token, so it is safer to use an already created hostname."
            err "Create ${hostname} manually in Dynv6 first, then rerun install_vray.sh with PUBLIC_DOMAIN=${hostname} and without DDNS_PROVIDER/DDNS_ZONE/DDNS_TOKEN."
        else
            err "Dynv6 Update API failed for ${hostname} (HTTP ${update_status:-unknown})."
            err "If you only have the Dynv6 Instructions password='...' value, create ${hostname} manually in Dynv6 first and rerun with PUBLIC_DOMAIN=${hostname}."
        fi
        if [[ -n "${update_response}" ]]; then
            err "Dynv6 response: ${update_response}"
        fi
        exit 1
    fi

    if [[ "${update_response}" == "badauth" || "${update_response}" == "abuse" || "${update_response}" == "notfqdn" || "${update_response}" == "nohost" || "${update_response}" == "dnserr" || "${update_response}" == "911" ]]; then
        err "Dynv6 Update API returned error: ${update_response}"
        if [[ "${update_response}" == "nohost" ]]; then
            err "This usually means the hostname does not exist yet in Dynv6. Create ${hostname} manually first, then rerun with PUBLIC_DOMAIN=${hostname}."
        elif [[ "${update_response}" == "badauth" ]]; then
            err "Use the exact value from Dynv6 Instructions line password='...'. Do not include surrounding text."
        fi
        exit 1
    fi

    wait_for_public_domain_resolution "${hostname}" "${ipv4_value}"
    log "Dynv6 domain ready via Update API: ${hostname} -> ${ipv4_value}"
    return 0
}


wait_for_public_domain_resolution() {
    local domain="$1"
    local expected_ipv4="$2"
    wait_for_host_resolution_to_ipv4 "${domain}" "${expected_ipv4}" "public domain"
}


derive_domain_bundle_defaults() {
    local seed="${1:-}"
    local base=""

    seed="$(trim_dot_domain "${seed}")"
    if [[ -z "${seed}" ]]; then
        return 0
    fi

    if [[ "${seed}" == app.* ]]; then
        base="${seed#app.}"
    elif [[ "${seed}" == panel.* ]]; then
        base="${seed#panel.}"
    elif [[ "${seed}" == mt.* ]]; then
        base="${seed#mt.}"
    else
        base="${seed}"
    fi

    printf '%s\n' "app.${base}"
    printf '%s\n' "panel.${base}"
    printf '%s\n' "mt.${base}"
}


prompt_domain_roles_if_needed() {
    if ! is_interactive_terminal; then
        return 0
    fi

    local seed="" suggested_app_domain="" suggested_panel_domain="" suggested_mt_domain=""
    local bundle=""

    if [[ -n "${PUBLIC_DOMAIN}" && -z "${APP_DOMAIN}" ]]; then
        APP_DOMAIN="${PUBLIC_DOMAIN}"
    fi

    seed="${APP_DOMAIN:-${PANEL_DOMAIN:-${MT_DOMAIN:-${PUBLIC_DOMAIN}}}}"
    seed="$(trim_dot_domain "${seed}")"
    if [[ -z "${seed}" ]]; then
        return 0
    fi

    bundle="$(derive_domain_bundle_defaults "${seed}")"
    suggested_app_domain="$(printf '%s' "${bundle}" | sed -n '1p')"
    suggested_panel_domain="$(printf '%s' "${bundle}" | sed -n '2p')"
    suggested_mt_domain="$(printf '%s' "${bundle}" | sed -n '3p')"

    echo ""
    info "Suggested domain role bundle"
    if is_xray_core_backend; then
        echo "  APP_DOMAIN = ${suggested_app_domain}"
        echo "  MT_DOMAIN  = ${suggested_mt_domain}"
    else
        echo "  APP_DOMAIN   = ${suggested_app_domain}"
        echo "  PANEL_DOMAIN = ${suggested_panel_domain}"
        echo "  MT_DOMAIN    = ${suggested_mt_domain}"
    fi

    if prompt_yes_no "Use this suggested domain role bundle?" "y"; then
        APP_DOMAIN="${suggested_app_domain}"
        if is_xray_core_backend; then
            PANEL_DOMAIN=""
        else
            PANEL_DOMAIN="${suggested_panel_domain}"
        fi
        MT_DOMAIN="${suggested_mt_domain}"
    else
        APP_DOMAIN="$(trim_dot_domain "$(prompt_plain_value "App/public domain" "${APP_DOMAIN:-${suggested_app_domain}}")")"
        if is_xray_core_backend; then
            PANEL_DOMAIN=""
        else
            PANEL_DOMAIN="$(trim_dot_domain "$(prompt_plain_value "Panel domain" "${PANEL_DOMAIN:-${suggested_panel_domain}}")")"
        fi
        MT_DOMAIN="$(trim_dot_domain "$(prompt_plain_value "MTProxy domain" "${MT_DOMAIN:-${suggested_mt_domain}}")")"
    fi

    PUBLIC_DOMAIN="${APP_DOMAIN}"

    echo ""
    info "Installer domain roles"
    echo "  App/public domain: ${APP_DOMAIN:-<unset>}"
    if is_3xui_backend; then
        echo "  Panel domain: ${PANEL_DOMAIN:-<unset>}"
    fi
    echo "  MTProxy domain: ${MT_DOMAIN:-<unset>}"
}


sync_domain_aliases() {
    APP_DOMAIN="$(trim_dot_domain "${APP_DOMAIN}")"
    PUBLIC_DOMAIN="$(trim_dot_domain "${PUBLIC_DOMAIN}")"
    PANEL_DOMAIN="$(trim_dot_domain "${PANEL_DOMAIN}")"
    MT_DOMAIN="$(trim_dot_domain "${MT_DOMAIN}")"
    SHARED_HTTP_DOMAIN="$(trim_dot_domain "${SHARED_HTTP_DOMAIN}")"

    if [[ -n "${APP_DOMAIN}" && -n "${PUBLIC_DOMAIN}" && "${APP_DOMAIN}" != "${PUBLIC_DOMAIN}" ]]; then
        warn "APP_DOMAIN and PUBLIC_DOMAIN differ; using APP_DOMAIN as the effective public domain"
    fi
    if [[ -n "${APP_DOMAIN}" ]]; then
        PUBLIC_DOMAIN="${APP_DOMAIN}"
    fi
    if [[ -z "${APP_DOMAIN}" && -n "${PUBLIC_DOMAIN}" ]]; then
        APP_DOMAIN="${PUBLIC_DOMAIN}"
    fi
}


validate_configured_public_hosts() {
    local primary_ip=""
    local host=""
    local validated=()

    primary_ip="$(get_primary_ipv4)"
    if [[ -z "${primary_ip}" ]]; then
        err "Could not detect the primary IPv4 address to validate configured public hosts."
        exit 1
    fi

    for host in "${PANEL_DOMAIN}" "${SHARED_HTTP_DOMAIN}" "${APP_DOMAIN}" "${PUBLIC_DOMAIN}"; do
        host="$(trim_dot_domain "${host}")"
        if [[ -z "${host}" ]]; then
            continue
        fi

        if [[ " ${validated[*]} " == *" ${host} "* ]]; then
            continue
        fi
        validated+=("${host}")

        info "Checking that ${host} points to this server (${primary_ip})..."
        if ! wait_for_host_resolution_to_ipv4 "${host}" "${primary_ip}" "configured public host"; then
            err "Refusing to continue: ${host} does not belong to this server."
            err "Fix the A record so ${host} resolves to ${primary_ip}, or use the correct domain for this host."
            exit 1
        fi
        log "Verified public host ${host} -> ${primary_ip}"
    done
}


configure_dynv6_domain() {
    if [[ -z "${DDNS_ZONE}" && -z "${DDNS_TOKEN}" && -z "${DDNS_PROVIDER}" ]]; then
        return 0
    fi

    if [[ -z "${DDNS_PROVIDER}" ]]; then
        DDNS_PROVIDER="dynv6"
    fi
    normalize_dynv6_credentials
    if [[ "${DDNS_PROVIDER}" != "dynv6" ]]; then
        err "Unsupported DDNS_PROVIDER=${DDNS_PROVIDER}. Currently install_vray.sh supports only dynv6."
        exit 1
    fi
    if [[ -z "${DDNS_ZONE}" || -z "${DDNS_TOKEN}" ]]; then
        err "For Dynv6 automation set both DDNS_ZONE and DDNS_TOKEN (or provide DDNS_INSTRUCTIONS_TEXT with the full Dynv6 Instructions block)."
        exit 1
    fi

    DDNS_ZONE="$(trim_dot_domain "${DDNS_ZONE}")"
    if [[ -z "${DDNS_HOST_LABEL}" ]]; then
        DDNS_HOST_LABEL="$(get_default_ddns_host_label)"
    else
        DDNS_HOST_LABEL="$(slugify_host_label "${DDNS_HOST_LABEL}")"
    fi
    PUBLIC_DOMAIN="$(trim_dot_domain "${PUBLIC_DOMAIN}")"

    if [[ -z "${PUBLIC_DOMAIN}" ]]; then
        if [[ -n "${DDNS_HOST_LABEL}" && "${DDNS_HOST_LABEL}" != "@" ]]; then
            PUBLIC_DOMAIN="${DDNS_HOST_LABEL}.${DDNS_ZONE}"
        else
            PUBLIC_DOMAIN="${DDNS_ZONE}"
        fi
    fi

    if [[ "${PUBLIC_DOMAIN}" != "${DDNS_ZONE}" && "${PUBLIC_DOMAIN}" != *".${DDNS_ZONE}" ]]; then
        err "PUBLIC_DOMAIN=${PUBLIC_DOMAIN} must be either ${DDNS_ZONE} itself or one of its subdomains."
        exit 1
    fi

    local primary_ip zone_json zone_id records_json record_id rest_status_file rest_status
    primary_ip="$(get_primary_ipv4)"
    if [[ -z "${primary_ip}" ]]; then
        err "Could not detect the primary IPv4 address for Dynv6 DNS update."
        exit 1
    fi

    info "Dynv6: ensuring zone ${DDNS_ZONE} and A record ${PUBLIC_DOMAIN} -> ${primary_ip}"
    rest_status_file="$(mktemp)"
    zone_json="$(dynv6_rest_api_request GET "https://dynv6.com/api/v2/zones/by-name/${DDNS_ZONE}" "" "${rest_status_file}" || true)"
    rest_status="$(cat "${rest_status_file}" 2>/dev/null || true)"
    rm -f "${rest_status_file}"
    if [[ "${rest_status}" == "401" || "${rest_status}" == "403" ]]; then
        dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status}"
        return 0
    fi
    if [[ -z "${rest_status}" || ! "${rest_status}" =~ ^2[0-9][0-9]$ && "${rest_status}" != "404" ]]; then
        dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status:-unknown}"
        return 0
    fi
    zone_id="$(printf '%s' "${zone_json}" | jq -r '.id // empty' 2>/dev/null || true)"
    if [[ -z "${zone_id}" ]]; then
        rest_status_file="$(mktemp)"
        zone_json="$(dynv6_rest_api_request POST "https://dynv6.com/api/v2/zones" "{\"name\":\"${DDNS_ZONE}\",\"ipv4address\":\"${primary_ip}\"}" "${rest_status_file}" || true)"
        rest_status="$(cat "${rest_status_file}" 2>/dev/null || true)"
        rm -f "${rest_status_file}"
        if [[ "${rest_status}" == "401" || "${rest_status}" == "403" || -z "${rest_status}" || ! "${rest_status}" =~ ^2[0-9][0-9]$ ]]; then
            dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status:-unknown} on zone create"
            return 0
        fi
        zone_id="$(printf '%s' "${zone_json}" | jq -r '.id // empty')"
    else
        rest_status_file="$(mktemp)"
        dynv6_rest_api_request PATCH "https://dynv6.com/api/v2/zones/${zone_id}" "{\"ipv4address\":\"${primary_ip}\"}" "${rest_status_file}" >/dev/null || true
        rest_status="$(cat "${rest_status_file}" 2>/dev/null || true)"
        rm -f "${rest_status_file}"
        if [[ "${rest_status}" == "401" || "${rest_status}" == "403" || -z "${rest_status}" || ! "${rest_status}" =~ ^2[0-9][0-9]$ ]]; then
            dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status:-unknown} on zone patch"
            return 0
        fi
    fi

    if [[ -z "${zone_id}" ]]; then
        err "Dynv6 zone ${DDNS_ZONE} was not created or returned no id."
        exit 1
    fi

    if [[ "${PUBLIC_DOMAIN}" != "${DDNS_ZONE}" ]]; then
        rest_status_file="$(mktemp)"
        records_json="$(dynv6_rest_api_request GET "https://dynv6.com/api/v2/zones/${zone_id}/records" "" "${rest_status_file}" || true)"
        rest_status="$(cat "${rest_status_file}" 2>/dev/null || true)"
        rm -f "${rest_status_file}"
        if [[ "${rest_status}" == "401" || "${rest_status}" == "403" || -z "${rest_status}" || ! "${rest_status}" =~ ^2[0-9][0-9]$ ]]; then
            dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status:-unknown} on records list"
            return 0
        fi
        record_id="$(printf '%s' "${records_json}" | jq -r --arg name "${PUBLIC_DOMAIN}" '.[] | select(.type == "A" and .name == $name) | .id' | head -n1)"
        if [[ -n "${record_id}" ]]; then
            rest_status_file="$(mktemp)"
            dynv6_rest_api_request PATCH "https://dynv6.com/api/v2/zones/${zone_id}/records/${record_id}" \
                "{\"name\":\"${PUBLIC_DOMAIN}\",\"type\":\"A\",\"data\":\"${primary_ip}\"}" "${rest_status_file}" >/dev/null || true
            rest_status="$(cat "${rest_status_file}" 2>/dev/null || true)"
            rm -f "${rest_status_file}"
            if [[ "${rest_status}" == "401" || "${rest_status}" == "403" || -z "${rest_status}" || ! "${rest_status}" =~ ^2[0-9][0-9]$ ]]; then
                dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status:-unknown} on record patch"
                return 0
            fi
        else
            rest_status_file="$(mktemp)"
            dynv6_rest_api_request POST "https://dynv6.com/api/v2/zones/${zone_id}/records" \
                "{\"name\":\"${PUBLIC_DOMAIN}\",\"type\":\"A\",\"data\":\"${primary_ip}\"}" "${rest_status_file}" >/dev/null || true
            rest_status="$(cat "${rest_status_file}" 2>/dev/null || true)"
            rm -f "${rest_status_file}"
            if [[ "${rest_status}" == "401" || "${rest_status}" == "403" || -z "${rest_status}" || ! "${rest_status}" =~ ^2[0-9][0-9]$ ]]; then
                dynv6_try_update_api_fallback "${PUBLIC_DOMAIN}" "${primary_ip}" "HTTP ${rest_status:-unknown} on record create"
                return 0
            fi
        fi
    fi

    wait_for_public_domain_resolution "${PUBLIC_DOMAIN}" "${primary_ip}"
    log "Dynv6 domain ready: ${PUBLIC_DOMAIN} -> ${primary_ip}"
}


apt_dns_works() {
    timeout 5 getent hosts deb.debian.org >/dev/null 2>&1 \
        && timeout 5 getent hosts security.debian.org >/dev/null 2>&1
}


apt_dns_tcp_works() {
    python3 - <<'PY'
import socket
import struct
import sys

query = bytes.fromhex("123401000001000000000000036465620664656269616e036f72670000010001")
packet = struct.pack("!H", len(query)) + query

for upstream in (("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53)):
    try:
        with socket.create_connection(upstream, timeout=4.0) as sock:
            sock.sendall(packet)
            hdr = sock.recv(2)
            if len(hdr) != 2:
                continue
            total = struct.unpack("!H", hdr)[0]
            data = b""
            while len(data) < total:
                chunk = sock.recv(total - len(data))
                if not chunk:
                    break
                data += chunk
            if data:
                sys.exit(0)
    except Exception:
        continue
sys.exit(1)
PY
}


force_tcp_dns_for_apt() {
    if grep -q '^options .*use-vc' /etc/resolv.conf 2>/dev/null; then
        return 0
    fi
    cp /etc/resolv.conf "/etc/resolv.conf.install_vray.bak.$(date +%s)" 2>/dev/null || true
    python3 - <<'PY'
from pathlib import Path

p = Path("/etc/resolv.conf")
text = p.read_text(encoding="utf-8")
if "options use-vc" not in text:
    if not text.endswith("\n"):
        text += "\n"
    text += "options use-vc timeout:2 attempts:2\n"
    p.write_text(text, encoding="utf-8")
PY
    warn "Enabled TCP DNS fallback in /etc/resolv.conf for apt operations"
}


apt_http_mirrors_reachable() {
    timeout 10 curl -I -4 --max-time 8 http://deb.debian.org/debian/ >/dev/null 2>&1 \
        && timeout 10 curl -I -4 --max-time 8 http://security.debian.org/ >/dev/null 2>&1
}


prepare_apt_networking() {
    if apt_dns_works; then
        return 0
    fi

    warn "Standard DNS resolution failed for Debian mirrors. Checking if TCP DNS fallback is possible..."
    if apt_dns_tcp_works; then
        force_tcp_dns_for_apt
        if apt_dns_works; then
            log "DNS resolution restored via TCP DNS fallback"
        else
            err "TCP DNS fallback was enabled but Debian mirror hostnames still do not resolve"
            return 1
        fi
    else
        err "Debian mirror hostnames do not resolve, and TCP DNS fallback is also unavailable"
        return 1
    fi

    if ! apt_http_mirrors_reachable; then
        err "Debian HTTP mirrors are unreachable from this host."
        err "Check provider egress filtering or mirror reachability before retrying install_vray.sh."
        return 1
    fi
}


ensure_nginx_runtime_limits() {
    mkdir -p /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/limits.conf <<'EOF'
[Service]
LimitNOFILE=1048576
Restart=on-failure
RestartSec=2s
OOMPolicy=continue
EOF

    python3 - <<'PY'
from pathlib import Path
import re

path = Path('/etc/nginx/nginx.conf')
if not path.exists():
    raise SystemExit(0)

text = path.read_text(encoding='utf-8')
original = text

if 'worker_rlimit_nofile' not in text:
    text = text.replace('worker_processes auto;\n', 'worker_processes auto;\nworker_rlimit_nofile 1048576;\n', 1)
else:
    text = re.sub(r'(^\s*worker_rlimit_nofile\s+)(\d+)(;)', lambda m: f"{m.group(1)}{max(int(m.group(2)), 1048576)}{m.group(3)}", text, flags=re.MULTILINE)

match = re.search(r'(^\s*worker_connections\s+)(\d+)(;)', text, re.MULTILINE)
if match:
    current = int(match.group(2))
    if current < 65535:
        text = text[:match.start()] + f"{match.group(1)}65535{match.group(3)}" + text[match.end():]

if text != original:
    path.write_text(text, encoding='utf-8')
PY

    systemctl daemon-reload
}


install_dependencies() {
    prepare_apt_networking || exit 1
    apt-get update -qq
    if is_xray_core_backend; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            curl ca-certificates openssl tar nginx libnginx-mod-stream certbot python3 python3-certbot-nginx iptables jq
        ensure_nginx_runtime_limits
        log "Base packages installed for standalone Xray-core mode with nginx shared-port support"
        return 0
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl ca-certificates openssl tar nginx libnginx-mod-stream certbot python3 python3-certbot-nginx iptables jq sqlite3
    ensure_nginx_runtime_limits
    log "Base packages installed for 3x-ui mode"
}


configure_vpnbot_network_limits() {
    local raw_target target current effective tmp written

    if [[ ! -e /proc/sys/net/netfilter/nf_conntrack_max ]] && command -v modprobe >/dev/null 2>&1; then
        if modprobe nf_conntrack >/dev/null 2>&1; then
            info "Loaded nf_conntrack module for conntrack sysctl"
        else
            info "nf_conntrack module could not be loaded; conntrack sysctl may be unavailable"
        fi
    fi

    if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        mkdir -p /etc/modules-load.d
        printf '%s\n' "nf_conntrack" > /etc/modules-load.d/vpnbot-conntrack.conf
    fi

    raw_target="${VPNBOT_NF_CONNTRACK_MAX:-1048576}"
    if [[ ! "${raw_target}" =~ ^[0-9]+$ ]]; then
        warn "Invalid VPNBOT_NF_CONNTRACK_MAX=${raw_target}; using 1048576"
        raw_target="1048576"
    fi

    target="${raw_target}"
    if (( target < 262144 )); then
        target=262144
    fi

    effective="${target}"
    if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        current="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || printf '0')"
        if [[ "${current}" =~ ^[0-9]+$ ]] && (( current > effective )); then
            effective="${current}"
        fi
    fi

    mkdir -p "$(dirname "${VPNBOT_NETWORK_SYSCTL_FILE}")"
    tmp="$(mktemp)"
    written=0
    cat > "${tmp}" <<EOF
# VPnBot VPN nodes can keep many simultaneous client flows.
# Keep conntrack headroom so user traffic cannot starve SSH/control-plane access.
EOF

    append_vpnbot_sysctl_setting() {
        local target_file="$1"
        local key="$2"
        local value="$3"
        local proc_path="/proc/sys/${key//./\/}"
        if [[ ! -e "${proc_path}" ]]; then
            info "sysctl ${key} is not available on this kernel; skipping"
            return 1
        fi
        printf '%s = %s\n' "${key}" "${value}" >> "${target_file}"
        return 0
    }

    append_vpnbot_sysctl_setting "${tmp}" "fs.file-max" "2097152" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.core.somaxconn" "65535" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.core.netdev_max_backlog" "250000" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.tcp_max_syn_backlog" "65535" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.ip_local_port_range" "1024 65535" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.tcp_fin_timeout" "15" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.tcp_tw_reuse" "1" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.tcp_keepalive_time" "600" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.tcp_keepalive_intvl" "60" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.ipv4.tcp_keepalive_probes" "5" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_max" "${effective}" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_established" "86400" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_close" "10" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_close_wait" "60" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_fin_wait" "120" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_time_wait" "120" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_last_ack" "30" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_syn_sent" "120" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_syn_recv" "60" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_tcp_timeout_unacknowledged" "300" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_udp_timeout" "30" && written=$((written + 1))
    append_vpnbot_sysctl_setting "${tmp}" "net.netfilter.nf_conntrack_udp_timeout_stream" "180" && written=$((written + 1))

    if (( written == 0 )); then
        info "No supported VPnBot network sysctl settings were found on this kernel; skipping"
        rm -f "${tmp}"
        return 0
    fi

    install -m 644 "${tmp}" "${VPNBOT_NETWORK_SYSCTL_FILE}"
    rm -f "${tmp}"
    chmod 644 "${VPNBOT_NETWORK_SYSCTL_FILE}" 2>/dev/null || true

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -n "${line}" && "${line}" != \#* ]] || continue
        key="${line%%=*}"
        value="${line#*=}"
        key="${key//[[:space:]]/}"
        value="$(printf '%s' "${value}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -n "${key}" ]] || continue
        if ! sysctl -w "${key}=${value}" >/dev/null 2>&1; then
            warn "Could not apply ${key}=${value} immediately; persisted ${VPNBOT_NETWORK_SYSCTL_FILE}"
        fi
    done < "${VPNBOT_NETWORK_SYSCTL_FILE}"

    log "Applied VPnBot network sysctl profile (${written} settings, conntrack target=${effective})"
}


normalize_inputs() {
    normalize_vless_backend_mode
    normalize_vpnbot_server_id
    sync_domain_aliases

    if is_3xui_backend; then
        if [[ -z "${XUI_PANEL_USERNAME}" ]]; then
            XUI_PANEL_USERNAME="admin_$(gen_random_string 6)"
        fi
        if [[ -z "${XUI_PANEL_PASSWORD}" ]]; then
            XUI_PANEL_PASSWORD="$(gen_random_string 16)"
        fi
        if [[ -z "${XUI_PANEL_WEBBASEPATH}" ]]; then
            XUI_PANEL_WEBBASEPATH="$(gen_random_string 18)"
        fi
        XUI_PANEL_WEBBASEPATH="${XUI_PANEL_WEBBASEPATH#/}"
        XUI_PANEL_WEBBASEPATH="${XUI_PANEL_WEBBASEPATH%/}"

        if [[ -z "${NGINX_PANEL_LOCATION}" ]]; then
            NGINX_PANEL_LOCATION="/${XUI_PANEL_WEBBASEPATH}/"
        fi
    fi

    if [[ -z "${SHARED_HTTP_DOMAIN}" && -n "${APP_DOMAIN}" ]]; then
        SHARED_HTTP_DOMAIN="${APP_DOMAIN}"
    fi

    if is_3xui_backend && [[ -z "${PANEL_DOMAIN}" ]]; then
        if [[ -n "${SHARED_HTTP_DOMAIN}" ]]; then
            PANEL_DOMAIN="${SHARED_HTTP_DOMAIN}"
        elif [[ -n "${APP_DOMAIN}" ]]; then
            PANEL_DOMAIN="${APP_DOMAIN}"
        fi
    fi

    local nginx_server_names=()
    local candidate=""
    for candidate in "${PANEL_DOMAIN}" "${SHARED_HTTP_DOMAIN}" "${APP_DOMAIN}"; do
        candidate="$(trim_dot_domain "${candidate}")"
        if [[ -z "${candidate}" ]]; then
            continue
        fi
        if [[ " ${nginx_server_names[*]} " == *" ${candidate} "* ]]; then
            continue
        fi
        nginx_server_names+=("${candidate}")
    done

    if [[ -z "${NGINX_SERVER_NAME}" ]]; then
        if [[ "${#nginx_server_names[@]}" -gt 0 ]]; then
            NGINX_SERVER_NAME="${nginx_server_names[*]}"
        else
            NGINX_SERVER_NAME="_"
        fi
    fi
}


fetch_upstream_installer() {
    local upstream_url="${XUI_UPSTREAM_INSTALL_URL}"
    local cache_bust="${VPNBOT_NODE_INSTALLER_CACHE_BUST:-$(date +%s)}"
    if [[ "${upstream_url}" == *"raw.githubusercontent.com"* ]]; then
        if [[ "${upstream_url}" == *"?"* ]]; then
            upstream_url="${upstream_url}&ts=${cache_bust}"
        else
            upstream_url="${upstream_url}?ts=${cache_bust}"
        fi
    fi
    curl -L --max-time 30 -H "Cache-Control: no-cache" "${upstream_url}" -o "${XUI_UPSTREAM_TMP}"
    python3 - <<'PY'
from pathlib import Path

src = Path("/tmp/install_3xui_upstream.sh").read_text(encoding="utf-8")
marker = '\necho -e "${green}Running...${plain}"\ninstall_base\ninstall_x-ui $1\n'
if marker not in src:
    raise SystemExit("Failed to strip autorun section from upstream 3x-ui installer")
Path("/tmp/install_3xui_upstream_sourced.sh").write_text(src.replace(marker, "\n", 1), encoding="utf-8")
PY
    log "Fetched upstream 3x-ui installer"
}


install_3xui_noninteractive() {
    fetch_upstream_installer
    # shellcheck disable=SC1090
    source "${XUI_SOURCED_TMP}"

    config_after_install() {
        "${xui_folder}/x-ui" setting \
            -username "${XUI_PANEL_USERNAME}" \
            -password "${XUI_PANEL_PASSWORD}" \
            -port "${XUI_PANEL_PORT}" \
            -webBasePath "${XUI_PANEL_WEBBASEPATH}" >/dev/null 2>&1
        "${xui_folder}/x-ui" migrate >/dev/null 2>&1 || true
        log "3x-ui panel configured non-interactively"
        info "Panel backend port: ${XUI_PANEL_PORT}"
        info "Panel webBasePath: ${XUI_PANEL_WEBBASEPATH}"
    }

    prompt_and_setup_ssl() {
        warn "Skipping upstream panel SSL setup: VPnBot nginx/stream layer handles TCP/443"
        return 0
    }

    install_base
    if [[ -n "${XUI_VERSION:-}" ]]; then
        install_x-ui "${XUI_VERSION}"
    else
        install_x-ui
    fi
}


get_effective_public_endpoint_host() {
    local host=""
    host="$(trim_dot_domain "${APP_DOMAIN:-${PUBLIC_DOMAIN:-}}")"
    if [[ -z "${host}" ]]; then
        host="$(get_primary_ipv4)"
    fi
    printf '%s' "${host}"
}


choose_available_tcp_port() {
    local preferred="${1:-0}"
    PREFERRED_TCP_PORT="${preferred}" python3 - <<'PY'
import os
import random
import socket
import sys

preferred_raw = os.environ.get("PREFERRED_TCP_PORT", "").strip()
try:
    preferred = int(preferred_raw) if preferred_raw else 0
except ValueError:
    preferred = 0


def is_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", int(port)))
    except OSError:
        sock.close()
        return False
    sock.close()
    return True


for candidate in [preferred, 8443]:
    if candidate > 0 and is_free(candidate):
        print(candidate)
        sys.exit(0)

for _ in range(2000):
    port = random.randint(20000, 45000)
    if is_free(port):
        print(port)
        sys.exit(0)

raise SystemExit("Could not find a free TCP port for standalone Xray-core smoke inbound")
PY
}


get_xray_core_archive_name() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)
            printf 'Xray-linux-64.zip'
            ;;
        aarch64|arm64)
            printf 'Xray-linux-arm64-v8a.zip'
            ;;
        armv7l|armv7*)
            printf 'Xray-linux-arm32-v7a.zip'
            ;;
        *)
            err "Unsupported CPU architecture for standalone Xray-core mode: ${arch}"
            exit 1
            ;;
    esac
}


resolve_xray_core_release_asset() {
    local archive_name="$1"
    XRAY_CORE_RELEASES_API_URL_VALUE="${XRAY_CORE_RELEASES_API_URL}" \
    XRAY_CORE_RELEASE_CHANNEL_VALUE="${XRAY_CORE_RELEASE_CHANNEL}" \
    XRAY_CORE_VERSION_VALUE="${XRAY_CORE_VERSION}" \
    XRAY_CORE_ARCHIVE_NAME_VALUE="${archive_name}" \
    python3 - <<'PY'
import json
import os
import sys
import urllib.parse
import urllib.request


def request_json(url: str):
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "vpnbot-install-vray",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


base = str(os.environ["XRAY_CORE_RELEASES_API_URL_VALUE"]).rstrip("/")
channel = str(os.environ["XRAY_CORE_RELEASE_CHANNEL_VALUE"]).strip().lower() or "stable"
version = str(os.environ["XRAY_CORE_VERSION_VALUE"]).strip() or "latest"
archive_name = str(os.environ["XRAY_CORE_ARCHIVE_NAME_VALUE"]).strip()

if version != "latest":
    release = request_json(f"{base}/tags/{urllib.parse.quote(version, safe='')}")
else:
    releases = request_json(f"{base}?per_page=20")
    if not isinstance(releases, list):
        raise SystemExit("GitHub releases API did not return a list")
    release = None
    for item in releases:
        if not isinstance(item, dict):
            continue
        if channel == "stable" and item.get("prerelease"):
            continue
        release = item
        break
    if release is None and releases:
        release = next((item for item in releases if isinstance(item, dict)), None)

if not isinstance(release, dict):
    raise SystemExit("Could not resolve a suitable Xray-core release")

for asset in release.get("assets") or []:
    if not isinstance(asset, dict):
        continue
    if str(asset.get("name") or "") != archive_name:
        continue
    print(str(asset.get("browser_download_url") or "").strip())
    print(str(release.get("tag_name") or "").strip())
    sys.exit(0)

raise SystemExit(f"Asset {archive_name} was not found in release {release.get('tag_name')}")
PY
}


write_xray_core_base_configs() {
    mkdir -p "${XRAY_CORE_ROOT}/bin" "${XRAY_CORE_CONFIG_DIR}" "${XRAY_CORE_SHARE_DIR}" "${XRAY_CORE_LOG_DIR}"
    touch "${XRAY_CORE_LOG_DIR}/access.log" "${XRAY_CORE_LOG_DIR}/error.log"
    chmod 755 "${XRAY_CORE_ROOT}" "${XRAY_CORE_ROOT}/bin" "${XRAY_CORE_CONFIG_DIR}" "${XRAY_CORE_SHARE_DIR}" "${XRAY_CORE_LOG_DIR}"
    chmod 600 "${XRAY_CORE_LOG_DIR}/access.log" "${XRAY_CORE_LOG_DIR}/error.log" 2>/dev/null || true

    # Keep minimal access/error logs enabled. The online and abuse trackers depend
    # on access.log, so rerunning the installer repairs older disabled log files.
    cat > "${XRAY_CORE_CONFIG_DIR}/00_log.json" <<EOF
{
  "log": {
    "access": "${XRAY_CORE_LOG_DIR}/access.log",
    "error": "${XRAY_CORE_LOG_DIR}/error.log",
    "loglevel": "${XUI_XRAY_LOGLEVEL}",
    "dnsLog": false
  }
}
EOF

    if [[ ! -f "${XRAY_CORE_CONFIG_DIR}/10_routing.json" ]]; then
        cat > "${XRAY_CORE_CONFIG_DIR}/10_routing.json" <<'EOF'
{
  "routing": {
    "domainStrategy": "AsIs",
    "rules": []
  }
}
EOF
    fi

    if [[ ! -f "${XRAY_CORE_CONFIG_DIR}/20_outbounds.json" ]]; then
        cat > "${XRAY_CORE_CONFIG_DIR}/20_outbounds.json" <<'EOF'
{
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ]
}
EOF
    fi

    # Xray v26 expects the local API listen address as one host:port value.
    # Rewriting this file also repairs older installs that had listen+port split.
    cat > "${XRAY_CORE_CONFIG_DIR}/30_api.json" <<EOF
{
  "api": {
    "tag": "api",
    "listen": "${XRAY_CORE_API_SERVER}",
    "services": [
      "HandlerService",
      "StatsService"
    ]
  },
  "stats": {}
}
EOF

    if [[ ! -f "${XRAY_CORE_CONFIG_DIR}/40_policy.json" ]]; then
        cat > "${XRAY_CORE_CONFIG_DIR}/40_policy.json" <<'EOF'
{
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "statsUserOnline": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  }
}
EOF
    fi
}


write_xray_logrotate_config() {
    mkdir -p "$(dirname "${XRAY_LOGROTATE_FILE}")"
    cat > "${XRAY_LOGROTATE_FILE}" <<EOF
${XRAY_CORE_LOG_DIR}/*.log ${XUI_XRAY_LOG_DIR}/*.log {
    daily
    rotate ${XRAY_LOGROTATE_DAYS}
    maxsize ${XRAY_LOGROTATE_MAXSIZE}
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
}
EOF
    chmod 644 "${XRAY_LOGROTATE_FILE}" 2>/dev/null || true
    log "Installed Xray logrotate policy: ${XRAY_LOGROTATE_FILE}"
}


write_xray_core_smoke_inbound_if_missing() {
    local public_host smoke_domain smoke_port smoke_uuid short_id key_output private_key public_key

    XRAY_CORE_PUBLIC_ENDPOINT="$(get_effective_public_endpoint_host)"

    if [[ -f "${XRAY_CORE_MANAGED_INBOUNDS_FILE}" ]]; then
        info "Standalone Xray managed inbounds file already exists, leaving it unchanged: ${XRAY_CORE_MANAGED_INBOUNDS_FILE}"
        return 0
    fi

    if ! env_is_true "${XRAY_CORE_SMOKE_ENABLE}"; then
        cat > "${XRAY_CORE_MANAGED_INBOUNDS_FILE}" <<'EOF'
{
  "inbounds": []
}
EOF
        log "Created empty managed inbounds file for standalone Xray-core"
        return 0
    fi

    public_host="${XRAY_CORE_PUBLIC_ENDPOINT}"
    smoke_domain="$(trim_dot_domain "${XRAY_CORE_SMOKE_DOMAIN}")"
    if [[ -z "${smoke_domain}" ]]; then
        smoke_domain="www.cloudflare.com"
    fi
    smoke_port="$(choose_available_tcp_port "${XRAY_CORE_SMOKE_PORT}")"
    smoke_uuid="${XRAY_CORE_SMOKE_UUID:-}"
    if [[ -z "${smoke_uuid}" ]]; then
        smoke_uuid="$("${XRAY_CORE_BIN}" uuid 2>/dev/null | tr -d '\r\n' || true)"
    fi
    if [[ -z "${smoke_uuid}" ]]; then
        smoke_uuid="$(python3 - <<'PY'
import uuid

print(uuid.uuid4())
PY
)"
    fi
    key_output="$("${XRAY_CORE_BIN}" x25519 2>&1 || true)"
    parsed_keys="$(XRAY_X25519_OUTPUT="${key_output}" python3 - <<'PY'
import os

text = os.environ.get("XRAY_X25519_OUTPUT", "")
private_key = ""
public_key = ""
for raw in text.splitlines():
    line = raw.strip()
    compact = line.lower().replace(" ", "").replace("_", "")
    value = line.split(":", 1)[1].strip() if ":" in line else ""
    if not value:
        parts = line.split()
        value = parts[-1].strip() if parts else ""
    if not private_key and "privatekey" in compact:
        private_key = value
    if not public_key and "publickey" in compact:
        public_key = value
print(private_key)
print(public_key)
PY
)"
    private_key="$(printf '%s\n' "${parsed_keys}" | sed -n '1p')"
    public_key="$(printf '%s\n' "${parsed_keys}" | sed -n '2p')"
    short_id="$(openssl rand -hex 8)"

    if [[ -z "${smoke_uuid}" || -z "${private_key}" || -z "${public_key}" || -z "${short_id}" ]]; then
        err "Failed to generate standalone Xray-core smoke-test credentials"
        err "xray binary: ${XRAY_CORE_BIN}"
        err "xray x25519 output:"
        printf '%s\n' "${key_output}" >&2
        exit 1
    fi

    XRAY_CORE_SMOKE_PORT_EFFECTIVE="${smoke_port}"
    XRAY_CORE_SMOKE_UUID="${smoke_uuid}"
    XRAY_CORE_SMOKE_PUBLIC_KEY="${public_key}"
    XRAY_CORE_SMOKE_SHORT_ID="${short_id}"
    XRAY_CORE_SMOKE_LINK="vless://${smoke_uuid}@${public_host}:${smoke_port}?type=tcp&security=reality&pbk=${public_key}&fp=chrome&sni=${smoke_domain}&sid=${short_id}&encryption=none#vpnbot-smoke"

    SMOKE_UUID_VALUE="${smoke_uuid}" \
    SMOKE_PORT_VALUE="${smoke_port}" \
    SMOKE_DOMAIN_VALUE="${smoke_domain}" \
    SMOKE_PRIVATE_KEY_VALUE="${private_key}" \
    SMOKE_SHORT_ID_VALUE="${short_id}" \
    MANAGED_INBOUNDS_FILE_VALUE="${XRAY_CORE_MANAGED_INBOUNDS_FILE}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "inbounds": [
        {
            "tag": "vpnbot-smoke-vless-reality-direct",
            "listen": "0.0.0.0",
            "port": int(os.environ["SMOKE_PORT_VALUE"]),
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": os.environ["SMOKE_UUID_VALUE"],
                        "email": "vpnbot-smoke"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "xver": 0,
                    "dest": f"{os.environ['SMOKE_DOMAIN_VALUE']}:443",
                    "serverNames": [os.environ["SMOKE_DOMAIN_VALUE"]],
                    "privateKey": os.environ["SMOKE_PRIVATE_KEY_VALUE"],
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [os.environ["SMOKE_SHORT_ID_VALUE"]]
                },
                "tcpSettings": {
                    "acceptProxyProtocol": False,
                    "header": {
                        "type": "none"
                    }
                }
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "metadataOnly": False
            }
        }
    ]
}

Path(os.environ["MANAGED_INBOUNDS_FILE_VALUE"]).write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
    log "Created standalone Xray-core smoke inbound on TCP port ${smoke_port}"
}


write_xray_core_service_unit() {
    cat > "${XRAY_CORE_SERVICE_FILE}" <<EOF
[Unit]
Description=VPnBot standalone Xray-core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${XRAY_CORE_ROOT}
Environment=XRAY_LOCATION_ASSET=${XRAY_CORE_SHARE_DIR}
Environment=XRAY_LOCATION_CONFDIR=${XRAY_CORE_CONFIG_DIR}
ExecStartPre=${XRAY_RESERVED_PORTS_SCRIPT}
ExecStart=${XRAY_CORE_BIN} run -confdir ${XRAY_CORE_CONFIG_DIR}
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}


write_xray_reserved_ports_helper() {
    cat > "${XRAY_RESERVED_PORTS_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

managed_file=${XRAY_CORE_MANAGED_INBOUNDS_FILE@Q}
sysctl_file=${VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE@Q}

ports="\$(python3 - "\${managed_file}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
rows = payload.get("inbounds") if isinstance(payload, dict) else []
ports = set()
if isinstance(rows, list):
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port") or 0)
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
print(",".join(str(port) for port in sorted(ports)))
PY
)"

if [[ -z "\${ports}" ]]; then
    exit 0
fi

mkdir -p "\$(dirname "\${sysctl_file}")"
{
    echo "# VPnBot standalone Xray-core managed inbound ports."
    echo "# These ports must not be reused as ephemeral source ports by nginx, MTProxy, or other local clients."
    echo "net.ipv4.ip_local_reserved_ports=\${ports}"
} > "\${sysctl_file}"

current="\$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
merged="\$(python3 - "\${current}" "\${ports}" <<'PY'
import sys

def parse(raw: str) -> set[int]:
    result = set()
    for chunk in str(raw or "").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            left, _, right = chunk.partition("-")
            try:
                start = int(left)
                end = int(right)
            except Exception:
                continue
            if start > end:
                start, end = end, start
            result.update(range(max(1, start), min(65535, end) + 1))
            continue
        try:
            value = int(chunk)
        except Exception:
            continue
        if 1 <= value <= 65535:
            result.add(value)
    return result

ports = parse(sys.argv[1]) | parse(sys.argv[2])
print(",".join(str(port) for port in sorted(ports)))
PY
)"

sysctl -w "net.ipv4.ip_local_reserved_ports=\${merged}" >/dev/null
EOF
    chmod 755 "${XRAY_RESERVED_PORTS_SCRIPT}"
}


download_node_installer_asset() {
    local asset_path="$1"
    local destination="$2"
    local mode="${3:-644}"
    local local_root="${VPNBOT_NODE_INSTALLER_LOCAL_ROOT:-}"
    local local_file=""
    local base_url="${VPNBOT_NODE_INSTALLER_BASE_URL%/}"
    local url="${base_url}/${asset_path}"
    local cache_bust="${VPNBOT_NODE_INSTALLER_CACHE_BUST:-$(date +%s)}"
    local tmp_file

    if [[ -n "${local_root}" ]]; then
        local_file="${local_root%/}/${asset_path}"
        if [[ -f "${local_file}" ]]; then
            install -m "${mode}" "${local_file}" "${destination}"
            return 0
        fi
    fi

    tmp_file="$(mktemp)"
    curl -fsSL --retry 3 --connect-timeout 10 \
        -H "Cache-Control: no-cache" \
        -o "${tmp_file}" "${url}?ts=${cache_bust}"
    install -m "${mode}" "${tmp_file}" "${destination}"
    rm -f "${tmp_file}"
}


write_xrayctl_assets() {
    download_node_installer_asset "assets/vpnbot_xrayctl.py" "${XRAY_CTL_SCRIPT}" 755
    log "Installed Xray-core local control helper: ${XRAY_CTL_SCRIPT}"
}


normalize_xray_online_tracker_service_unit() {
    if [[ ! -f "${XRAY_ONLINE_TRACKER_SERVICE_FILE}" ]]; then
        return 0
    fi

    if grep -Fq "ExecStart=${XRAY_ONLINE_TRACKER_LEGACY_SCRIPT}" "${XRAY_ONLINE_TRACKER_SERVICE_FILE}"; then
        cp -a "${XRAY_ONLINE_TRACKER_SERVICE_FILE}" "${XRAY_ONLINE_TRACKER_SERVICE_FILE}.bak.$(date +%Y%m%d%H%M%S)" || true
        sed -i "s#^ExecStart=${XRAY_ONLINE_TRACKER_LEGACY_SCRIPT}.*#ExecStart=${XRAY_ONLINE_TRACKER_CANONICAL_SCRIPT}#" "${XRAY_ONLINE_TRACKER_SERVICE_FILE}"
        log "Repaired legacy online tracker ExecStart path in ${XRAY_ONLINE_TRACKER_SERVICE_FILE}"
    fi
}


restart_xray_online_tracker_service_only() {
    systemctl daemon-reload
    systemctl enable "${XRAY_ONLINE_TRACKER_SERVICE_NAME}" >/dev/null
    if systemctl is-active --quiet "${XRAY_ONLINE_TRACKER_SERVICE_NAME}"; then
        systemctl restart "${XRAY_ONLINE_TRACKER_SERVICE_NAME}"
    else
        systemctl start "${XRAY_ONLINE_TRACKER_SERVICE_NAME}"
    fi
}


write_xray_online_tracker_assets() {
    local tracker_state_dir
    tracker_state_dir="/var/lib/vpnbot-xray-online"
    mkdir -p "${tracker_state_dir}"
    chmod 755 "${tracker_state_dir}"

    normalize_xray_online_tracker_service_unit

    download_node_installer_asset "assets/vpnbot_xray_online_tracker.py" "${XRAY_ONLINE_TRACKER_SCRIPT}" 755
    log "Installed Xray-core online tracker helper: ${XRAY_ONLINE_TRACKER_SCRIPT}"

    cat > "${XRAY_ONLINE_TRACKER_SERVICE_FILE}" <<EOF
[Unit]
Description=VPnBot Xray-core online tracker
After=network-online.target ${XRAY_CORE_SERVICE_NAME}
Wants=network-online.target ${XRAY_CORE_SERVICE_NAME}

[Service]
Type=simple
User=root
Environment=XRAY_ONLINE_ACCESS_LOG=${XRAY_CORE_LOG_DIR}/access.log
Environment=XRAY_ONLINE_BIND_HOST=${XRAY_ONLINE_TRACKER_BIND}
Environment=XRAY_ONLINE_BIND_PORT=${XRAY_ONLINE_TRACKER_PORT}
Environment=XRAY_ONLINE_WINDOW_SECONDS=${XRAY_ONLINE_TRACKER_WINDOW_SECONDS}
Environment=XRAY_ONLINE_BOOTSTRAP_BYTES=${XRAY_ONLINE_TRACKER_BOOTSTRAP_BYTES}
Environment=XRAY_ONLINE_STATS_INTERVAL_SECONDS=${XRAY_ONLINE_TRACKER_STATS_INTERVAL_SECONDS}
Environment=XRAY_ONLINE_XRAY_BIN=${XRAY_CORE_BIN}
Environment=XRAY_ONLINE_XRAY_API_SERVER=${XRAY_CORE_API_SERVER}
Environment=XRAY_ABUSE_AUDIT_WINDOW_SECONDS=${XRAY_ABUSE_AUDIT_WINDOW_SECONDS}
Environment=XRAY_ABUSE_AUDIT_MAX_EVENTS=${XRAY_ABUSE_AUDIT_MAX_EVENTS}
Environment=XRAY_ABUSE_AUDIT_TOP_LIMIT=${XRAY_ABUSE_AUDIT_TOP_LIMIT}
Environment=XRAY_ABUSE_MULTI_IP_OBSERVE_IPS=${XRAY_ABUSE_MULTI_IP_OBSERVE_IPS}
Environment=XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS=${XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS}
Environment=XRAY_ABUSE_MULTI_IP_HIGH_IPS=${XRAY_ABUSE_MULTI_IP_HIGH_IPS}
Environment=XRAY_ABUSE_MULTI_IP_CRITICAL_IPS=${XRAY_ABUSE_MULTI_IP_CRITICAL_IPS}
Environment=XRAY_ABUSE_MULTI_IP_MIN_PREFIXES=${XRAY_ABUSE_MULTI_IP_MIN_PREFIXES}
Environment=XRAY_ABUSE_MULTI_IP_TOP_LIMIT=${XRAY_ABUSE_MULTI_IP_TOP_LIMIT}
Environment=XRAY_ABUSE_MULTI_IP_WINDOWS=${XRAY_ABUSE_MULTI_IP_WINDOWS}
Environment=XRAY_ABUSE_MULTI_IP_HISTORY_FILE=${XRAY_ABUSE_MULTI_IP_HISTORY_FILE}
Environment=XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS=${XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS}
Environment=XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS=${XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS}
Environment=XRAY_ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS=${XRAY_ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS}
Environment=XRAY_ABUSE_MULTI_IP_CACHE_TTL_SECONDS=${XRAY_ABUSE_MULTI_IP_CACHE_TTL_SECONDS}
ExecStart=${XRAY_ONLINE_TRACKER_SCRIPT}
Restart=always
RestartSec=2s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    normalize_xray_online_tracker_service_unit
    restart_xray_online_tracker_service_only
    if ! systemctl is-active --quiet "${XRAY_ONLINE_TRACKER_SERVICE_NAME}"; then
        journalctl -u "${XRAY_ONLINE_TRACKER_SERVICE_NAME}" -n 100 --no-pager || true
        err "Xray-core online tracker service failed to reach active state: ${XRAY_ONLINE_TRACKER_SERVICE_NAME}"
        exit 1
    fi

    log "Installed Xray-core online tracker service: ${XRAY_ONLINE_TRACKER_SERVICE_NAME}"
    info "Xray-core online tracker API: ${XRAY_ONLINE_TRACKER_URL}"
    info "Xray-core abuse audit API: ${XRAY_ABUSE_AUDIT_URL}"
}


install_standalone_xray_core() {
    local archive_name tmp_dir zip_path extract_dir
    local asset_url="" release_tag=""
    local release_meta=()

    archive_name="$(get_xray_core_archive_name)"
    mapfile -t release_meta < <(resolve_xray_core_release_asset "${archive_name}")
    asset_url="${release_meta[0]:-}"
    release_tag="${release_meta[1]:-}"

    if [[ -z "${asset_url}" ]]; then
        err "Failed to resolve download URL for standalone Xray-core archive ${archive_name}"
        exit 1
    fi

    tmp_dir="$(mktemp -d)"
    zip_path="${tmp_dir}/${archive_name}"
    extract_dir="${tmp_dir}/extract"
    mkdir -p "${extract_dir}"

    curl -fsSL --retry 3 --connect-timeout 10 -o "${zip_path}" "${asset_url}"
    python3 - "${zip_path}" "${extract_dir}" <<'PY'
import sys
import zipfile

archive_path = sys.argv[1]
extract_dir = sys.argv[2]

with zipfile.ZipFile(archive_path) as zf:
    zf.extractall(extract_dir)
PY

    write_xray_core_base_configs
    write_xray_logrotate_config

    install -m 755 "${extract_dir}/xray" "${XRAY_CORE_BIN}"
    if [[ -f "${extract_dir}/geoip.dat" ]]; then
        install -m 644 "${extract_dir}/geoip.dat" "${XRAY_CORE_SHARE_DIR}/geoip.dat"
    fi
    if [[ -f "${extract_dir}/geosite.dat" ]]; then
        install -m 644 "${extract_dir}/geosite.dat" "${XRAY_CORE_SHARE_DIR}/geosite.dat"
    fi

    write_xray_core_smoke_inbound_if_missing
    write_xray_reserved_ports_helper
    write_xray_core_service_unit

    XRAY_LOCATION_ASSET="${XRAY_CORE_SHARE_DIR}" \
    XRAY_LOCATION_CONFDIR="${XRAY_CORE_CONFIG_DIR}" \
    "${XRAY_CORE_BIN}" run -confdir "${XRAY_CORE_CONFIG_DIR}" -dump >/dev/null

    systemctl daemon-reload
    systemctl enable --now "${XRAY_CORE_SERVICE_NAME}"
    if ! systemctl is-active --quiet "${XRAY_CORE_SERVICE_NAME}"; then
        journalctl -u "${XRAY_CORE_SERVICE_NAME}" -n 100 --no-pager || true
        err "Standalone Xray-core service failed to reach active state: ${XRAY_CORE_SERVICE_NAME}"
        exit 1
    fi

    XRAY_CORE_INSTALLED_VERSION="${release_tag}"
    if [[ -z "${XRAY_CORE_PUBLIC_ENDPOINT}" ]]; then
        XRAY_CORE_PUBLIC_ENDPOINT="$(get_effective_public_endpoint_host)"
    fi

    rm -rf "${tmp_dir}"
    log "Installed official Xray-core ${release_tag:-unknown} into ${XRAY_CORE_ROOT}"
    info "Standalone Xray service: ${XRAY_CORE_SERVICE_NAME}"
}


configure_xray_minimal_logging() {
    mkdir -p "${XUI_XRAY_LOG_DIR}"
    touch "${XUI_XRAY_ACCESS_LOG}" "${XUI_XRAY_ERROR_LOG}"
    chmod 640 "${XUI_XRAY_ACCESS_LOG}" "${XUI_XRAY_ERROR_LOG}" 2>/dev/null || true

    local resolved_config_path=""
    local attempt=""
    for attempt in $(seq 1 20); do
        if [[ -f "${XUI_BIN_CONFIG}" ]]; then
            resolved_config_path="${XUI_BIN_CONFIG}"
            break
        fi
        for candidate in \
            "/usr/local/x-ui/bin/config.json" \
            "/etc/x-ui/config.json" \
            "/etc/x-ui/xray/config.json"
        do
            if [[ -f "${candidate}" ]]; then
                resolved_config_path="${candidate}"
                break 2
            fi
        done
        sleep 1
    done

    if [[ -z "${resolved_config_path}" ]]; then
        err "Xray config not found after waiting: ${XUI_BIN_CONFIG}"
        return 1
    fi

    if [[ "${resolved_config_path}" != "${XUI_BIN_CONFIG}" ]]; then
        warn "Using detected Xray config path instead of default: ${resolved_config_path}"
    fi

    XUI_BIN_CONFIG_PATH="${resolved_config_path}" \
    XUI_XRAY_ACCESS_LOG_PATH="${XUI_XRAY_ACCESS_LOG}" \
    XUI_XRAY_ERROR_LOG_PATH="${XUI_XRAY_ERROR_LOG}" \
    XUI_XRAY_LOGLEVEL_VALUE="${XUI_XRAY_LOGLEVEL}" \
    XUI_XRAY_DNS_LOG_VALUE="${XUI_XRAY_DNS_LOG}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

config_path = Path(os.environ["XUI_BIN_CONFIG_PATH"])
access_log = str(os.environ["XUI_XRAY_ACCESS_LOG_PATH"]).strip()
error_log = str(os.environ["XUI_XRAY_ERROR_LOG_PATH"]).strip()
loglevel = str(os.environ["XUI_XRAY_LOGLEVEL_VALUE"]).strip() or "warning"
dns_log_raw = str(os.environ["XUI_XRAY_DNS_LOG_VALUE"]).strip().lower()
dns_log = dns_log_raw in {"1", "true", "yes", "on"}

if not config_path.exists():
    raise SystemExit(f"Xray config not found: {config_path}")

payload = json.loads(config_path.read_text(encoding="utf-8"))
log_cfg = payload.get("log")
if not isinstance(log_cfg, dict):
    log_cfg = {}

desired = {
    "access": access_log,
    "error": error_log,
    "loglevel": loglevel,
    "dnsLog": dns_log,
}

changed = False
for key, value in desired.items():
    if log_cfg.get(key) != value:
        log_cfg[key] = value
        changed = True

payload["log"] = log_cfg

if changed:
    config_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
PY

    systemctl restart x-ui
    log "Configured minimal Xray logging for client IP tracking"
    info "Xray access log: ${XUI_XRAY_ACCESS_LOG}"
    info "Xray error log: ${XUI_XRAY_ERROR_LOG}"
    info "Xray loglevel: ${XUI_XRAY_LOGLEVEL}; dnsLog=${XUI_XRAY_DNS_LOG}"
}


panel_direct_access_local_only() {
    iptables -C INPUT -p tcp --dport "${XUI_PANEL_PORT}" -s 127.0.0.1 -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "${XUI_PANEL_PORT}" -s 127.0.0.1 -j ACCEPT
    iptables -C INPUT -p tcp --dport "${XUI_PANEL_PORT}" -j DROP 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${XUI_PANEL_PORT}" -j DROP
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save 2>/dev/null || true
    fi
    log "Direct external access to panel port ${XUI_PANEL_PORT} blocked; localhost is allowed"
}


ensure_nginx_layout() {
    local stream_root_file="${NGINX_STREAM_ROOT_FILE}"
    local legacy_stream_root_file="/etc/nginx/stream_vpnbot_mux.conf"
    local existing_stream_include="${NGINX_STREAM_INCLUDE_DIR}/*.conf"

    mkdir -p /etc/nginx/ssl/vpnbot
    mkdir -p "${NGINX_HTTP_LOCATION_DIR}"
    mkdir -p "${NGINX_STREAM_INCLUDE_DIR}"
    rm -f /etc/nginx/sites-enabled/default || true

    if grep -q 'stream_vpnbot_mux.conf' /etc/nginx/nginx.conf; then
        stream_root_file="${legacy_stream_root_file}"
        sed -i '\|include /etc/nginx/vpnbot-stream-root.conf;|d' /etc/nginx/nginx.conf
    elif grep -Eq '^[[:space:]]*stream[[:space:]]*\{' /etc/nginx/nginx.conf; then
        sed -i '\|include /etc/nginx/vpnbot-stream-root.conf;|d' /etc/nginx/nginx.conf
        EXISTING_STREAM_INCLUDE="${existing_stream_include}" python3 - <<'PY'
from pathlib import Path
import os
import re

path = Path('/etc/nginx/nginx.conf')
text = path.read_text(encoding='utf-8')
include_line = f"    include {os.environ['EXISTING_STREAM_INCLUDE']};"
if os.environ['EXISTING_STREAM_INCLUDE'] in text:
    raise SystemExit(0)

start = re.search(r'(?m)^[ \t]*stream[ \t]*\{', text)
if not start:
    raise SystemExit(0)

brace_depth = 0
end_index = None
for index in range(start.start(), len(text)):
    char = text[index]
    if char == '{':
        brace_depth += 1
    elif char == '}':
        brace_depth -= 1
        if brace_depth == 0:
            end_index = index
            break

if end_index is None:
    raise SystemExit(0)

before = text[:end_index].rstrip('\n')
after = text[end_index:]
updated = before + '\n' + include_line + '\n' + after
path.write_text(updated, encoding='utf-8')
PY
        stream_root_file=""
    elif ! grep -q 'vpnbot-stream-root.conf' /etc/nginx/nginx.conf; then
        printf '\ninclude %s;\n' "${stream_root_file}" >> /etc/nginx/nginx.conf
    fi

    if [[ -n "${stream_root_file}" && -f "${stream_root_file}" ]]; then
        cp "${stream_root_file}" "${stream_root_file}.bak.$(date +%s)" 2>/dev/null || true
    fi

    if [[ -n "${stream_root_file}" ]]; then
        cat > "${stream_root_file}" <<EOF
stream {
    include ${NGINX_STREAM_INCLUDE_DIR}/*.conf;
}
EOF
    fi
}


create_self_signed_cert() {
    local cert_domains=()
    local host=""
    for host in "${PANEL_DOMAIN}" "${SHARED_HTTP_DOMAIN}" "${APP_DOMAIN}" "${PUBLIC_DOMAIN}"; do
        host="$(trim_dot_domain "${host}")"
        if [[ -z "${host}" ]]; then
            continue
        fi
        if [[ " ${cert_domains[*]} " == *" ${host} "* ]]; then
            continue
        fi
        cert_domains+=("${host}")
    done

    local cert_name="${SELF_SIGNED_CERT_NAME:-${PANEL_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-www.amd.com}}}}"
    local primary_ip
    primary_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    local openssl_cfg
    openssl_cfg="$(mktemp)"
    cat > "${openssl_cfg}" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
CN = ${cert_name}

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${cert_name}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    local dns_index=3
    for host in "${cert_domains[@]}"; do
        if [[ "${host}" == "${cert_name}" ]]; then
            continue
        fi
        echo "DNS.${dns_index} = ${host}" >> "${openssl_cfg}"
        dns_index=$((dns_index + 1))
    done
    if [[ -n "${primary_ip}" ]]; then
        echo "IP.2 = ${primary_ip}" >> "${openssl_cfg}"
    fi
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "${NGINX_SSL_KEY}" \
        -out "${NGINX_SSL_CERT}" \
        -config "${openssl_cfg}" >/dev/null 2>&1
    rm -f "${openssl_cfg}"
    chmod 600 "${NGINX_SSL_KEY}"
    chmod 644 "${NGINX_SSL_CERT}"
    warn "Self-signed certificate created at ${NGINX_SSL_CERT}"
}


ensure_bootstrap_tls_cert() {
    if [[ -s "${NGINX_SSL_CERT}" && -s "${NGINX_SSL_KEY}" ]]; then
        return 0
    fi
    create_self_signed_cert
}


issue_or_create_cert() {
    local cert_domains=()
    local host=""
    for host in "${PANEL_DOMAIN}" "${SHARED_HTTP_DOMAIN}" "${APP_DOMAIN}" "${PUBLIC_DOMAIN}"; do
        host="$(trim_dot_domain "${host}")"
        if [[ -z "${host}" ]]; then
            continue
        fi
        if [[ " ${cert_domains[*]} " == *" ${host} "* ]]; then
            continue
        fi
        cert_domains+=("${host}")
    done

    if [[ "${#cert_domains[@]}" -gt 0 && "${ENABLE_CERTBOT}" == "1" ]]; then
        local primary_domain="${cert_domains[0]}"
        local certbot_args=()
        for host in "${cert_domains[@]}"; do
            certbot_args+=("-d" "${host}")
        done
        # We install the nginx server block ourselves. Certbot only needs to solve
        # the challenge and store the certificate; using `certonly` avoids
        # "Could not automatically find a matching server block" on fresh hosts.
        if certbot certonly --nginx "${certbot_args[@]}" -m "${LETSENCRYPT_EMAIL:-admin@${primary_domain}}" --agree-tos --non-interactive; then
            mkdir -p /etc/nginx/ssl/vpnbot
            rm -f /etc/nginx/ssl/vpnbot/fullchain.pem /etc/nginx/ssl/vpnbot/privkey.pem
            ln -s "/etc/letsencrypt/live/${primary_domain}/fullchain.pem" /etc/nginx/ssl/vpnbot/fullchain.pem
            ln -s "/etc/letsencrypt/live/${primary_domain}/privkey.pem" /etc/nginx/ssl/vpnbot/privkey.pem
            NGINX_SSL_CERT="/etc/nginx/ssl/vpnbot/fullchain.pem"
            NGINX_SSL_KEY="/etc/nginx/ssl/vpnbot/privkey.pem"
            log "Let's Encrypt certificate issued for: ${cert_domains[*]}"
            return 0
        fi
        warn "Let's Encrypt issuance failed; falling back to self-signed certificate"
    fi

    create_self_signed_cert
}


write_nginx_http_site() {
    local panel_location_block=""
    local http2_listen_suffix=" http2"
    local http2_directive=""
    if is_3xui_backend; then
        panel_location_block="$(cat <<EOF
    location ${NGINX_PANEL_LOCATION} {
        proxy_pass http://127.0.0.1:${XUI_PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

EOF
)"
    fi

    local nginx_version
    nginx_version="$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')"
    if python3 - "${nginx_version}" <<'PY' >/dev/null 2>&1
import sys
parts = []
for chunk in (sys.argv[1] if len(sys.argv) > 1 else "").split("."):
    try:
        parts.append(int(chunk))
    except Exception:
        parts.append(0)
while len(parts) < 3:
    parts.append(0)
raise SystemExit(0 if tuple(parts[:3]) >= (1, 25, 1) else 1)
PY
    then
        http2_listen_suffix=""
        http2_directive="    http2 on;"
    fi

    cat > "${NGINX_HTTP_SITE_FILE}" <<EOF
server {
    listen 80;
    server_name ${NGINX_SERVER_NAME};
    return 301 https://\$host\$request_uri;
}

server {
    listen 127.0.0.1:${HTTP_FRONTEND_LOCAL_PORT} ssl${http2_listen_suffix};
    listen 127.0.0.1:${HTTP_FRONTEND_PROXY_LOCAL_PORT} ssl${http2_listen_suffix} proxy_protocol;
${http2_directive}
    server_name ${NGINX_SERVER_NAME};
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate ${NGINX_SSL_CERT};
    ssl_certificate_key ${NGINX_SSL_KEY};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    client_max_body_size 50m;

${panel_location_block}    # Dynamic shared HTTP routes are generated here.

    include ${NGINX_HTTP_LOCATION_DIR}/*.conf;

    location / {
        default_type text/html;
        return 200 '<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Service Portal</title>
  <style>
    body{margin:0;font-family:Verdana,Arial,sans-serif;background:#f5f7fb;color:#1f2937}
    .wrap{max-width:760px;margin:12vh auto;padding:40px;background:white;border-radius:18px;box-shadow:0 12px 40px rgba(31,41,55,.12)}
    h1{margin:0 0 14px;font-size:32px;font-weight:700}
    p{font-size:16px;line-height:1.55;color:#4b5563}
    .muted{margin-top:28px;font-size:13px;color:#9ca3af}
  </style>
</head>
<body>
  <main class="wrap">
    <h1>Service Portal</h1>
    <p>Сайт временно обслуживается. Пожалуйста, повторите запрос позже.</p>
    <p class="muted">Request ID: vpnbot-edge</p>
  </main>
</body>
</html>';
    }
}
EOF

    ln -sf "${NGINX_HTTP_SITE_FILE}" /etc/nginx/sites-enabled/vpnbot_vray_http.conf
}


write_installer_state() {
    local panel_base_url="http://127.0.0.1:${XUI_PANEL_PORT}/${XUI_PANEL_WEBBASEPATH}"
    umask 077
    PANEL_PORT="${XUI_PANEL_PORT}" \
    PANEL_WEB_BASE_PATH="${XUI_PANEL_WEBBASEPATH}" \
    PANEL_USERNAME="${XUI_PANEL_USERNAME}" \
    PANEL_PASSWORD="${XUI_PANEL_PASSWORD}" \
    PANEL_BASE_URL="${panel_base_url}" \
    PANEL_DOMAIN_VALUE="${PANEL_DOMAIN}" \
    APP_DOMAIN_VALUE="${APP_DOMAIN}" \
    MT_DOMAIN_VALUE="${MT_DOMAIN}" \
    SHARED_HTTP_DOMAIN_VALUE="${SHARED_HTTP_DOMAIN}" \
    PUBLIC_DOMAIN_VALUE="${PUBLIC_DOMAIN}" \
    DDNS_PROVIDER_VALUE="${DDNS_PROVIDER}" \
    DDNS_ZONE_VALUE="${DDNS_ZONE}" \
    DDNS_HOST_LABEL_VALUE="${DDNS_HOST_LABEL}" \
    DDNS_LABEL_SUFFIX_VALUE="${DDNS_LABEL_SUFFIX}" \
    VPNBOT_SERVER_ID_VALUE="${VPNBOT_SERVER_ID}" \
    SYNC_SCRIPT_VALUE="${XUI_SYNC_SCRIPT}" \
    SSL_CERT_VALUE="${NGINX_SSL_CERT}" \
    SSL_KEY_VALUE="${NGINX_SSL_KEY}" \
    HTTP_FRONTEND_LOCAL_PORT_VALUE="${HTTP_FRONTEND_LOCAL_PORT}" \
    HTTP_FRONTEND_PROXY_LOCAL_PORT_VALUE="${HTTP_FRONTEND_PROXY_LOCAL_PORT}" \
    INSTALLER_STATE_FILE="${XUI_INSTALLER_STATE_FILE}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "panel_port": int(os.environ["PANEL_PORT"]),
    "panel_web_base_path": os.environ["PANEL_WEB_BASE_PATH"],
    "panel_username": os.environ["PANEL_USERNAME"],
    "panel_password": os.environ["PANEL_PASSWORD"],
    "panel_base_url": os.environ["PANEL_BASE_URL"],
    "panel_domain": os.environ["PANEL_DOMAIN_VALUE"],
    "app_domain": os.environ["APP_DOMAIN_VALUE"],
    "mt_domain": os.environ["MT_DOMAIN_VALUE"],
    "shared_http_domain": os.environ["SHARED_HTTP_DOMAIN_VALUE"],
    "public_domain": os.environ["PUBLIC_DOMAIN_VALUE"],
    "ddns_provider": os.environ["DDNS_PROVIDER_VALUE"],
    "ddns_zone": os.environ["DDNS_ZONE_VALUE"],
    "ddns_host_label": os.environ["DDNS_HOST_LABEL_VALUE"],
    "ddns_label_suffix": os.environ["DDNS_LABEL_SUFFIX_VALUE"],
    "vpnbot_server_id": os.environ["VPNBOT_SERVER_ID_VALUE"],
    "sync_script": os.environ["SYNC_SCRIPT_VALUE"],
    "ssl_cert": os.environ["SSL_CERT_VALUE"],
    "ssl_key": os.environ["SSL_KEY_VALUE"],
    "http_frontend_local_port": int(os.environ["HTTP_FRONTEND_LOCAL_PORT_VALUE"]),
    "http_frontend_proxy_local_port": int(os.environ["HTTP_FRONTEND_PROXY_LOCAL_PORT_VALUE"]),
}
Path(os.environ["INSTALLER_STATE_FILE"]).write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
    chmod 600 "${XUI_INSTALLER_STATE_FILE}"
}


write_rollout_bundle() {
    local panel_host public_dns_name server_public_ip panel_api_url mt_suggested_domain effective_mt_domain
    panel_host="${PANEL_DOMAIN:-${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-}}}}"
    public_dns_name="${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-}}}"
    server_public_ip="$(get_primary_ipv4)"
    if [[ -n "${panel_host}" ]]; then
        panel_api_url="https://${panel_host}${NGINX_PANEL_LOCATION%/}"
    else
        panel_api_url=""
    fi

    if [[ "${public_dns_name}" == app.* ]]; then
        mt_suggested_domain="mt.${public_dns_name#app.}"
    elif [[ "${panel_host}" == panel.* ]]; then
        mt_suggested_domain="mt.${panel_host#panel.}"
    else
        mt_suggested_domain=""
    fi
    effective_mt_domain="${MT_DOMAIN:-${mt_suggested_domain}}"

    umask 077
    PANEL_DOMAIN_VALUE="${panel_host}" \
    APP_DOMAIN_VALUE="${public_dns_name}" \
    MT_DOMAIN_VALUE="${effective_mt_domain}" \
    SHARED_HTTP_DOMAIN_VALUE="${SHARED_HTTP_DOMAIN}" \
    PUBLIC_DOMAIN_VALUE="${PUBLIC_DOMAIN}" \
    MT_SUGGESTED_DOMAIN_VALUE="${mt_suggested_domain}" \
    PANEL_API_URL_VALUE="${panel_api_url}" \
    PUBLIC_IP_VALUE="${server_public_ip}" \
    XUI_PANEL_PORT_VALUE="${XUI_PANEL_PORT}" \
    XUI_PANEL_WEBBASEPATH_VALUE="${XUI_PANEL_WEBBASEPATH}" \
    ROLLOUT_BUNDLE_FILE="${XUI_ROLLOUT_BUNDLE_FILE}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "domain_roles": {
        "panel_domain": str(os.environ.get("PANEL_DOMAIN_VALUE", "")).strip(),
        "app_domain": str(os.environ.get("APP_DOMAIN_VALUE", "")).strip(),
        "mt_domain": str(os.environ.get("MT_DOMAIN_VALUE", "")).strip(),
        "shared_http_domain": str(os.environ.get("SHARED_HTTP_DOMAIN_VALUE", "")).strip(),
        "public_domain_legacy_alias": str(os.environ.get("PUBLIC_DOMAIN_VALUE", "")).strip(),
        "mt_suggested_domain": str(os.environ.get("MT_SUGGESTED_DOMAIN_VALUE", "")).strip(),
    },
    "panel": {
        "api_url": str(os.environ.get("PANEL_API_URL_VALUE", "")).strip(),
        "api_host_suggested": str(os.environ.get("PUBLIC_IP_VALUE", "")).strip(),
        "backend_port": int(os.environ.get("XUI_PANEL_PORT_VALUE", "2053") or 2053),
        "web_base_path": str(os.environ.get("XUI_PANEL_WEBBASEPATH_VALUE", "")).strip(),
    },
    "env_examples": {
        "install_vray": {
            "APP_DOMAIN": str(os.environ.get("APP_DOMAIN_VALUE", "")).strip(),
            "PANEL_DOMAIN": str(os.environ.get("PANEL_DOMAIN_VALUE", "")).strip(),
        },
        "install_mtproxy": {
            "MTPROXY_TLS_DOMAIN": str(os.environ.get("MT_DOMAIN_VALUE", "")).strip(),
        },
    },
    "rules": [
        "panel_domain is for 3x-ui panel and bot api_url",
        "app_domain is the user-facing VLESS/shared HTTP domain",
        "mt_suggested_domain is the recommended exact hostname for MTProxy ee",
        "do not reuse the exact same hostname for panel and MTProxy ee on one shared external port",
        "for bot runtime, prefer api_host_suggested as api_host when you want panel API to avoid domain/SNI conflicts",
    ],
}

Path(os.environ["ROLLOUT_BUNDLE_FILE"]).write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
    chmod 600 "${XUI_ROLLOUT_BUNDLE_FILE}"
}


write_xray_core_installer_state() {
    umask 077
    XRAY_CORE_ROOT_VALUE="${XRAY_CORE_ROOT}" \
    XRAY_CORE_BIN_VALUE="${XRAY_CORE_BIN}" \
    XRAY_CORE_CONFIG_DIR_VALUE="${XRAY_CORE_CONFIG_DIR}" \
    XRAY_CORE_SHARE_DIR_VALUE="${XRAY_CORE_SHARE_DIR}" \
    XRAY_CORE_LOG_DIR_VALUE="${XRAY_CORE_LOG_DIR}" \
    XRAY_CORE_MANAGED_INBOUNDS_FILE_VALUE="${XRAY_CORE_MANAGED_INBOUNDS_FILE}" \
    XRAY_CORE_SERVICE_NAME_VALUE="${XRAY_CORE_SERVICE_NAME}" \
    XRAY_CORE_API_SERVER_VALUE="${XRAY_CORE_API_SERVER}" \
    XRAY_CTL_SCRIPT_VALUE="${XRAY_CTL_SCRIPT}" \
    XRAY_ONLINE_TRACKER_SERVICE_NAME_VALUE="${XRAY_ONLINE_TRACKER_SERVICE_NAME}" \
    XRAY_ONLINE_TRACKER_URL_VALUE="${XRAY_ONLINE_TRACKER_URL}" \
    XRAY_ONLINE_TRACKER_WINDOW_SECONDS_VALUE="${XRAY_ONLINE_TRACKER_WINDOW_SECONDS}" \
    XRAY_ABUSE_AUDIT_URL_VALUE="${XRAY_ABUSE_AUDIT_URL}" \
    XRAY_ABUSE_AUDIT_WINDOW_SECONDS_VALUE="${XRAY_ABUSE_AUDIT_WINDOW_SECONDS}" \
    XRAY_ABUSE_MULTI_IP_URL_VALUE="${XRAY_ABUSE_MULTI_IP_URL}" \
    XRAY_ABUSE_MULTI_IP_OBSERVE_IPS_VALUE="${XRAY_ABUSE_MULTI_IP_OBSERVE_IPS}" \
    XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS_VALUE="${XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS}" \
    XRAY_ABUSE_MULTI_IP_HIGH_IPS_VALUE="${XRAY_ABUSE_MULTI_IP_HIGH_IPS}" \
    XRAY_ABUSE_MULTI_IP_CRITICAL_IPS_VALUE="${XRAY_ABUSE_MULTI_IP_CRITICAL_IPS}" \
    XRAY_ABUSE_MULTI_IP_MIN_PREFIXES_VALUE="${XRAY_ABUSE_MULTI_IP_MIN_PREFIXES}" \
    XRAY_ABUSE_MULTI_IP_WINDOWS_VALUE="${XRAY_ABUSE_MULTI_IP_WINDOWS}" \
    XRAY_ABUSE_MULTI_IP_HISTORY_FILE_VALUE="${XRAY_ABUSE_MULTI_IP_HISTORY_FILE}" \
    XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS_VALUE="${XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS}" \
    XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS_VALUE="${XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS}" \
    XRAY_CORE_VERSION_VALUE="${XRAY_CORE_INSTALLED_VERSION}" \
    XRAY_CORE_PUBLIC_ENDPOINT_VALUE="${XRAY_CORE_PUBLIC_ENDPOINT}" \
    APP_DOMAIN_VALUE="${APP_DOMAIN}" \
    PUBLIC_DOMAIN_VALUE="${PUBLIC_DOMAIN}" \
    SHARED_HTTP_DOMAIN_VALUE="${SHARED_HTTP_DOMAIN}" \
    DDNS_PROVIDER_VALUE="${DDNS_PROVIDER}" \
    DDNS_ZONE_VALUE="${DDNS_ZONE}" \
    DDNS_HOST_LABEL_VALUE="${DDNS_HOST_LABEL}" \
    XRAY_SYNC_SCRIPT_VALUE="${XRAY_SYNC_SCRIPT}" \
    SSL_CERT_VALUE="${NGINX_SSL_CERT}" \
    SSL_KEY_VALUE="${NGINX_SSL_KEY}" \
    HTTP_FRONTEND_LOCAL_PORT_VALUE="${HTTP_FRONTEND_LOCAL_PORT}" \
    HTTP_FRONTEND_PROXY_LOCAL_PORT_VALUE="${HTTP_FRONTEND_PROXY_LOCAL_PORT}" \
    XRAY_CORE_SMOKE_ENABLE_VALUE="${XRAY_CORE_SMOKE_ENABLE}" \
    XRAY_CORE_SMOKE_PORT_VALUE="${XRAY_CORE_SMOKE_PORT_EFFECTIVE}" \
    XRAY_CORE_SMOKE_DOMAIN_VALUE="${XRAY_CORE_SMOKE_DOMAIN}" \
    XRAY_CORE_SMOKE_UUID_VALUE="${XRAY_CORE_SMOKE_UUID:-}" \
    XRAY_CORE_SMOKE_PUBLIC_KEY_VALUE="${XRAY_CORE_SMOKE_PUBLIC_KEY}" \
    XRAY_CORE_SMOKE_SHORT_ID_VALUE="${XRAY_CORE_SMOKE_SHORT_ID}" \
    XRAY_CORE_SMOKE_LINK_VALUE="${XRAY_CORE_SMOKE_LINK}" \
    INSTALLER_STATE_FILE="${XRAY_CORE_INSTALLER_STATE_FILE}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path


def parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


payload = {
    "backend_mode": "xray-core",
    "xray_root": os.environ["XRAY_CORE_ROOT_VALUE"],
    "xray_bin": os.environ["XRAY_CORE_BIN_VALUE"],
    "xray_confdir": os.environ["XRAY_CORE_CONFIG_DIR_VALUE"],
    "xray_share_dir": os.environ["XRAY_CORE_SHARE_DIR_VALUE"],
    "xray_log_dir": os.environ["XRAY_CORE_LOG_DIR_VALUE"],
    "managed_inbounds_file": os.environ["XRAY_CORE_MANAGED_INBOUNDS_FILE_VALUE"],
    "service_name": os.environ["XRAY_CORE_SERVICE_NAME_VALUE"],
    "api_server": os.environ["XRAY_CORE_API_SERVER_VALUE"],
    "xray_ctl_script": os.environ["XRAY_CTL_SCRIPT_VALUE"],
    "online_tracker": {
        "service_name": os.environ["XRAY_ONLINE_TRACKER_SERVICE_NAME_VALUE"],
        "api_url": os.environ["XRAY_ONLINE_TRACKER_URL_VALUE"],
        "window_seconds": int(os.environ["XRAY_ONLINE_TRACKER_WINDOW_SECONDS_VALUE"]),
        "abuse_audit_api_url": os.environ["XRAY_ABUSE_AUDIT_URL_VALUE"],
        "abuse_audit_window_seconds": int(os.environ["XRAY_ABUSE_AUDIT_WINDOW_SECONDS_VALUE"]),
        "multi_ip_abuse_api_url": os.environ["XRAY_ABUSE_MULTI_IP_URL_VALUE"],
        "multi_ip_thresholds": {
            "observe_ips": int(os.environ["XRAY_ABUSE_MULTI_IP_OBSERVE_IPS_VALUE"]),
            "suspicious_ips": int(os.environ["XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS_VALUE"]),
            "high_ips": int(os.environ["XRAY_ABUSE_MULTI_IP_HIGH_IPS_VALUE"]),
            "critical_ips": int(os.environ["XRAY_ABUSE_MULTI_IP_CRITICAL_IPS_VALUE"]),
            "min_prefixes": int(os.environ["XRAY_ABUSE_MULTI_IP_MIN_PREFIXES_VALUE"]),
            "windows": [
                int(item)
                for item in os.environ["XRAY_ABUSE_MULTI_IP_WINDOWS_VALUE"].split(",")
                if item.strip().isdigit()
            ],
            "known_ip_ttl_seconds": int(os.environ["XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS_VALUE"]),
            "repeat_window_seconds": int(os.environ["XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS_VALUE"]),
        },
        "multi_ip_history_file": os.environ["XRAY_ABUSE_MULTI_IP_HISTORY_FILE_VALUE"],
    },
    "xray_version": os.environ["XRAY_CORE_VERSION_VALUE"],
    "public_endpoint": os.environ["XRAY_CORE_PUBLIC_ENDPOINT_VALUE"],
    "app_domain": os.environ["APP_DOMAIN_VALUE"],
    "public_domain": os.environ["PUBLIC_DOMAIN_VALUE"],
    "shared_http_domain": os.environ["SHARED_HTTP_DOMAIN_VALUE"],
    "ddns_provider": os.environ["DDNS_PROVIDER_VALUE"],
    "ddns_zone": os.environ["DDNS_ZONE_VALUE"],
    "ddns_host_label": os.environ["DDNS_HOST_LABEL_VALUE"],
    "sync_script": os.environ["XRAY_SYNC_SCRIPT_VALUE"],
    "ssl_cert": os.environ["SSL_CERT_VALUE"],
    "ssl_key": os.environ["SSL_KEY_VALUE"],
    "http_frontend_local_port": int(os.environ["HTTP_FRONTEND_LOCAL_PORT_VALUE"]),
    "http_frontend_proxy_local_port": int(os.environ["HTTP_FRONTEND_PROXY_LOCAL_PORT_VALUE"]),
    "smoke_profile": {
        "enabled": parse_bool(os.environ.get("XRAY_CORE_SMOKE_ENABLE_VALUE")),
        "port": int(os.environ["XRAY_CORE_SMOKE_PORT_VALUE"]) if os.environ.get("XRAY_CORE_SMOKE_PORT_VALUE") else None,
        "reality_target": os.environ["XRAY_CORE_SMOKE_DOMAIN_VALUE"],
        "uuid": os.environ["XRAY_CORE_SMOKE_UUID_VALUE"],
        "public_key": os.environ["XRAY_CORE_SMOKE_PUBLIC_KEY_VALUE"],
        "short_id": os.environ["XRAY_CORE_SMOKE_SHORT_ID_VALUE"],
        "link": os.environ["XRAY_CORE_SMOKE_LINK_VALUE"],
    },
}

Path(os.environ["INSTALLER_STATE_FILE"]).write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
    chmod 600 "${XRAY_CORE_INSTALLER_STATE_FILE}"
}


write_xray_core_rollout_bundle() {
    umask 077
    APP_DOMAIN_VALUE="${APP_DOMAIN}" \
    PUBLIC_DOMAIN_VALUE="${PUBLIC_DOMAIN}" \
    SHARED_HTTP_DOMAIN_VALUE="${SHARED_HTTP_DOMAIN}" \
    XRAY_CORE_PUBLIC_ENDPOINT_VALUE="${XRAY_CORE_PUBLIC_ENDPOINT}" \
    XRAY_CORE_ROOT_VALUE="${XRAY_CORE_ROOT}" \
    XRAY_CORE_CONFIG_DIR_VALUE="${XRAY_CORE_CONFIG_DIR}" \
    XRAY_CORE_MANAGED_INBOUNDS_FILE_VALUE="${XRAY_CORE_MANAGED_INBOUNDS_FILE}" \
    XRAY_CORE_SERVICE_NAME_VALUE="${XRAY_CORE_SERVICE_NAME}" \
    XRAY_CORE_API_SERVER_VALUE="${XRAY_CORE_API_SERVER}" \
    XRAY_CTL_SCRIPT_VALUE="${XRAY_CTL_SCRIPT}" \
    XRAY_ONLINE_TRACKER_SERVICE_NAME_VALUE="${XRAY_ONLINE_TRACKER_SERVICE_NAME}" \
    XRAY_ONLINE_TRACKER_URL_VALUE="${XRAY_ONLINE_TRACKER_URL}" \
    XRAY_ABUSE_AUDIT_URL_VALUE="${XRAY_ABUSE_AUDIT_URL}" \
    XRAY_ABUSE_MULTI_IP_URL_VALUE="${XRAY_ABUSE_MULTI_IP_URL}" \
    XRAY_CORE_VERSION_VALUE="${XRAY_CORE_INSTALLED_VERSION}" \
    XRAY_CORE_SMOKE_LINK_VALUE="${XRAY_CORE_SMOKE_LINK}" \
    XRAY_SYNC_SCRIPT_VALUE="${XRAY_SYNC_SCRIPT}" \
    ROLLOUT_BUNDLE_FILE="${XRAY_CORE_ROLLOUT_BUNDLE_FILE}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "backend_mode": "xray-core",
    "domain_roles": {
        "app_domain": str(os.environ.get("APP_DOMAIN_VALUE", "")).strip(),
        "public_domain_legacy_alias": str(os.environ.get("PUBLIC_DOMAIN_VALUE", "")).strip(),
        "shared_http_domain": str(os.environ.get("SHARED_HTTP_DOMAIN_VALUE", "")).strip(),
        "public_endpoint": str(os.environ.get("XRAY_CORE_PUBLIC_ENDPOINT_VALUE", "")).strip(),
    },
    "standalone_xray": {
        "root": str(os.environ.get("XRAY_CORE_ROOT_VALUE", "")).strip(),
        "confdir": str(os.environ.get("XRAY_CORE_CONFIG_DIR_VALUE", "")).strip(),
        "managed_inbounds_file": str(os.environ.get("XRAY_CORE_MANAGED_INBOUNDS_FILE_VALUE", "")).strip(),
        "service_name": str(os.environ.get("XRAY_CORE_SERVICE_NAME_VALUE", "")).strip(),
        "api_server": str(os.environ.get("XRAY_CORE_API_SERVER_VALUE", "")).strip(),
        "xray_ctl_script": str(os.environ.get("XRAY_CTL_SCRIPT_VALUE", "")).strip(),
        "online_tracker_service_name": str(os.environ.get("XRAY_ONLINE_TRACKER_SERVICE_NAME_VALUE", "")).strip(),
        "online_tracker_api_url": str(os.environ.get("XRAY_ONLINE_TRACKER_URL_VALUE", "")).strip(),
        "abuse_audit_api_url": str(os.environ.get("XRAY_ABUSE_AUDIT_URL_VALUE", "")).strip(),
        "multi_ip_abuse_api_url": str(os.environ.get("XRAY_ABUSE_MULTI_IP_URL_VALUE", "")).strip(),
        "version": str(os.environ.get("XRAY_CORE_VERSION_VALUE", "")).strip(),
        "smoke_link": str(os.environ.get("XRAY_CORE_SMOKE_LINK_VALUE", "")).strip(),
        "sync_script": str(os.environ.get("XRAY_SYNC_SCRIPT_VALUE", "")).strip(),
    },
    "rules": [
        "standalone xray-core is installed in a dedicated folder without x-ui",
        "online/recent-activity stats are served by a local-only vpnbot-xray-online.service API",
        "abuse triage is served by the same local-only tracker at /abuse and is built from Xray access.log",
        "VPnBot treats the online tracker as required for xray-core online stats and does not silently fall back to direct access.log parsing",
        "VPnBot add/remove uses vpnbot-xrayctl on the node first and falls back to legacy SSH/SFTP only while old nodes are being updated",
        "shared 443 publication is handled through nginx stream/http route sync for managed xray inbounds",
        "VPnBot manages this backend through SSH plus the local Xray API, not through 3x-ui panel endpoints",
        "runtime config must set backend_type=xray-core and skip_subscription=true for standalone nodes",
    ],
}

Path(os.environ["ROLLOUT_BUNDLE_FILE"]).write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
    chmod 600 "${XRAY_CORE_ROLLOUT_BUNDLE_FILE}"
}


write_xray_sync_assets() {
    mkdir -p "${VPNBOT_ASSET_LIB_DIR}"
    local helper_asset
    helper_asset="${VPNBOT_ASSET_LIB_DIR}/vpnbot_xray_sync_routes.py"
    download_node_installer_asset "assets/vpnbot_xray_sync_routes.py" "${helper_asset}" 755
    cat > "${XRAY_SYNC_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export XRAY_CORE_MANAGED_INBOUNDS_FILE=${XRAY_CORE_MANAGED_INBOUNDS_FILE@Q}
export XRAY_CORE_CONFIG_DIR=${XRAY_CORE_CONFIG_DIR@Q}
export XRAY_CORE_BIN=${XRAY_CORE_BIN@Q}
export XRAY_CORE_SHARE_DIR=${XRAY_CORE_SHARE_DIR@Q}
export XRAY_CORE_SERVICE_NAME=${XRAY_CORE_SERVICE_NAME@Q}
export NGINX_HTTP_LOCATION_DIR=${NGINX_HTTP_LOCATION_DIR@Q}
export NGINX_STREAM_MAP_FILE=${NGINX_STREAM_MAP_FILE@Q}
export NGINX_STREAM_SERVER_FILE=${NGINX_STREAM_SERVER_FILE@Q}
export HTTP_FRONTEND_LOCAL_PORT=${HTTP_FRONTEND_LOCAL_PORT@Q}
export HTTP_FRONTEND_PROXY_LOCAL_PORT=${HTTP_FRONTEND_PROXY_LOCAL_PORT@Q}
export XRAY_CORE_INSTALLER_STATE_FILE=${XRAY_CORE_INSTALLER_STATE_FILE@Q}
export APP_DOMAIN=${APP_DOMAIN@Q}
export SHARED_HTTP_DOMAIN=${SHARED_HTTP_DOMAIN@Q}
export PUBLIC_DOMAIN=${PUBLIC_DOMAIN@Q}
export XRAY_SYNC_STATE_DIR=${XRAY_SYNC_STATE_DIR@Q}
export VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE=${VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE@Q}
export VPNBOT_NGINX_AUTOSTART=${VPNBOT_NGINX_AUTOSTART@Q}
exec /usr/bin/env python3 ${helper_asset@Q} "\$@"
EOF
    chmod 755 "${XRAY_SYNC_SCRIPT}"
    log "Installed Xray-core route sync helper: ${XRAY_SYNC_SCRIPT}"

    cat > "${XRAY_SYNC_SERVICE}" <<EOF
[Unit]
Description=VPnBot xray route sync
After=network-online.target ${XRAY_CORE_SERVICE_NAME} nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${XRAY_SYNC_SCRIPT}
EOF

    cat > "${XRAY_SYNC_PATH}" <<EOF
[Unit]
Description=Watch xray managed inbounds changes and regenerate nginx routes

[Path]
PathChanged=${XRAY_CORE_MANAGED_INBOUNDS_FILE}

[Install]
WantedBy=multi-user.target
EOF

    cat > "${XRAY_SYNC_TIMER}" <<EOF
[Unit]
Description=Periodic VPnBot xray route sync

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
RandomizedDelaySec=15s
Unit=vpnbot-xray-sync-routes.service

[Install]
WantedBy=timers.target
EOF
}


write_xui_sync_assets() {
    mkdir -p "${VPNBOT_ASSET_LIB_DIR}"
    local helper_asset
    helper_asset="${VPNBOT_ASSET_LIB_DIR}/vpnbot_xui_sync_routes.py"
    download_node_installer_asset "assets/vpnbot_xui_sync_routes.py" "${helper_asset}" 755
    cat > "${XUI_SYNC_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export XUI_DB_PATH=${XUI_DB_PATH@Q}
export XUI_BIN_CONFIG=${XUI_BIN_CONFIG@Q}
export NGINX_HTTP_LOCATION_DIR=${NGINX_HTTP_LOCATION_DIR@Q}
export NGINX_STREAM_MAP_FILE=${NGINX_STREAM_MAP_FILE@Q}
export NGINX_STREAM_SERVER_FILE=${NGINX_STREAM_SERVER_FILE@Q}
export HTTP_FRONTEND_LOCAL_PORT=${HTTP_FRONTEND_LOCAL_PORT@Q}
export XUI_INSTALLER_STATE_FILE=${XUI_INSTALLER_STATE_FILE@Q}
export PANEL_DOMAIN=${PANEL_DOMAIN@Q}
export APP_DOMAIN=${APP_DOMAIN@Q}
export SHARED_HTTP_DOMAIN=${SHARED_HTTP_DOMAIN@Q}
export PUBLIC_DOMAIN=${PUBLIC_DOMAIN@Q}
export XUI_SYNC_STATE_DIR=${XUI_SYNC_STATE_DIR@Q}
export VPNBOT_NGINX_AUTOSTART=${VPNBOT_NGINX_AUTOSTART@Q}
exec /usr/bin/env python3 ${helper_asset@Q} "\$@"
EOF
    chmod 755 "${XUI_SYNC_SCRIPT}"
    log "Installed 3x-ui route sync helper: ${XUI_SYNC_SCRIPT}"

    cat > "${XUI_SYNC_SERVICE}" <<EOF
[Unit]
Description=VPnBot x-ui route sync
After=network-online.target x-ui.service nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${XUI_SYNC_SCRIPT}
EOF

    cat > "${XUI_SYNC_PATH}" <<EOF
[Unit]
Description=Watch x-ui config changes and regenerate nginx routes

[Path]
PathChanged=${XUI_DB_PATH}
PathChanged=${XUI_BIN_CONFIG}

[Install]
WantedBy=multi-user.target
EOF

    cat > "${XUI_SYNC_TIMER}" <<EOF
[Unit]
Description=Periodic VPnBot x-ui route sync

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
RandomizedDelaySec=15s
Unit=vpnbot-xui-sync-routes.service

[Install]
WantedBy=timers.target
EOF
}


write_reality_sni_pool_asset() {
    mkdir -p "${VPNBOT_ASSET_SHARE_DIR}"
    mkdir -p "$(dirname "${VPNBOT_REALITY_SNI_POOL_FILE}")"
    download_node_installer_asset "assets/reality_sni_pool.json" "${VPNBOT_REALITY_SNI_POOL_FILE}" 644
    log "Installed shared REALITY SNI pool: ${VPNBOT_REALITY_SNI_POOL_FILE}"
}


write_preset_helper() {
    mkdir -p "${VPNBOT_ASSET_LIB_DIR}"
    write_reality_sni_pool_asset
    local helper_asset
    helper_asset="${VPNBOT_ASSET_LIB_DIR}/vpnbot_xui_presets.py"
    download_node_installer_asset "assets/vpnbot_xui_presets.py" "${helper_asset}" 755
    cat > "${XUI_PRESET_HELPER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export XUI_INSTALLER_STATE_FILE=${XUI_INSTALLER_STATE_FILE@Q}
export XUI_SYNC_SCRIPT=${XUI_SYNC_SCRIPT@Q}
export NGINX_SSL_CERT=${NGINX_SSL_CERT@Q}
export NGINX_SSL_KEY=${NGINX_SSL_KEY@Q}
export VPNBOT_REALITY_SNI_POOL_FILE=${VPNBOT_REALITY_SNI_POOL_FILE@Q}
exec /usr/bin/env python3 ${helper_asset@Q} "\$@"
EOF
    chmod 755 "${XUI_PRESET_HELPER}"
    log "Installed 3x-ui preset helper: ${XUI_PRESET_HELPER}"
}



write_vless_preset_helper() {
    mkdir -p "${VPNBOT_ASSET_LIB_DIR}"
    write_reality_sni_pool_asset
    local helper_asset
    helper_asset="${VPNBOT_ASSET_LIB_DIR}/vpnbot_vless_presets.py"
    download_node_installer_asset "assets/vpnbot_vless_presets.py" "${helper_asset}" 755
    cat > "${VPNBOT_VLESS_PRESET_HELPER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export VPNBOT_VLESS_BACKEND=${VPNBOT_VLESS_BACKEND@Q}
export XUI_PRESET_HELPER=${XUI_PRESET_HELPER@Q}
export XRAY_CORE_INSTALLER_STATE_FILE=${XRAY_CORE_INSTALLER_STATE_FILE@Q}
export XRAY_CORE_BIN=${XRAY_CORE_BIN@Q}
export XRAY_CORE_CONFIG_DIR=${XRAY_CORE_CONFIG_DIR@Q}
export XRAY_CORE_SHARE_DIR=${XRAY_CORE_SHARE_DIR@Q}
export XRAY_CORE_MANAGED_INBOUNDS_FILE=${XRAY_CORE_MANAGED_INBOUNDS_FILE@Q}
export XRAY_CORE_SERVICE_NAME=${XRAY_CORE_SERVICE_NAME@Q}
export XRAY_SYNC_SCRIPT=${XRAY_SYNC_SCRIPT@Q}
export VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE=${VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE@Q}
export NGINX_SSL_CERT=${NGINX_SSL_CERT@Q}
export NGINX_SSL_KEY=${NGINX_SSL_KEY@Q}
export VPNBOT_REALITY_SNI_POOL_FILE=${VPNBOT_REALITY_SNI_POOL_FILE@Q}
exec /usr/bin/env python3 ${helper_asset@Q} "\$@"
EOF
    chmod 755 "${VPNBOT_VLESS_PRESET_HELPER}"
    log "Installed VLESS preset helper: ${VPNBOT_VLESS_PRESET_HELPER}"
}



write_direct_helpers() {
    cat > "${NGINX_WS_HELPER}" <<'WS'
#!/usr/bin/env bash
set -euo pipefail
echo "Deprecated: use remark/tag markers in 3x-ui and run vpnbot-xui-sync-routes"
echo "Marker examples:"
echo "  [443] or [shared:443] inbound over shared TCP/443"
echo "  [8443] or [shared:8443] inbound over shared TCP/8443"
echo "  [direct] inbound on its own real port"
WS
    chmod 755 "${NGINX_WS_HELPER}"

    cat > "${NGINX_GRPC_HELPER}" <<'GRPC'
#!/usr/bin/env bash
set -euo pipefail
echo "Deprecated: use remark/tag markers in 3x-ui and run vpnbot-xui-sync-routes"
GRPC
    chmod 755 "${NGINX_GRPC_HELPER}"

    cat > "${NGINX_ROUTE_LIST_HELPER}" <<'LIST'
#!/usr/bin/env bash
set -euo pipefail
echo "HTTP routes:"
ls -1 /etc/nginx/vpnbot-http-locations.d 2>/dev/null || true
echo ""
echo "Stream files:"
ls -1 /etc/nginx/vpnbot-stream.d 2>/dev/null || true
LIST
    chmod 755 "${NGINX_ROUTE_LIST_HELPER}"
}


enable_sync() {
    systemctl daemon-reload
    if is_xray_core_backend; then
        systemctl enable --now vpnbot-xray-sync-routes.path
        systemctl enable --now vpnbot-xray-sync-routes.timer
        systemctl start vpnbot-xray-sync-routes.service
        return 0
    fi
    systemctl enable --now vpnbot-xui-sync-routes.path
    systemctl enable --now vpnbot-xui-sync-routes.timer
    systemctl start vpnbot-xui-sync-routes.service
}


run_initial_preset_flow() {
    if [[ "${XUI_PRESET_AUTORUN}" == "none" ]]; then
        return 0
    fi

    if [[ -t 0 && -t 1 ]]; then
        echo ""
        info "Inbound catalog"
        if is_xray_core_backend; then
            echo "  The installer can create standalone Xray-core inbound variants with direct/shared publication right now."
        else
            echo "  The installer can create grouped inbound variants for the current VLESS backend right now."
        fi
        echo "  If you skip it now, you can run: ${VPNBOT_VLESS_PRESET_HELPER}"
        "${VPNBOT_VLESS_PRESET_HELPER}"
    else
        info "Non-interactive mode detected; skip inbound catalog menu. Run ${VPNBOT_VLESS_PRESET_HELPER} later if needed."
    fi
}


show_xray_core_summary() {
    local public_endpoint
    public_endpoint="${XRAY_CORE_PUBLIC_ENDPOINT:-$(get_effective_public_endpoint_host)}"

    echo ""
    echo "==============================================="
    echo "  Standalone Xray-core install complete"
    echo "==============================================="
    echo ""
    info "Standalone Xray-core"
    echo "  Backend mode: ${VPNBOT_VLESS_BACKEND}"
    echo "  Version: ${XRAY_CORE_INSTALLED_VERSION:-<unknown>}"
    echo "  Service: ${XRAY_CORE_SERVICE_NAME}"
    echo "  Local API: ${XRAY_CORE_API_SERVER}"
    echo "  Online tracker service: ${XRAY_ONLINE_TRACKER_SERVICE_NAME}"
    echo "  Online tracker API: ${XRAY_ONLINE_TRACKER_URL}"
    echo "  Abuse audit API: ${XRAY_ABUSE_AUDIT_URL}"
    echo "  Multi-IP abuse API: ${XRAY_ABUSE_MULTI_IP_URL}"
    echo "  Multi-IP history: ${XRAY_ABUSE_MULTI_IP_HISTORY_FILE}"
    echo "  Root: ${XRAY_CORE_ROOT}"
    echo "  Binary: ${XRAY_CORE_BIN}"
    echo "  Config dir: ${XRAY_CORE_CONFIG_DIR}"
    echo "  Managed inbounds file: ${XRAY_CORE_MANAGED_INBOUNDS_FILE}"
    echo "  Assets dir: ${XRAY_CORE_SHARE_DIR}"
    echo "  Logs dir: ${XRAY_CORE_LOG_DIR}"
    echo ""
    info "Public endpoint"
    echo "  Public host/IP: ${public_endpoint:-<unknown>}"
    if [[ -n "${APP_DOMAIN}" ]]; then
        echo "  APP_DOMAIN: ${APP_DOMAIN}"
    fi
    if [[ -n "${PUBLIC_DOMAIN}" ]]; then
        echo "  PUBLIC_DOMAIN: ${PUBLIC_DOMAIN}"
    fi
    echo ""
    info "Smoke profile"
    if [[ -n "${XRAY_CORE_SMOKE_LINK}" ]]; then
        echo "  Smoke inbound: enabled"
        echo "  TCP port: ${XRAY_CORE_SMOKE_PORT_EFFECTIVE}"
        echo "  REALITY target/SNI: ${XRAY_CORE_SMOKE_DOMAIN}"
        echo "  UUID: ${XRAY_CORE_SMOKE_UUID}"
        echo "  Public key: ${XRAY_CORE_SMOKE_PUBLIC_KEY}"
        echo "  Short ID: ${XRAY_CORE_SMOKE_SHORT_ID}"
        echo "  Test link:"
        echo "  ${XRAY_CORE_SMOKE_LINK}"
    else
        echo "  Smoke inbound: not created automatically"
        echo "  Managed file currently contains:"
        echo "  ${XRAY_CORE_MANAGED_INBOUNDS_FILE}"
    fi
    echo ""
    info "State files"
    echo "  Installer state: ${XRAY_CORE_INSTALLER_STATE_FILE}"
    echo "  Rollout bundle: ${XRAY_CORE_ROLLOUT_BUNDLE_FILE}"
    echo ""
    info "What this mode does"
    echo "  • installs official Xray-core into a dedicated folder"
    echo "  • starts a separate systemd service without x-ui"
    echo "  • keeps configs, assets and logs away from /usr/local/x-ui"
    echo "  • runs a local-only online tracker service from Xray access.log"
    echo "  • exposes a local-only abuse audit at /abuse for target-port triage"
    echo "  • exposes local-only multi-IP scoring at /abuse/multi-ip"
    echo "  • requires the online tracker for VPnBot online stats; missing tracker is an error"
    echo "  • publishes shared ports through nginx stream/http route sync"
    echo "  • keeps xray-managed inbounds in a separate JSON file under confdir"
    echo ""
    info "Important compatibility note"
    echo "  VPnBot manages standalone Xray-core through SSH plus the local Xray API."
    echo "  VPnBot online stats require ${XRAY_ONLINE_TRACKER_SERVICE_NAME}; missing tracker means the node is installed incorrectly."
    echo "  Abuse checks can query: curl '${XRAY_ABUSE_AUDIT_URL}?port=49907'"
    echo "  Multi-IP scoring can query: curl '${XRAY_ABUSE_MULTI_IP_URL}'"
    echo "  Do not configure it as a 3x-ui panel server in /root/vpnbotdata/config/servers.json."
    echo "  Use backend_type=xray-core and skip_subscription=true."
    echo ""
    info "Shared ports"
    echo "  Shared publication is handled by: ${XRAY_SYNC_SCRIPT}"
    echo "  Local HTTPS frontend: 127.0.0.1:${HTTP_FRONTEND_LOCAL_PORT}"
    echo "  Local HTTPS frontend (PROXY protocol): 127.0.0.1:${HTTP_FRONTEND_PROXY_LOCAL_PORT}"
    echo "  nginx shared stream configs: ${NGINX_STREAM_INCLUDE_DIR}"
    echo "  nginx shared HTTP routes: ${NGINX_HTTP_LOCATION_DIR}"
    echo ""
    info "Helper commands"
    echo "  Quick install command:"
    echo "  ${INSTALL_VRAY_CURL_COMMAND}"
    echo ""
    echo "  systemctl status ${XRAY_CORE_SERVICE_NAME} --no-pager"
    echo "  journalctl -u ${XRAY_CORE_SERVICE_NAME} -n 200 --no-pager"
    echo "  systemctl restart ${XRAY_CORE_SERVICE_NAME}"
    echo "  systemctl status ${XRAY_ONLINE_TRACKER_SERVICE_NAME} --no-pager"
    echo "  journalctl -u ${XRAY_ONLINE_TRACKER_SERVICE_NAME} -n 200 --no-pager"
    echo "  curl -fsS ${XRAY_ONLINE_TRACKER_URL}"
    echo "  ${XRAY_CORE_BIN} version"
    echo "  XRAY_LOCATION_ASSET=${XRAY_CORE_SHARE_DIR} ${XRAY_CORE_BIN} run -confdir ${XRAY_CORE_CONFIG_DIR} -dump >/tmp/vpnbot-xray-dump.json"
    echo "  ${VPNBOT_VLESS_PRESET_HELPER}"
    echo "  ${VPNBOT_VLESS_PRESET_HELPER} --list"
    echo "  ${XRAY_SYNC_SCRIPT}"
    echo "  ${XRAY_SYNC_SCRIPT} --explain"
    echo "  cat ${XRAY_CORE_MANAGED_INBOUNDS_FILE}"
    echo "  cat ${XRAY_CORE_INSTALLER_STATE_FILE}"
}


show_summary() {
    if is_xray_core_backend; then
        show_xray_core_summary
        return 0
    fi

    local panel_host panel_browser_url panel_api_url server_public_ip public_dns_name effective_mt_domain mt_suggested_domain
    panel_host="${PANEL_DOMAIN:-${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-}}}}"
    if [[ -z "${panel_host}" ]]; then
        panel_host="$(get_primary_ipv4)"
    fi
    if [[ -n "${panel_host}" ]]; then
        panel_browser_url="https://${panel_host}${NGINX_PANEL_LOCATION}"
    else
        panel_browser_url="https://<server-ip-or-domain>${NGINX_PANEL_LOCATION}"
    fi
    panel_api_url="${panel_browser_url%/}"
    server_public_ip="$(get_primary_ipv4)"
    public_dns_name="${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-}}}"
    if [[ "${public_dns_name}" == app.* ]]; then
        mt_suggested_domain="mt.${public_dns_name#app.}"
    elif [[ "${panel_host}" == panel.* ]]; then
        mt_suggested_domain="mt.${panel_host#panel.}"
    else
        mt_suggested_domain="mt.<base>"
    fi
    effective_mt_domain="${MT_DOMAIN:-${mt_suggested_domain}}"

    echo ""
    echo "==========================================="
    echo "  3x-ui / VLESS install complete"
    echo "==========================================="
    echo ""
    info "3x-ui panel access"
    echo "  Panel URL: ${panel_browser_url}"
    echo "  Username: ${XUI_PANEL_USERNAME}"
    echo "  Password: ${XUI_PANEL_PASSWORD}"
    echo "  Credentials saved to: ${XUI_INSTALLER_STATE_FILE}"
    echo "  Rollout bundle saved to: ${XUI_ROLLOUT_BUNDLE_FILE}"
    echo "  Note: open the panel URL with the trailing slash, not /login"
    echo ""
    info "Rollout block"
    echo "  Domain for panel: ${panel_host:-<set PANEL_DOMAIN>}"
    echo "  Domain for users: ${public_dns_name:-<set APP_DOMAIN/PUBLIC_DOMAIN>}"
    echo "  Recommended domain for MTProxy: ${mt_suggested_domain}"
    echo "  Active MTProxy domain: ${effective_mt_domain}"
    echo "  Panel/API url for bot: ${panel_api_url}"
    echo "  Recommended api_host override: ${server_public_ip:-<public-ip>}"
    echo ""
    info "Ready env block"
    echo "  Use these values for the next rollout step:"
    printf 'APP_DOMAIN=%q\n' "${public_dns_name:-}"
    printf 'PANEL_DOMAIN=%q\n' "${panel_host:-}"
    printf 'MTPROXY_TLS_DOMAIN=%q\n' "${effective_mt_domain:-}"
    echo ""
    info "3x-ui panel backend"
    echo "  Backend port: ${XUI_PANEL_PORT}"
    echo "  WebBasePath: ${XUI_PANEL_WEBBASEPATH}"
    echo "  Xray access log: ${XUI_XRAY_ACCESS_LOG}"
    echo "  Xray error log: ${XUI_XRAY_ERROR_LOG}"
    echo "  Xray loglevel: ${XUI_XRAY_LOGLEVEL} (clientIps needs access log enabled)"
    echo ""
    info "Shared TCP port mode"
    echo "  Panel domain: ${PANEL_DOMAIN:-${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-<set APP_DOMAIN/PUBLIC_DOMAIN>}}}}"
    echo "  Shared HTTP domain: ${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-<set APP_DOMAIN/PUBLIC_DOMAIN>}}}"
    echo "  Server public IPv4: ${server_public_ip:-<unknown>}"
    if [[ -n "${DDNS_ZONE}" ]]; then
        echo "  Dynv6 zone: ${DDNS_ZONE}"
        echo "  Dynv6 hostname: ${PUBLIC_DOMAIN}"
        echo "  Dynv6 host label: ${DDNS_HOST_LABEL:-<auto>}"
        if [[ -n "${VPNBOT_SERVER_ID}" ]]; then
            echo "  Derived from server_id: ${VPNBOT_SERVER_ID}"
        fi
        echo "  Saved Dynv6 defaults: ${XUI_INSTALLER_DEFAULTS_FILE}"
    fi
    echo "  nginx public shared TCP ports -> stream mux"
    echo "  local HTTPS frontend: 127.0.0.1:${HTTP_FRONTEND_LOCAL_PORT}"
    echo "  local HTTPS frontend (PROXY protocol): 127.0.0.1:${HTTP_FRONTEND_PROXY_LOCAL_PORT}"
    echo ""
    info "Publication markers"
    echo "  [443] or [shared:443]     -> publish through shared TCP/443"
    echo "  [8443] or [shared:8443]   -> publish through shared TCP/8443"
    echo "  [direct]                  -> keep the inbound on its own real external port"
    echo ""
    info "Bot Runtime Hint"
    echo "  If you add this server to /root/vpnbotdata/config/servers.json:"
    echo "  • DNS name for VLESS/TLS users: ${public_dns_name:-<set APP_DOMAIN/PUBLIC_DOMAIN>}"
    echo "  • Panel/API host for the bot: ${panel_host:-<set PANEL_DOMAIN>}"
    echo "  • Server public IPv4: ${server_public_ip:-<unknown>}"
    echo "  • api_url: ${panel_api_url}"
    echo "  • api_user: ${XUI_PANEL_USERNAME}"
    echo "  • api_password: ${XUI_PANEL_PASSWORD}"
    echo "  • For VLESS 'domain' use the app/shared domain above."
    echo "  • Do not confuse panel URL and user-facing domain: panel URL is for the bot/admin API, domain is what clients import in keys."
    echo ""
    info "Ready JSON for Bot"
    echo "  Paste this block into /root/vpnbotdata/config/servers.json on the bot host:"
    BOT_SERVER_ID_VALUE="${VPNBOT_SERVER_ID:-server_id_here}" \
    BOT_SERVER_NAME_VALUE="${VPNBOT_SERVER_ID:-FLAG Server Description}" \
    BOT_PUBLIC_DOMAIN_VALUE="${public_dns_name:-${server_public_ip}}" \
    BOT_PUBLIC_IP_VALUE="${server_public_ip}" \
    BOT_API_HOST_VALUE="${server_public_ip}" \
    BOT_PANEL_API_URL_VALUE="${panel_api_url}" \
    BOT_PANEL_USER_VALUE="${XUI_PANEL_USERNAME}" \
    BOT_PANEL_PASSWORD_VALUE="${XUI_PANEL_PASSWORD}" \
    BOT_PUBLIC_PORT_VALUE="${BOT_PUBLIC_PORT_VALUE:-443}" \
    BOT_SUB_PORT_VALUE="2096" \
    BOT_SUB_SCHEME_VALUE="http" \
    python3 - <<'PY'
import json
import os

server_id = str(os.environ.get("BOT_SERVER_ID_VALUE", "")).strip().lower() or "server_id_here"
server_name = str(os.environ.get("BOT_SERVER_NAME_VALUE", "")).strip() or "FLAG Server Description"
public_domain = str(os.environ.get("BOT_PUBLIC_DOMAIN_VALUE", "")).strip()
public_ip = str(os.environ.get("BOT_PUBLIC_IP_VALUE", "")).strip()
api_host = str(os.environ.get("BOT_API_HOST_VALUE", "")).strip()
api_url = str(os.environ.get("BOT_PANEL_API_URL_VALUE", "")).strip()
api_user = str(os.environ.get("BOT_PANEL_USER_VALUE", "")).strip()
api_password = str(os.environ.get("BOT_PANEL_PASSWORD_VALUE", "")).strip()
public_port = int(os.environ.get("BOT_PUBLIC_PORT_VALUE", "443") or 443)
sub_port = int(os.environ.get("BOT_SUB_PORT_VALUE", "2096") or 2096)
sub_scheme = str(os.environ.get("BOT_SUB_SCHEME_VALUE", "http") or "http").strip()

payload = {
    server_id: {
        "name": server_name,
        "domain": public_domain,
        "port": public_port,
        "location": "Country, City",
        "api_url": api_url,
        "api_host": api_host,
        "api_user": api_user,
        "api_password": api_password,
        "allowed_levels": ["vless_max"],
        "enabled": True,
        "sub_port": sub_port,
        "sub_scheme": sub_scheme,
    }
}
print(json.dumps(payload, ensure_ascii=False, indent=2))
PY
    echo "  Note: field 'port' above is the user-facing public port, not the backend x-ui panel port."
    echo ""
    info "Ready Rollout Bundle"
    echo "  Use this as structured context for the next AI / operator when rolling out linked services on the same host:"
    PANEL_DOMAIN_VALUE="${panel_host}" \
    APP_DOMAIN_VALUE="${public_dns_name}" \
    SHARED_HTTP_DOMAIN_VALUE="${SHARED_HTTP_DOMAIN:-${APP_DOMAIN:-${PUBLIC_DOMAIN:-}}}" \
    PUBLIC_DOMAIN_VALUE="${PUBLIC_DOMAIN}" \
    MT_SUGGESTED_DOMAIN_VALUE="$(python3 - <<'PY'
import os
panel = str(os.environ.get("PANEL_DOMAIN_VALUE", "")).strip()
app = str(os.environ.get("APP_DOMAIN_VALUE", "")).strip()
if panel.startswith("panel."):
    print("mt." + panel[len("panel."):])
elif app.startswith("app."):
    print("mt." + app[len("app."):])
elif panel:
    print("mt." + panel)
elif app:
    print("mt." + app)
else:
    print("")
PY
)" \
    python3 - <<'PY'
import json
import os

payload = {
    "domain_scheme": {
        "panel_domain": str(os.environ.get("PANEL_DOMAIN_VALUE", "")).strip(),
        "app_domain": str(os.environ.get("APP_DOMAIN_VALUE", "")).strip(),
        "shared_http_domain": str(os.environ.get("SHARED_HTTP_DOMAIN_VALUE", "")).strip(),
        "public_domain_legacy_alias": str(os.environ.get("PUBLIC_DOMAIN_VALUE", "")).strip(),
        "mt_suggested_domain": str(os.environ.get("MT_SUGGESTED_DOMAIN_VALUE", "")).strip(),
    },
    "rules": [
        "panel_domain is for 3x-ui panel and api_url used by the bot/admin API",
        "app_domain is the user-facing VLESS/shared HTTP hostname",
        "mt_suggested_domain should be used for MTProxy ee on shared external 443",
        "do not reuse the exact same hostname for panel and MTProxy ee on one shared 443",
    ],
}
print(json.dumps(payload, ensure_ascii=False, indent=2))
PY
    echo "  Note: api_host is the direct IP override for panel API requests when you want the bot to avoid domain/SNI problems."
    echo ""
    info "What happens automatically"
    echo "  • tls/reality + [shared-port] on any transport -> nginx stream SNI route on that shared port"
    echo "  • ws/grpc/http-like without tls/reality + [shared-port] -> nginx HTTP route on that shared port"
    echo "  • [direct] -> no shared mux, inbound keeps its own port"
    echo "  • x-ui DB/config changes trigger vpnbot-xui-sync-routes.path"
    echo "  • periodic safety sync runs via vpnbot-xui-sync-routes.timer"
    echo ""
    info "Helper commands"
    echo "  Quick install command:"
    echo "  ${INSTALL_VRAY_CURL_COMMAND}"
    echo ""
    echo "  vpnbot-xui-sync-routes"
    echo "  vpnbot-xui-sync-routes --explain"
    echo "  ${VPNBOT_VLESS_PRESET_HELPER}"
    echo "  ${VPNBOT_VLESS_PRESET_HELPER} --list"
    echo "  ${XUI_PRESET_HELPER} --catalog-json"
    echo "  vpnbot-nginx-list-routes"
    echo "  systemctl status vpnbot-xui-sync-routes.path --no-pager"
    echo "  systemctl status vpnbot-xui-sync-routes.timer --no-pager"
    echo "  cat ${XUI_SYNC_STATE_DIR}/last_sync_report.txt"
    echo "  cat ${XUI_INSTALLER_STATE_FILE}"
    echo "  cat ${XUI_INSTALLER_DEFAULTS_FILE}"
    echo "  Example DDNS env: DDNS_PROVIDER=dynv6 DDNS_ZONE=myvpn.dynv6.net DDNS_TOKEN=<ddclient-password> VPNBOT_SERVER_ID=de-bmv4-ultra-u2"
    echo "  Or pass full Dynv6 text: DDNS_PROVIDER=dynv6 DDNS_INSTRUCTIONS_TEXT=\$'protocol=dyndns2\\nserver=dynv6.com\\nlogin=none\\npassword=...\\nmyvpn.dynv6.net'"
    echo "  Optional override: DDNS_HOST_LABEL=de-bmv4-manual-tls or DDNS_LABEL_SUFFIX=vmess"
    echo ""
    info "Cheat sheet"
    echo "  1. Run ${VPNBOT_VLESS_PRESET_HELPER}"
    echo "  2. Select one or several inbound lines from the catalog"
    echo "  3. The helper will parse protocol/transport/security/SNI from the selected lines"
    echo "  4. If a direct or shared port is busy, the helper will try to auto-resolve it and print what changed"
    echo "  5. Sync then rebuilds nginx routes automatically"
    echo "  6. If you want to force it immediately: vpnbot-xui-sync-routes"
    echo "  7. If something was not published through shared port, read last_sync_report.txt"
    echo "  8. The catalog is grouped into Reality TCP, Reality XHTTP and TLS."
    echo ""
    info "Architecture notes"
    echo "  • AWG should keep UDP/443."
    echo "  • Shared VLESS/TLS mux can own multiple TCP ports, not only 443."
    echo "  • Direct-mode inbound ports are still real ports."
    echo "  • For tls/reality shared mode, set proper serverNames in the inbound."
    echo "  • Shared ports remove external port collisions, but tls/reality still need unique SNI per route."
}


main() {
    check_root
    load_installer_defaults
    normalize_vless_backend_mode
    prompt_vless_backend_mode_if_needed
    normalize_dynv6_credentials
    collect_interactive_defaults
    sync_domain_aliases
    install_dependencies
    configure_vpnbot_network_limits
    configure_dynv6_domain
    normalize_inputs
    validate_configured_public_hosts
    if is_xray_core_backend; then
        install_standalone_xray_core
        write_xrayctl_assets
        write_xray_online_tracker_assets
        ensure_nginx_layout
        ensure_bootstrap_tls_cert
        write_nginx_http_site
        issue_or_create_cert
        write_nginx_http_site
        write_xray_core_installer_state
        write_xray_core_rollout_bundle
        write_xray_sync_assets
        write_vless_preset_helper
        write_direct_helpers
        enable_sync
    else
        install_3xui_noninteractive
        configure_xray_minimal_logging
        write_xray_logrotate_config
        panel_direct_access_local_only
        ensure_nginx_layout
        ensure_bootstrap_tls_cert
        write_nginx_http_site
        issue_or_create_cert
        write_nginx_http_site
        write_installer_state
        write_rollout_bundle
        write_xui_sync_assets
        write_preset_helper
        write_vless_preset_helper
        write_direct_helpers
        enable_sync
    fi
    run_initial_preset_flow
    show_summary
}

main "$@"
