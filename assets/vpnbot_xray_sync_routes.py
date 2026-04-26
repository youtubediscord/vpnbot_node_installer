#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

MANAGED_INBOUNDS_FILE = Path(os.environ.get("XRAY_CORE_MANAGED_INBOUNDS_FILE", "/opt/vpnbot/xray-core/config/50_vpnbot_managed_inbounds.json"))
XRAY_CORE_CONFIG_DIR = Path(os.environ.get("XRAY_CORE_CONFIG_DIR", str(MANAGED_INBOUNDS_FILE.parent)))
XRAY_CORE_BIN = os.environ.get("XRAY_CORE_BIN", "/opt/vpnbot/xray-core/bin/xray")
XRAY_CORE_SHARE_DIR = os.environ.get("XRAY_CORE_SHARE_DIR", "/opt/vpnbot/xray-core/share")
XRAY_CORE_SERVICE_NAME = os.environ.get("XRAY_CORE_SERVICE_NAME", "vpnbot-xray.service")
HTTP_DIR = Path(os.environ.get("NGINX_HTTP_LOCATION_DIR", "/etc/nginx/vpnbot-http-locations.d"))
STREAM_MAP = Path(os.environ.get("NGINX_STREAM_MAP_FILE", "/etc/nginx/vpnbot-stream.d/vpnbot_stream_map.conf"))
STREAM_SERVER = Path(os.environ.get("NGINX_STREAM_SERVER_FILE", "/etc/nginx/vpnbot-stream.d/vpnbot_stream_server.conf"))
HTTP_FRONTEND = f"127.0.0.1:{os.environ.get('HTTP_FRONTEND_LOCAL_PORT', '10443')}"
HTTP_FRONTEND_PROXY = f"127.0.0.1:{os.environ.get('HTTP_FRONTEND_PROXY_LOCAL_PORT', '10444')}"
INSTALLER_STATE_FILE = Path(os.environ.get("XRAY_CORE_INSTALLER_STATE_FILE", "/etc/vpnbot-xray-installer-state.json"))
DEFAULT_APP_DOMAIN = os.environ.get("APP_DOMAIN", "")
DEFAULT_SHARED_HTTP_DOMAIN = os.environ.get("SHARED_HTTP_DOMAIN", "")
DEFAULT_PUBLIC_DOMAIN = os.environ.get("PUBLIC_DOMAIN", "")
STATE_DIR = Path(os.environ.get("XRAY_SYNC_STATE_DIR", "/var/lib/vpnbot-xray-sync"))
REPORT_FILE = STATE_DIR / "last_sync_report.txt"
EXTRA_STREAM_ROUTES = Path("/etc/vpnbot-shared-stream-routes.json")
RESERVED_PORTS_SYSCTL_FILE = Path(os.environ.get("VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE", "/etc/sysctl.d/99-vpnbot-xray-reserved-ports.conf"))
NGINX_AUTOSTART = str(os.environ.get("VPNBOT_NGINX_AUTOSTART", "1")).strip().lower() not in {"0", "false", "no", "off"}

MARK_RE = re.compile(r"\[(?P<value>direct|shared:\d+|\d+)\]", re.IGNORECASE)
DOLLAR = "$"


def load_installer_state() -> dict:
    if not INSTALLER_STATE_FILE.exists():
        return {}
    try:
        payload = json.loads(INSTALLER_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


INSTALLER_STATE = load_installer_state()
APP_DOMAIN = str(INSTALLER_STATE.get("app_domain") or DEFAULT_APP_DOMAIN or "").strip()
SHARED_HTTP_DOMAIN = str(INSTALLER_STATE.get("shared_http_domain") or DEFAULT_SHARED_HTTP_DOMAIN or "").strip()
PUBLIC_DOMAIN = str(INSTALLER_STATE.get("public_domain") or DEFAULT_PUBLIC_DOMAIN or "").strip()


def parse_publication_spec(text: str) -> dict:
    m = MARK_RE.search(text or "")
    if not m:
        return {"mode": "direct", "port": None}
    raw = m.group("value").lower()
    if raw == "direct":
        return {"mode": "direct", "port": None}
    if raw.startswith("shared:"):
        try:
            port = int(raw.split(":", 1)[1])
        except Exception:
            return {"mode": "direct", "port": None}
        return {"mode": "shared", "port": port}
    try:
        port = int(raw)
    except Exception:
        return {"mode": "direct", "port": None}
    return {"mode": "shared", "port": port}


def resolve_publication_spec(tag: str, remark: str) -> tuple[dict, str]:
    for candidate in (str(tag or ""), str(remark or "")):
        if not MARK_RE.search(candidate):
            continue
        return parse_publication_spec(candidate), candidate
    return parse_publication_spec(str(tag or "")), str(tag or "")


def normalize_inbound_rows(raw_obj) -> list[dict]:
    if raw_obj is None:
        return []
    if isinstance(raw_obj, str):
        try:
            raw_obj = json.loads(raw_obj)
        except Exception:
            return []
    if isinstance(raw_obj, list):
        return [row for row in raw_obj if isinstance(row, dict)]
    if isinstance(raw_obj, dict):
        nested = raw_obj.get("inbounds")
        if isinstance(nested, list):
            return [row for row in nested if isinstance(row, dict)]
        return [raw_obj]
    return []


def load_inbounds() -> list[dict]:
    if not MANAGED_INBOUNDS_FILE.exists():
        return []
    try:
        payload = json.loads(MANAGED_INBOUNDS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Failed to parse managed inbounds file {MANAGED_INBOUNDS_FILE}: {exc}") from exc
    return normalize_inbound_rows(payload.get("inbounds"))


def json_load(value):
    if not value:
        return {}
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}


def ensure_dirs():
    HTTP_DIR.mkdir(parents=True, exist_ok=True)
    STREAM_MAP.parent.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def snapshot_generated_nginx_config() -> dict[str, bytes]:
    paths = [STREAM_MAP, STREAM_SERVER]
    if HTTP_DIR.exists():
        paths.extend(sorted(HTTP_DIR.glob("*.conf")))
    snapshot = {}
    for path in paths:
        if path.exists():
            snapshot[str(path)] = path.read_bytes()
    return snapshot


def apply_nginx_config_if_needed(before: dict[str, bytes]) -> str:
    after = snapshot_generated_nginx_config()
    changed = before != after
    subprocess.run(["nginx", "-t"], check=True)

    active = subprocess.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0
    if not active:
        if not NGINX_AUTOSTART:
            return "nginx was inactive; autostart skipped"
        subprocess.run(["systemctl", "start", "nginx"], check=True)
        return "nginx was inactive; started"
    if changed:
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        return "nginx config changed; reloaded"
    return "nginx config unchanged; reload skipped"


def parse_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_extra_routes() -> list[dict]:
    if not EXTRA_STREAM_ROUTES.exists():
        return []
    try:
        payload = json.loads(EXTRA_STREAM_ROUTES.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Failed to parse shared stream routes file {EXTRA_STREAM_ROUTES}: {exc}") from exc

    if isinstance(payload, dict):
        raw_routes = payload.get("routes") or []
    elif isinstance(payload, list):
        raw_routes = payload
    else:
        raw_routes = []

    routes = []
    for idx, item in enumerate(raw_routes, start=1):
        if not isinstance(item, dict):
            continue
        route_id = str(item.get("route_id") or item.get("id") or f"route_{idx}").strip() or f"route_{idx}"
        if not parse_bool(item.get("enabled"), default=True):
            continue
        domain = str(item.get("domain") or "").strip().lower()
        default_route = parse_bool(item.get("default"), default=False) or domain in {"default", "__default__", "*", "_"}
        backend_host = str(item.get("backend_host") or "127.0.0.1").strip() or "127.0.0.1"
        source = str(item.get("source") or item.get("service_type") or "external").strip() or "external"
        proxy_protocol = parse_bool(item.get("proxy_protocol"), default=False)
        try:
            shared_port = int(item.get("shared_port") or 0)
            backend_port = int(item.get("backend_port") or 0)
        except Exception:
            continue
        if (not domain and not default_route) or shared_port <= 0 or backend_port <= 0:
            continue
        routes.append(
            {
                "route_id": route_id,
                "domain": "" if default_route else domain,
                "default": default_route,
                "shared_port": shared_port,
                "backend_host": backend_host,
                "backend_port": backend_port,
                "source": source,
                "proxy_protocol": proxy_protocol,
            }
        )
    return routes


def register_stream_target(
    shared_port: int,
    domain: str,
    backend_target: str,
    passthrough_by_port: dict[int, dict[str, str]],
    source: str,
) -> None:
    shared_map = passthrough_by_port.setdefault(shared_port, {})
    existing = shared_map.get(domain)
    if existing and existing != backend_target:
        raise SystemExit(
            f"Shared stream conflict on port {shared_port} for domain {domain}: "
            f"{existing} already registered, new target {backend_target} from {source}"
        )
    shared_map[domain] = backend_target


def register_default_stream_target(
    shared_port: int,
    backend_target: str,
    default_by_port: dict[int, str],
    source: str,
) -> None:
    existing = default_by_port.get(shared_port)
    if existing and existing != backend_target:
        raise SystemExit(
            f"Shared stream default-route conflict on port {shared_port}: "
            f"{existing} already registered, new target {backend_target} from {source}"
        )
    default_by_port[shared_port] = backend_target


def write_http_route(name: str, path: str, port: int, grpc: bool) -> None:
    target = HTTP_DIR / f"{name}.conf"
    if grpc:
        body = f'''location {path} {{
    grpc_set_header Host $host;
    grpc_set_header X-Real-IP $remote_addr;
    grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    grpc_set_header X-Forwarded-Proto https;
    grpc_pass grpc://127.0.0.1:{port};
}}
'''
    else:
        body = f'''location {path} {{
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_pass http://127.0.0.1:{port};
}}
'''
    target.write_text(body, encoding="utf-8")


def build_stream_configs(
    shared_ports: list[int],
    shared_domains: set[str],
    passthrough_by_port: dict[int, dict[str, str]],
    default_by_port: dict[int, str],
    proxy_protocol_ports: set[int],
) -> str:
    blocks = []
    for shared_port in shared_ports:
        use_proxy_protocol = shared_port in proxy_protocol_ports
        var_name = f"{DOLLAR}vpnbot_backend_{shared_port}"
        explicit_routes = passthrough_by_port.get(shared_port) or {}
        fallback_target = HTTP_FRONTEND_PROXY if use_proxy_protocol else HTTP_FRONTEND
        default_target = default_by_port.get(shared_port, fallback_target)
        lines = [
            f"map {DOLLAR}ssl_preread_server_name {var_name} {{",
            "    hostnames;",
            f"    default {default_target};",
        ]
        for domain in sorted(shared_domains):
            if domain in explicit_routes:
                continue
            lines.append(f"    {domain} {fallback_target};")
        for domain, backend_target in sorted(explicit_routes.items()):
            lines.append(f"    {domain} {backend_target};")
        lines.append("}")
        lines.append("")
        lines.append("server {")
        lines.append(f"    listen {shared_port} reuseport;")
        lines.append(f"    proxy_pass {var_name};")
        if use_proxy_protocol:
            lines.append("    proxy_protocol on;")
        lines.append("    ssl_preread on;")
        lines.append("}")
        lines.append("")
        blocks.append("\n".join(lines))
    return "\n".join(blocks).rstrip() + "\n"


def validate_and_restart_xray(report_lines: list[str]) -> None:
    env = os.environ.copy()
    env.setdefault("XRAY_LOCATION_ASSET", XRAY_CORE_SHARE_DIR)
    result = subprocess.run(
        [XRAY_CORE_BIN, "run", "-test", "-confdir", str(XRAY_CORE_CONFIG_DIR)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            "Xray config validation failed after proxy protocol sync:\n"
            + (result.stdout or "")
            + (result.stderr or "")
        )
    subprocess.run(["systemctl", "restart", XRAY_CORE_SERVICE_NAME], check=True)
    report_lines.append(f"xray_restart: {XRAY_CORE_SERVICE_NAME} restarted after proxy_protocol config sync")


def sync_xray_proxy_protocol_settings(
    rows: list[dict],
    proxy_protocol_ports: set[int],
    report_lines: list[str],
) -> None:
    changed = False
    enabled = 0
    disabled = 0

    for row in rows:
        if not isinstance(row, dict):
            continue
        tag = str(row.get("tag") or "")
        remark = str(row.get("remark") or "")
        publication, _publication_source = resolve_publication_spec(tag, remark)
        if publication["mode"] != "shared" or not publication.get("port"):
            continue

        shared_port = int(publication["port"])
        desired = shared_port in proxy_protocol_ports
        stream = row.get("streamSettings")
        if not isinstance(stream, dict):
            stream = {}
            row["streamSettings"] = stream

        sockopt = stream.get("sockopt")
        if not isinstance(sockopt, dict):
            sockopt = {}
            stream["sockopt"] = sockopt
        current_sockopt = bool(sockopt.get("acceptProxyProtocol"))
        if current_sockopt != desired:
            sockopt["acceptProxyProtocol"] = desired
            changed = True
            enabled += 1 if desired else 0
            disabled += 0 if desired else 1

        if str(stream.get("network") or "").lower() == "tcp":
            tcp = stream.get("tcpSettings")
            if not isinstance(tcp, dict):
                tcp = {"header": {"type": "none"}}
                stream["tcpSettings"] = tcp
            current_tcp = bool(tcp.get("acceptProxyProtocol"))
            if current_tcp != desired:
                tcp["acceptProxyProtocol"] = desired
                changed = True

    if not changed:
        report_lines.append("proxy_protocol_xray: already in sync")
        return

    payload = {"inbounds": rows}
    MANAGED_INBOUNDS_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_lines.append(
        f"proxy_protocol_xray: updated managed inbounds enabled={enabled} disabled={disabled}"
    )
    validate_and_restart_xray(report_lines)


def write_report(lines: list[str]) -> None:
    REPORT_FILE.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def parse_reserved_ports(raw: str) -> set[int]:
    ports: set[int] = set()
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
            for value in range(max(1, start), min(65535, end) + 1):
                ports.add(value)
            continue
        try:
            value = int(chunk)
        except Exception:
            continue
        if 1 <= value <= 65535:
            ports.add(value)
    return ports


def format_reserved_ports(ports: set[int]) -> str:
    return ",".join(str(port) for port in sorted(ports))


def current_reserved_ports() -> set[int]:
    result = subprocess.run(
        ["sysctl", "-n", "net.ipv4.ip_local_reserved_ports"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    return parse_reserved_ports(result.stdout.strip())


def managed_inbound_ports(rows: list[dict]) -> set[int]:
    ports: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port") or 0)
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ports


def sync_xray_reserved_ports(rows: list[dict], report_lines: list[str] | None = None) -> None:
    ports = managed_inbound_ports(rows)
    if not ports:
        return

    RESERVED_PORTS_SYSCTL_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESERVED_PORTS_SYSCTL_FILE.write_text(
        "# VPnBot standalone Xray-core managed inbound ports.\n"
        "# These ports must not be reused as ephemeral source ports by nginx, MTProxy, or other local clients.\n"
        f"net.ipv4.ip_local_reserved_ports={format_reserved_ports(ports)}\n",
        encoding="utf-8",
    )

    merged = current_reserved_ports() | ports
    value = format_reserved_ports(merged)
    result = subprocess.run(
        ["sysctl", "-w", f"net.ipv4.ip_local_reserved_ports={value}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        raise SystemExit(f"Failed to reserve xray inbound ports via sysctl: {message}")

    if report_lines is not None:
        report_lines.append(f"reserved_xray_ports: {format_reserved_ports(ports)}")


def main() -> int:
    if "--explain" in sys.argv:
        print(
            "vpnbot-xray-sync-routes modes:\n"
            "  [443] or [shared:443]   publish inbound through shared TCP/443\n"
            "  [8443] or [shared:8443] publish inbound through shared TCP/8443\n"
            "  [direct]                keep inbound on its own real port\n"
            "\n"
            "Shared port behaviour:\n"
            "  tls/reality on any transport -> nginx stream SNI passthrough on the chosen external port\n"
            "  ws/grpc/http-like without tls/reality -> nginx HTTP route behind the chosen shared port\n"
            "\n"
            "Notes:\n"
            "  - xray-core sync reads managed inbounds from JSON instead of x-ui DB\n"
            "  - if no shared marker is present, sync treats inbound as direct\n"
            "  - for reality/tls on any shared port, inbound must have serverNames / serverName set\n"
            "    unless it intentionally acts as the default no-SNI backend for that shared port\n"
            "  - xhttp/httpupgrade/splithttp are treated as HTTP-like routes when possible\n"
            "  - route sync is automatic via systemd path + timer\n"
            f"  - sync report: {REPORT_FILE}\n"
        )
        return 0

    ensure_dirs()
    nginx_config_before = snapshot_generated_nginx_config()
    for f in HTTP_DIR.glob("*.conf"):
        f.unlink()

    rows = load_inbounds()
    shared_domains = set()
    for host in (SHARED_HTTP_DOMAIN, APP_DOMAIN, PUBLIC_DOMAIN):
        host = str(host or "").strip()
        if host:
            shared_domains.add(host)

    shared_ports = set()
    passthrough_by_port = {}
    default_by_port = {}
    xray_stream_ports: set[int] = set()
    proxy_protocol_blocked_ports: set[int] = set()
    report_lines = [
        "VPnBot xray-core sync report",
        "============================",
        "",
        f"managed_inbounds: {MANAGED_INBOUNDS_FILE}",
        f"shared_http_domain: {SHARED_HTTP_DOMAIN or APP_DOMAIN or PUBLIC_DOMAIN or '<none>'}",
        "",
    ]

    for idx, row in enumerate(rows, start=1):
        row_id = row.get("id") if row.get("id") is not None else idx
        tag = str(row.get("tag") or "")
        remark = str(row.get("remark") or "")
        protocol = str(row.get("protocol") or "").lower()
        port = int(row.get("port") or 0)

        if not parse_bool(row.get("enable"), default=True):
            report_lines.append(f"id={row_id} skip disabled tag={tag!r}")
            continue
        if port <= 0:
            report_lines.append(f"id={row_id} skip invalid_port tag={tag!r}")
            continue

        publication, publication_source = resolve_publication_spec(tag, remark)
        if publication["mode"] != "shared" or not publication.get("port"):
            report_lines.append(
                f"id={row_id} direct port={port} protocol={protocol} tag={tag!r} remark={remark!r}"
            )
            continue
        shared_port = int(publication["port"])
        shared_ports.add(shared_port)

        stream = json_load(row.get("streamSettings"))
        network = str(stream.get("network") or "").lower()
        security = str(stream.get("security") or "").lower()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", tag or f"inbound_{row_id}")

        domains = []
        if security == "reality":
            reality = stream.get("realitySettings") or {}
            domains = [str(x).strip() for x in (reality.get("serverNames") or []) if str(x).strip()]
        elif security == "tls":
            tls = stream.get("tlsSettings") or {}
            raw_names = tls.get("serverNames") or []
            if isinstance(raw_names, list):
                domains.extend(str(x).strip() for x in raw_names if str(x).strip())
            server_name = str(tls.get("serverName") or "").strip()
            if server_name:
                domains.append(server_name)
            nested = tls.get("settings") or {}
            nested_name = str(nested.get("serverName") or "").strip()
            if nested_name:
                domains.append(nested_name)
        domains = sorted({d for d in domains if d})

        if domains:
            backend_target = f"127.0.0.1:{port}"
            xray_stream_ports.add(shared_port)
            for domain in domains:
                register_stream_target(shared_port, domain, backend_target, passthrough_by_port, f"xray inbound #{row_id}")
            report_lines.append(
                f"id={row_id} shared-stream external_port={shared_port} network={network or '<none>'} security={security or '<none>'} "
                f"domains={','.join(domains)} backend_port={port} protocol={protocol} "
                f"marker_source={publication_source!r} tag={tag!r} remark={remark!r}"
            )
            continue

        if security in {"tls", "reality"}:
            backend_target = f"127.0.0.1:{port}"
            xray_stream_ports.add(shared_port)
            register_default_stream_target(
                shared_port,
                backend_target,
                default_by_port,
                f"xray inbound #{row_id}",
            )
            report_lines.append(
                f"id={row_id} shared-stream-default external_port={shared_port} network={network or '<none>'} "
                f"security={security or '<none>'} backend_port={port} protocol={protocol} "
                f"reason=no_sni_domains marker_source={publication_source!r} tag={tag!r} remark={remark!r}"
            )
            continue

        if network == "ws":
            ws = stream.get("wsSettings") or {}
            path = str(ws.get("path") or "").strip() or f"/ws-{port}"
            write_http_route(safe_name, path, port, grpc=False)
            report_lines.append(
                f"id={row_id} shared-http external_port={shared_port} network=ws security={security or '<none>'} "
                f"path={path} backend_port={port} protocol={protocol} "
                f"marker_source={publication_source!r} tag={tag!r} remark={remark!r}"
            )
            continue

        if network == "grpc":
            grpc = stream.get("grpcSettings") or {}
            service_name = str(grpc.get("serviceName") or "").strip() or f"grpc-{port}"
            write_http_route(safe_name, "/" + service_name.lstrip("/"), port, grpc=True)
            report_lines.append(
                f"id={row_id} shared-http external_port={shared_port} network=grpc security={security or '<none>'} "
                f"service=/{service_name.lstrip('/')} backend_port={port} protocol={protocol} "
                f"marker_source={publication_source!r} tag={tag!r} remark={remark!r}"
            )
            continue

        httpish_path = ""
        for key in ("xhttpSettings", "httpupgradeSettings", "splitHTTPSettings"):
            cfg = stream.get(key) or {}
            candidate = str(cfg.get("path") or "").strip()
            if candidate:
                httpish_path = candidate
                break
        if network in {"xhttp", "httpupgrade", "splithttp"}:
            path = httpish_path or f"/{network}-{port}"
            write_http_route(safe_name, path, port, grpc=False)
            report_lines.append(
                f"id={row_id} shared-http external_port={shared_port} network={network} security={security or '<none>'} "
                f"path={path} backend_port={port} protocol={protocol} "
                f"marker_source={publication_source!r} tag={tag!r} remark={remark!r}"
            )
            continue

        report_lines.append(
            f"id={row_id} unsupported_shared_port external_port={shared_port} network={network or '<none>'} security={security or '<none>'} "
            f"backend_port={port} protocol={protocol} reason=no_sni_or_http_route "
            f"marker_source={publication_source!r} tag={tag!r} remark={remark!r}"
        )

    for route in load_extra_routes():
        shared_port = int(route["shared_port"])
        backend_target = f'{route["backend_host"]}:{route["backend_port"]}'
        shared_ports.add(shared_port)
        if not route.get("proxy_protocol"):
            proxy_protocol_blocked_ports.add(shared_port)
        if route.get("default"):
            register_default_stream_target(
                shared_port,
                backend_target,
                default_by_port,
                f'external route {route["route_id"]}',
            )
            report_lines.append(
                f'external route_id={route["route_id"]} external_port={shared_port} '
                f'domain=<default> backend_target={backend_target} source={route["source"]!r} '
                f'proxy_protocol={bool(route.get("proxy_protocol"))}'
            )
        else:
            register_stream_target(
                shared_port,
                route["domain"],
                backend_target,
                passthrough_by_port,
                f'external route {route["route_id"]}',
            )
            report_lines.append(
                f'external route_id={route["route_id"]} external_port={shared_port} '
                f'domain={route["domain"]} backend_target={backend_target} source={route["source"]!r} '
                f'proxy_protocol={bool(route.get("proxy_protocol"))}'
            )

    proxy_protocol_ports = set(xray_stream_ports) - set(proxy_protocol_blocked_ports)
    if proxy_protocol_ports:
        report_lines.append(f"proxy_protocol_ports: {','.join(str(p) for p in sorted(proxy_protocol_ports))}")
    if proxy_protocol_blocked_ports:
        report_lines.append(
            "proxy_protocol_disabled_ports_due_external_routes: "
            + ",".join(str(p) for p in sorted(proxy_protocol_blocked_ports))
        )
    sync_xray_proxy_protocol_settings(rows, proxy_protocol_ports, report_lines)
    sync_xray_reserved_ports(rows, report_lines)

    STREAM_MAP.write_text(
        build_stream_configs(
            sorted(shared_ports),
            shared_domains,
            passthrough_by_port,
            default_by_port,
            proxy_protocol_ports,
        ),
        encoding="utf-8",
    )
    STREAM_SERVER.write_text("# generated by vpnbot-xray-sync-routes\n", encoding="utf-8")
    write_report(report_lines)

    nginx_action = apply_nginx_config_if_needed(nginx_config_before)
    print(f"vpnbot-xray-sync-routes: nginx config regenerated successfully ({nginx_action})")
    print(f"vpnbot-xray-sync-routes: report written to {REPORT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
