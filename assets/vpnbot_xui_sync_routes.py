#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

DB_PATH = Path(os.environ.get("XUI_DB_PATH", "/etc/x-ui/x-ui.db"))
CONFIG_PATH = Path(os.environ.get("XUI_BIN_CONFIG", "/usr/local/x-ui/bin/config.json"))
HTTP_DIR = Path(os.environ.get("NGINX_HTTP_LOCATION_DIR", "/etc/nginx/vpnbot-http-locations.d"))
STREAM_MAP = Path(os.environ.get("NGINX_STREAM_MAP_FILE", "/etc/nginx/vpnbot-stream.d/vpnbot_stream_map.conf"))
STREAM_SERVER = Path(os.environ.get("NGINX_STREAM_SERVER_FILE", "/etc/nginx/vpnbot-stream.d/vpnbot_stream_server.conf"))
HTTP_FRONTEND = f"127.0.0.1:{os.environ.get('HTTP_FRONTEND_LOCAL_PORT', '10443')}"
INSTALLER_STATE_FILE = Path(os.environ.get("XUI_INSTALLER_STATE_FILE", "/etc/vpnbot-xui-installer-state.json"))
DEFAULT_PANEL_DOMAIN = os.environ.get("PANEL_DOMAIN", "")
DEFAULT_APP_DOMAIN = os.environ.get("APP_DOMAIN", "")
DEFAULT_SHARED_HTTP_DOMAIN = os.environ.get("SHARED_HTTP_DOMAIN", "")
DEFAULT_PUBLIC_DOMAIN = os.environ.get("PUBLIC_DOMAIN", "")
STATE_DIR = Path(os.environ.get("XUI_SYNC_STATE_DIR", "/var/lib/vpnbot-xui-sync"))
REPORT_FILE = STATE_DIR / "last_sync_report.txt"
EXTRA_STREAM_ROUTES = Path("/etc/vpnbot-shared-stream-routes.json")
NGINX_AUTOSTART = str(os.environ.get("VPNBOT_NGINX_AUTOSTART", "1")).strip().lower() not in {"0", "false", "no", "off"}

MARK_RE = re.compile(r"\[(?P<value>direct|shared:\d+|\d+)\]", re.IGNORECASE)


def load_installer_state() -> dict:
    if not INSTALLER_STATE_FILE.exists():
        return {}
    try:
        payload = json.loads(INSTALLER_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


INSTALLER_STATE = load_installer_state()
PANEL_DOMAIN = str(INSTALLER_STATE.get("panel_domain") or DEFAULT_PANEL_DOMAIN or "").strip()
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


def load_inbounds() -> list[dict]:
    if not DB_PATH.exists():
        raise SystemExit(f"3x-ui DB not found: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(inbounds)")}
        select_parts = []
        for plain in ("id", "remark", "tag", "enable", "port", "protocol", "settings", "sniffing"):
            if plain in cols:
                select_parts.append(plain)
        if "streamSettings" in cols:
            select_parts.append("streamSettings")
        elif "stream_settings" in cols:
            select_parts.append("stream_settings AS streamSettings")
        q = "SELECT " + ", ".join(select_parts) + " FROM inbounds"
        rows = [dict(r) for r in conn.execute(q)]
        return rows
    finally:
        conn.close()


def json_load(value):
    if not value:
        return {}
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


DOLLAR = "$"


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
) -> str:
    blocks = []
    for shared_port in shared_ports:
        var_name = f"{DOLLAR}vpnbot_backend_{shared_port}"
        explicit_routes = passthrough_by_port.get(shared_port) or {}
        default_target = default_by_port.get(shared_port, HTTP_FRONTEND)
        lines = [
            f"map {DOLLAR}ssl_preread_server_name {var_name} {{",
            "    hostnames;",
            f"    default {default_target};",
        ]
        for domain in sorted(shared_domains):
            if domain in explicit_routes:
                continue
            lines.append(f"    {domain} {HTTP_FRONTEND};")
        for domain, backend_target in sorted(explicit_routes.items()):
            lines.append(f"    {domain} {backend_target};")
        lines.append("}")
        lines.append("")
        lines.append("server {")
        lines.append(f"    listen {shared_port} reuseport;")
        lines.append(f"    proxy_pass {var_name};")
        lines.append("    ssl_preread on;")
        lines.append("}")
        lines.append("")
        blocks.append("\n".join(lines))
    return "\n".join(blocks).rstrip() + "\n"


def write_report(lines: list[str]) -> None:
    REPORT_FILE.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    if "--explain" in sys.argv:
        print(
            "vpnbot-xui-sync-routes modes:\n"
            "  [443] or [shared:443]   publish inbound through shared TCP/443\n"
            "  [8443] or [shared:8443] publish inbound through shared TCP/8443\n"
            "  [direct]                keep inbound on its own real port\n"
            "\n"
            "Shared port behaviour:\n"
            "  tls/reality on any transport -> nginx stream SNI passthrough on the chosen external port\n"
            "  ws/grpc/http-like without tls/reality -> nginx HTTP route behind the chosen shared port\n"
            "\n"
            "Notes:\n"
            "  - if no shared marker is present, sync treats inbound as direct\n"
            "  - for reality/tls on any shared port, inbound must have serverNames / serverName set\n"
            "    unless it intentionally acts as the default no-SNI backend for that shared port\n"
            "  - xhttp/httpupgrade/splithttp are treated as HTTP-like routes when possible\n"
            "  - route sync is automatic via systemd path + timer\n"
            "  - manual sync is still available: vpnbot-xui-sync-routes\n"
            f"  - sync report: {REPORT_FILE}\n"
        )
        return 0

    ensure_dirs()
    nginx_config_before = snapshot_generated_nginx_config()
    for f in HTTP_DIR.glob("*.conf"):
        f.unlink()

    rows = load_inbounds()
    shared_domains = set()
    for host in (PANEL_DOMAIN, SHARED_HTTP_DOMAIN, APP_DOMAIN, PUBLIC_DOMAIN):
        host = str(host or "").strip()
        if host:
            shared_domains.add(host)

    shared_ports = set()
    passthrough_by_port = {}
    default_by_port = {}
    report_lines = [
        "VPnBot x-ui sync report",
        "=======================",
        "",
        f"db: {DB_PATH}",
        f"config: {CONFIG_PATH}",
        f"panel_domain: {PANEL_DOMAIN or SHARED_HTTP_DOMAIN or APP_DOMAIN or PUBLIC_DOMAIN or '<none>'}",
        f"shared_http_domain: {SHARED_HTTP_DOMAIN or APP_DOMAIN or PUBLIC_DOMAIN or '<none>'}",
        "",
    ]

    for row in rows:
        row_id = row.get("id")
        remark = str(row.get("remark") or "")
        tag = str(row.get("tag") or "")
        protocol = str(row.get("protocol") or "").lower()
        port = int(row.get("port") or 0)

        if not int(row.get("enable", 0) or 0):
            report_lines.append(f"id={row_id} skip disabled")
            continue
        if port <= 0:
            report_lines.append(f"id={row_id} skip invalid_port remark={remark!r} tag={tag!r}")
            continue
        publication = parse_publication_spec(remark + " " + tag)
        if publication["mode"] != "shared" or not publication.get("port"):
            report_lines.append(f"id={row_id} direct port={port} protocol={protocol} remark={remark!r}")
            continue
        shared_port = int(publication["port"])
        shared_ports.add(shared_port)

        stream = json_load(row.get("streamSettings"))
        network = str(stream.get("network") or "").lower()
        security = str(stream.get("security") or "").lower()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", remark or tag or f"inbound_{row.get('id')}")

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
            for domain in domains:
                register_stream_target(shared_port, domain, backend_target, passthrough_by_port, f"x-ui inbound #{row_id}")
            report_lines.append(
                f"id={row_id} shared-stream external_port={shared_port} network={network or '<none>'} security={security or '<none>'} "
                f"domains={','.join(domains)} backend_port={port} protocol={protocol} remark={remark!r}"
            )
            continue

        if security in {"tls", "reality"}:
            backend_target = f"127.0.0.1:{port}"
            register_default_stream_target(
                shared_port,
                backend_target,
                default_by_port,
                f"x-ui inbound #{row_id}",
            )
            report_lines.append(
                f"id={row_id} shared-stream-default external_port={shared_port} network={network or '<none>'} "
                f"security={security or '<none>'} backend_port={port} protocol={protocol} "
                f"reason=no_sni_domains remark={remark!r}"
            )
            continue

        if network == "ws":
            ws = stream.get("wsSettings") or {}
            path = str(ws.get("path") or "").strip() or f"/ws-{port}"
            write_http_route(safe_name, path, port, grpc=False)
            report_lines.append(f"id={row_id} shared-http external_port={shared_port} network=ws security={security or '<none>'} path={path} backend_port={port} protocol={protocol} remark={remark!r}")
            continue

        if network == "grpc":
            grpc = stream.get("grpcSettings") or {}
            service_name = str(grpc.get("serviceName") or "").strip() or f"grpc-{port}"
            write_http_route(safe_name, "/" + service_name.lstrip("/"), port, grpc=True)
            report_lines.append(f"id={row_id} shared-http external_port={shared_port} network=grpc security={security or '<none>'} service=/{service_name.lstrip('/')} backend_port={port} protocol={protocol} remark={remark!r}")
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
            report_lines.append(f"id={row_id} shared-http external_port={shared_port} network={network} security={security or '<none>'} path={path} backend_port={port} protocol={protocol} remark={remark!r}")
            continue

        report_lines.append(
            f"id={row_id} unsupported_shared_port external_port={shared_port} network={network or '<none>'} security={security or '<none>'} "
            f"backend_port={port} protocol={protocol} reason=no_sni_or_http_route remark={remark!r}"
        )

    for route in load_extra_routes():
        shared_port = int(route["shared_port"])
        backend_target = f'{route["backend_host"]}:{route["backend_port"]}'
        shared_ports.add(shared_port)
        if route.get("default"):
            register_default_stream_target(
                shared_port,
                backend_target,
                default_by_port,
                f'external route {route["route_id"]}',
            )
            report_lines.append(
                f'external route_id={route["route_id"]} external_port={shared_port} '
                f'domain=<default> backend_target={backend_target} source={route["source"]!r}'
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
                f'domain={route["domain"]} backend_target={backend_target} source={route["source"]!r}'
            )

    STREAM_MAP.write_text(build_stream_configs(sorted(shared_ports), shared_domains, passthrough_by_port, default_by_port), encoding="utf-8")
    STREAM_SERVER.write_text("# generated by vpnbot-xui-sync-routes\n", encoding="utf-8")
    write_report(report_lines)

    nginx_action = apply_nginx_config_if_needed(nginx_config_before)
    print(f"vpnbot-xui-sync-routes: nginx config regenerated successfully ({nginx_action})")
    print(f"vpnbot-xui-sync-routes: report written to {REPORT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
