#!/usr/bin/env python3
from __future__ import annotations

import http.cookiejar
import json
import os
import random
import re
import socket
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

STATE_FILE = Path(os.environ.get("XUI_INSTALLER_STATE_FILE", "/etc/vpnbot-xui-installer-state.json"))
SYNC_SCRIPT = os.environ.get("XUI_SYNC_SCRIPT", "/usr/local/bin/vpnbot-xui-sync-routes")
DEFAULT_TLS_CERT = os.environ.get("NGINX_SSL_CERT", "/etc/nginx/ssl/vpnbot/fullchain.pem")
DEFAULT_TLS_KEY = os.environ.get("NGINX_SSL_KEY", "/etc/nginx/ssl/vpnbot/privkey.pem")

REALITY_FINGERPRINT = "chrome"
PORT_MIN = 20000
PORT_MAX = 45000
def load_state() -> dict:
    if not STATE_FILE.exists():
        raise SystemExit(f"Installer state file not found: {STATE_FILE}")
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def get_public_tls_domain(state: dict) -> str:
    return str(state.get("public_domain") or "").strip().lower()


def make_opener() -> tuple[urllib.request.OpenerDirector, dict]:
    state = load_state()
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    return opener, state


def request_json(opener, state: dict, method: str, path: str, data: dict | None = None) -> dict:
    url = state["panel_base_url"].rstrip("/") + path
    body = None
    headers = {}
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    with opener.open(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def login(opener, state: dict) -> None:
    result = request_json(
        opener,
        state,
        "POST",
        "/login",
        {
            "username": state["panel_username"],
            "password": state["panel_password"],
        },
    )
    if not result.get("success"):
        raise SystemExit(f"3x-ui login failed: {result}")


def parse_json_field(value):
    if not value:
        return {}
    if isinstance(value, (dict, list)):
        return value
    return json.loads(value)


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
        if raw_obj and all(isinstance(v, dict) for v in raw_obj.values()):
            return list(raw_obj.values())
        return [raw_obj]
    return []


def list_inbounds(opener, state: dict) -> list[dict]:
    result = request_json(opener, state, "GET", "/panel/api/inbounds/list")
    rows = normalize_inbound_rows(result.get("obj"))
    for row in rows:
        for key in ("settings", "streamSettings", "sniffing"):
            try:
                row[key] = parse_json_field(row.get(key))
            except Exception:
                row[key] = {}
    return rows


def get_x25519(opener, state: dict) -> dict:
    result = request_json(opener, state, "GET", "/panel/api/server/getNewX25519Cert")
    obj = result.get("obj") or {}
    if not obj.get("privateKey") or not obj.get("publicKey"):
        raise SystemExit(f"3x-ui did not return X25519 keys: {result}")
    return obj


def add_inbound(opener, state: dict, payload: dict) -> dict:
    form = {}
    for key in ("up", "down", "total", "remark", "enable", "expiryTime", "listen", "port", "protocol"):
        form[key] = str(payload.get(key, ""))
    for key in ("settings", "streamSettings", "sniffing", "allocate"):
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            form[key] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            form[key] = str(value)
    result = request_json(opener, state, "POST", "/panel/api/inbounds/add", form)
    if not result.get("success"):
        raise SystemExit(f"3x-ui add inbound failed: {json.dumps(result, ensure_ascii=False)}")
    return result.get("obj") or {}


def update_inbound(opener, state: dict, inbound_id: int, payload: dict) -> dict:
    form = {}
    for key in ("up", "down", "total", "remark", "enable", "expiryTime", "listen", "port", "protocol"):
        form[key] = str(payload.get(key, ""))
    for key in ("settings", "streamSettings", "sniffing", "allocate"):
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            form[key] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            form[key] = str(value)
    result = request_json(opener, state, "POST", f"/panel/api/inbounds/update/{int(inbound_id)}", form)
    if not result.get("success"):
        raise SystemExit(f"3x-ui update inbound failed: {json.dumps(result, ensure_ascii=False)}")
    return result.get("obj") or {}


def ensure_clients_array_on_inbound(opener, state: dict, inbound_obj: dict, payload: dict) -> dict:
    settings = payload.get("settings")
    if not isinstance(settings, dict):
        return inbound_obj

    clients = settings.get("clients")
    if isinstance(clients, list):
        updated = dict(payload)
        updated["id"] = int(inbound_obj.get("id") or payload.get("id") or 0)
        return update_inbound(opener, state, updated["id"], updated)
    return inbound_obj


def run_sync() -> None:
    subprocess.run([SYNC_SCRIPT], check=True)


def normalize_sni(sni: str) -> str:
    return str(sni or "").strip().lower()


def slugify(text: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", str(text or "").strip().lower()).strip("-")
    return value or "route"


def parse_publication_spec(text: str) -> dict:
    m = re.search(r"\[(?P<value>direct|shared:\d+|\d+)\]", text or "", re.IGNORECASE)
    if not m:
        return {"mode": "direct", "port": None}
    raw = m.group("value").lower()
    if raw == "direct":
        return {"mode": "direct", "port": None}
    if raw.startswith("shared:"):
        return {"mode": "shared", "port": int(raw.split(":", 1)[1])}
    return {"mode": "shared", "port": int(raw)}


def has_no_flow_marker(text: str) -> bool:
    value = str(text or "").lower()
    return "no flow" in value or "no-flow" in value or "noflow" in value


def reality_server_names(primary: str) -> list[str]:
    names: list[str] = []
    for raw in [
        primary,
        *globals().get("REALITY_SERVER_NAME_POOL", []),
        *globals().get("CATALOG_REALITY_TCP_DOMAINS", []),
        *globals().get("CATALOG_REALITY_XHTTP_DOMAINS", []),
        *globals().get("XRAY_TCP_REALITY_DOMAINS", []),
    ]:
        normalized = normalize_sni(raw)
        if normalized and normalized not in names:
            names.append(normalized)
    return names or [normalize_sni(primary)]


def spec_route_sni_values(spec: dict) -> set[str]:
    if spec.get("security") == "reality":
        return set(reality_server_names(str(spec.get("domain") or "")))
    if spec.get("security") == "tls":
        normalized = normalize_sni(str(spec.get("domain") or ""))
        return {normalized} if normalized else set()
    return set()


def list_reality_sni_pool() -> list[str]:
    return reality_server_names("")


def build_reality_line_from_sni(sni: str, *, protocol: str = "vless", network: str = "tcp", no_flow: bool = False, mode: str = "direct-random") -> str:
    normalized = normalize_sni(sni)
    pool = set(list_reality_sni_pool())
    if not normalized or normalized not in pool:
        raise SystemExit(f"SNI {sni!r} не найден в общем REALITY SNI pool")
    proto = str(protocol or "vless").lower()
    net = str(network or "tcp").lower()
    if proto not in {"vless", "trojan"}:
        raise SystemExit("Для REALITY SNI pool доступны только vless и trojan")
    if net not in {"tcp", "xhttp"}:
        raise SystemExit("Для REALITY SNI pool доступны только tcp и xhttp")
    if no_flow and not (proto == "vless" and net == "tcp"):
        raise SystemExit("no-flow доступен только для VLESS TCP REALITY")
    bits = [proto, net, "raw"]
    if no_flow:
        bits.append("no-flow")
    bits.append(normalized)
    if mode == "443":
        return "443 " + " ".join(bits)
    if mode == "8443":
        return "8443 " + " ".join(bits)
    suffix = "случайный shared-порт" if mode == "shared-random" else "случайный direct-порт"
    return " ".join(bits + [suffix])


def iter_existing_actual_ports(rows: list[dict]) -> set[int]:
    return {int(row.get("port") or 0) for row in rows if isinstance(row, dict) and int(row.get("port") or 0) > 0}


def iter_existing_shared_ports(rows: list[dict]) -> set[int]:
    ports = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        publication = parse_publication_spec(f"{row.get('remark') or ''} {row.get('tag') or ''}")
        if publication["mode"] == "shared" and publication.get("port"):
            ports.add(int(publication["port"]))
    return ports


def extract_existing_route_keys(rows: list[dict]) -> dict[int, dict[str, set[str]]]:
    state: dict[int, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        publication = parse_publication_spec(f"{row.get('remark') or ''} {row.get('tag') or ''}")
        if publication["mode"] != "shared" or not publication.get("port"):
            continue
        shared_port = int(publication["port"])
        stream = row.get("streamSettings") or {}
        security = str(stream.get("security") or "").lower()
        bucket = state.setdefault(shared_port, {"sni": set(), "http_paths": set()})
        if security in {"reality", "tls"}:
            if security == "reality":
                reality = stream.get("realitySettings") or {}
                names = reality.get("serverNames") or []
                for name in names:
                    normalized = normalize_sni(name)
                    if normalized:
                        bucket["sni"].add(normalized)
            else:
                tls = stream.get("tlsSettings") or {}
                for candidate in list(tls.get("serverNames") or []) + [tls.get("serverName"), (tls.get("settings") or {}).get("serverName")]:
                    normalized = normalize_sni(candidate)
                    if normalized:
                        bucket["sni"].add(normalized)
        else:
            network = str(stream.get("network") or "").lower()
            route_path = None
            if network == "ws":
                route_path = str((stream.get("wsSettings") or {}).get("path") or "").strip()
            elif network == "grpc":
                service = str((stream.get("grpcSettings") or {}).get("serviceName") or "").strip()
                route_path = "/" + service.lstrip("/") if service else ""
            elif network in {"xhttp", "httpupgrade", "splithttp"}:
                for key in ("xhttpSettings", "httpupgradeSettings", "splitHTTPSettings"):
                    route_path = str((stream.get(key) or {}).get("path") or "").strip()
                    if route_path:
                        break
            if route_path:
                bucket["http_paths"].add(route_path)
    return state


def choose_random_port(inbounds: list[dict], *, forbidden: set[int] | None = None) -> int:
    used = {int(row.get("port") or 0) for row in inbounds if int(row.get("port") or 0) > 0}
    used.update(forbidden or set())
    for _ in range(1000):
        port = random.randint(PORT_MIN, PORT_MAX)
        if port not in used:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("0.0.0.0", port))
            except OSError:
                sock.close()
                continue
            sock.close()
            return port
    raise SystemExit("Could not find a free random port in the configured range")


def require_fixed_port(inbounds: list[dict], port: int) -> int:
    used = {int(row.get("port") or 0) for row in inbounds if int(row.get("port") or 0) > 0}
    if port in used:
        raise SystemExit(f"Required fixed port {port} is already occupied by another inbound")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", int(port)))
    except OSError:
        sock.close()
        raise SystemExit(f"Required fixed port {port} is already occupied by another local service")
    sock.close()
    return port


def build_reality_settings(opener, state: dict, sni: str) -> dict:
    cert = get_x25519(opener, state)
    short_id = "".join(random.choice("0123456789abcdef") for _ in range(16))
    server_names = reality_server_names(sni)
    return {
        "show": False,
        "xver": 0,
        "dest": f"{sni}:443",
        "serverNames": server_names,
        "privateKey": cert["privateKey"],
        "minClient": "",
        "maxClient": "",
        "maxTimediff": 0,
        "shortIds": [short_id],
        "settings": {
            "publicKey": cert["publicKey"],
            "fingerprint": REALITY_FINGERPRINT,
            "serverName": "",
            "spiderX": "/",
        },
    }


def build_sniffing(enabled: bool) -> dict:
    return {
        "enabled": enabled,
        "destOverride": ["http", "tls", "quic", "fakedns"],
        "metadataOnly": False,
        "routeOnly": bool(enabled),
    }


def parse_custom_spec_line(line: str) -> dict:
    original = line.strip()
    if not original:
        raise SystemExit("Пустую строку inbound'а разобрать нельзя")

    tokens = original.split()
    lower_tokens = [token.lower() for token in tokens]
    spec = {
        "source": original,
        "protocol": "vless",
        "network": None,
        "security": None,
        "preferred_port": None,
        "domain": None,
        "any_port": False,
        "no_flow": False,
    }

    if tokens and tokens[0].isdigit():
        spec["preferred_port"] = int(tokens[0])
        tokens = tokens[1:]
        lower_tokens = lower_tokens[1:]

    joined = " ".join(lower_tokens)
    if "любой порт" in joined or "any port" in joined:
        spec["any_port"] = True
    if "случайный direct-порт" in joined or "random direct" in joined:
        spec["any_port"] = True
        spec["publication"] = "direct-random"
    if "случайный shared-порт" in joined or "random shared" in joined:
        spec["any_port"] = True
        spec["publication"] = "shared-random"
    if "no flow" in joined or "no-flow" in joined or "noflow" in joined:
        spec["no_flow"] = True

    for token in tokens:
        low = token.lower()
        if low in {"vless", "vmess", "trojan"}:
            spec["protocol"] = low
        elif low in {"tcp", "grpc", "xhttp", "ws", "httpupgrade", "splithttp"}:
            spec["network"] = low
        elif low in {"raw", "reality"}:
            spec["security"] = "reality"
        elif low in {"tls", "none"}:
            spec["security"] = low
        elif low in {"no-flow", "noflow", "no_flow"}:
            spec["no_flow"] = True
        elif token.isdigit() and spec["preferred_port"] is None:
            spec["preferred_port"] = int(token)
        elif "." in token and not token.startswith("["):
            spec["domain"] = token.lower()

    if not spec["network"]:
        raise SystemExit(f"Не удалось понять транспорт в строке: {original}")

    if spec["security"] is None:
        if spec["domain"] and spec["network"] in {"tcp", "xhttp", "grpc"}:
            spec["security"] = "reality"
        else:
            spec["security"] = "none"

    if spec["preferred_port"] is None and not spec["any_port"]:
        spec["any_port"] = True

    if spec["security"] in {"reality", "tls"} and not spec["domain"]:
        raise SystemExit(f"Для reality/tls нужен домен/SNI в строке: {original}")

    return spec


def custom_http_path(spec: dict) -> str:
    if str(spec.get("network") or "").lower() == "xhttp":
        return "/"
    base = slugify(spec["domain"] or f"{spec['protocol']}-{spec['network']}")
    return f"/{base}-{spec['network']}"


def choose_backend_port(rows: list[dict], occupied_actual_ports: set[int], occupied_shared_ports: set[int], state: dict) -> int:
    forbidden = set(occupied_actual_ports) | set(occupied_shared_ports)
    forbidden.update({int(state["panel_port"]), int(state["http_frontend_local_port"])})
    return choose_random_port(rows, forbidden=forbidden)


def assign_and_validate_custom_specs(specs: list[dict], rows: list[dict], state: dict) -> list[dict]:
    occupied_actual_ports = set(iter_existing_actual_ports(rows))
    occupied_shared_ports = set(iter_existing_shared_ports(rows))
    existing_routes = extract_existing_route_keys(rows)
    new_routes: dict[int, dict[str, set[str]]] = {}
    preferred_counts: dict[int, int] = {}

    for spec in specs:
        preferred = spec.get("preferred_port")
        if preferred is None:
            continue
        preferred_counts[int(preferred)] = preferred_counts.get(int(preferred), 0) + 1

    for spec in specs:
        spec.setdefault("resolution_notes", [])
        preferred_port = spec.get("preferred_port")
        if preferred_port is not None:
            preferred_port = int(preferred_port)
            wants_shared = (
                preferred_counts.get(preferred_port, 0) > 1
                or preferred_port in occupied_shared_ports
            )

            if wants_shared:
                shared_port = preferred_port
                spec["mode"] = "shared"

                def route_conflict(candidate_port: int) -> bool:
                    route_bucket = existing_routes.setdefault(candidate_port, {"sni": set(), "http_paths": set()})
                    pending_bucket = new_routes.setdefault(candidate_port, {"sni": set(), "http_paths": set()})
                    if spec["security"] in {"reality", "tls"}:
                        sni_values = spec_route_sni_values(spec)
                        return bool(sni_values & route_bucket["sni"] or sni_values & pending_bucket["sni"])
                    path = custom_http_path(spec)
                    return path in route_bucket["http_paths"] or path in pending_bucket["http_paths"]

                if shared_port in occupied_actual_ports or route_conflict(shared_port):
                    replacement = choose_backend_port(rows, occupied_actual_ports, occupied_shared_ports, state)
                    if shared_port in occupied_actual_ports:
                        spec["resolution_notes"].append(
                            f"желаемый порт {preferred_port} пришлось перевести в shared и перенести на {replacement}, потому что реальный порт уже был занят"
                        )
                    else:
                        spec["resolution_notes"].append(
                            f"на shared-порту {preferred_port} уже был конфликт маршрута, назначен {replacement}"
                        )
                    shared_port = replacement
                elif preferred_counts.get(preferred_port, 0) > 1:
                    spec["resolution_notes"].append(
                        f"порт {preferred_port} выбран несколькими inbound'ами, поэтому они будут опубликованы как shared на одном внешнем порту"
                    )

                spec["external_port"] = shared_port
                route_bucket = existing_routes.setdefault(shared_port, {"sni": set(), "http_paths": set()})
                pending_bucket = new_routes.setdefault(shared_port, {"sni": set(), "http_paths": set()})
                if spec["security"] in {"reality", "tls"}:
                    pending_bucket["sni"].update(spec_route_sni_values(spec))
                else:
                    path = custom_http_path(spec)
                    spec["http_path"] = path
                    pending_bucket["http_paths"].add(path)
                backend_port = choose_backend_port(rows, occupied_actual_ports, occupied_shared_ports, state)
                spec["listen_port"] = backend_port
                occupied_actual_ports.add(backend_port)
                occupied_shared_ports.add(shared_port)
                continue

        spec["mode"] = "direct"
        if preferred_port is not None:
            direct_port = int(preferred_port)
            if direct_port in occupied_actual_ports or direct_port in occupied_shared_ports:
                replacement = choose_backend_port(rows, occupied_actual_ports, occupied_shared_ports, state)
                spec["resolution_notes"].append(
                    f"желаемый direct-порт {direct_port} был занят, назначен {replacement}"
                )
                direct_port = replacement
            else:
                spec["resolution_notes"].append(
                    f"порт {direct_port} используется только одним inbound'ом, поэтому он будет опубликован как direct"
                )
        else:
            direct_port = choose_backend_port(rows, occupied_actual_ports, occupied_shared_ports, state)
            spec["resolution_notes"].append(
                f"порт не был задан явно, назначен свободный direct-порт {direct_port}"
            )
        spec["listen_port"] = direct_port
        occupied_actual_ports.add(direct_port)

    return specs


def build_payload_from_custom_spec(opener, state: dict, spec: dict) -> tuple[dict | None, str]:
    protocol = spec["protocol"]
    network = spec["network"]
    security = spec["security"]
    domain = spec.get("domain") or ""
    listen_port = int(spec["listen_port"])
    public_tls_domain = get_public_tls_domain(state)

    if security == "tls" and public_tls_domain and domain and domain != public_tls_domain:
        raise SystemExit(
            "Для TLS-inbound install_vray.sh сейчас использует сертификат, выпущенный на "
            f"{public_tls_domain}. Поэтому в строке каталога для TLS укажи именно этот домен, "
            "либо сначала подготовь другой сертификат вручную."
        )

    existing = match_existing(
        list_inbounds(opener, state),
        protocol=protocol,
        network=network,
        security=security,
        sni=domain if security in {"reality", "tls"} else "",
        port=listen_port if spec["mode"] == "direct" else None,
        no_flow=bool(spec.get("no_flow")) if protocol == "vless" and network == "tcp" and security == "reality" else None,
    )
    if existing:
        return None, f"reuse existing {protocol} {network} {security} for {domain or listen_port} (inbound #{existing.get('id')})"

    remark_bits = []
    if spec["mode"] == "shared":
        remark_bits.append(f"[shared:{spec['external_port']}]")
    else:
        remark_bits.append("[direct]")
    remark_bits.extend([protocol, network, security])
    if spec.get("no_flow"):
        remark_bits.append("no-flow")
    if domain:
        remark_bits.append(domain)
    remark = " ".join(remark_bits)

    if protocol == "vless":
        settings = {"clients": [], "decryption": "none", "fallbacks": []}
    elif protocol == "trojan":
        settings = {"clients": [], "fallbacks": []}
    elif protocol == "vmess":
        settings = {"clients": []}
    else:
        raise SystemExit(f"Неподдерживаемый протокол: {protocol}")

    stream = {
        "network": network,
        "security": security,
        "externalProxy": [],
    }

    if security == "reality":
        stream["realitySettings"] = build_reality_settings(opener, state, domain)
    elif security == "tls":
        stream["tlsSettings"] = {
            "serverName": domain,
            "alpn": ["h2", "http/1.1"] if network == "grpc" else ["http/1.1"],
            "minVersion": "1.2",
            "maxVersion": "1.3",
            "cipherSuites": "",
            "rejectUnknownSni": False,
            "disableSystemRoot": False,
            "enableSessionResumption": False,
            "certificates": [
                {
                    "certificateFile": DEFAULT_TLS_CERT,
                    "keyFile": DEFAULT_TLS_KEY,
                    "ocspStapling": 3600,
                    "usage": "encipherment",
                }
            ],
            "settings": {
                "allowInsecure": False,
                "fingerprint": REALITY_FINGERPRINT,
                "serverName": domain,
            },
        }

    if network == "tcp":
        stream["tcpSettings"] = {"acceptProxyProtocol": False, "header": {"type": "none"}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": slugify(domain or f"{protocol}-grpc")}
    elif network == "xhttp":
        stream["xhttpSettings"] = {
            "path": custom_http_path(spec),
            "host": "",
            "headers": {},
            "scMaxBufferedPosts": 30,
            "scMaxEachPostBytes": "1000000",
            "noSSEHeader": False,
            "xPaddingBytes": "100-1000",
            "mode": "auto",
        }
    elif network == "ws":
        stream["wsSettings"] = {"path": custom_http_path(spec), "headers": {}}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": custom_http_path(spec), "host": ""}
    elif network == "splithttp":
        stream["splitHTTPSettings"] = {"path": custom_http_path(spec), "host": ""}
    else:
        raise SystemExit(f"Неподдерживаемый транспорт: {network}")

    payload = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark,
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": listen_port,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
        "sniffing": build_sniffing(security != "reality"),
    }

    human_mode = f"shared port {spec['external_port']}" if spec["mode"] == "shared" else f"direct port {listen_port}"
    human_target = f", target={domain}:443" if domain and security == "reality" else ""
    return payload, f"create {protocol} {network} {security} on {human_mode} backend_port={listen_port}" + (f", sni={domain}{human_target}" if domain else "")


def collect_custom_specs_from_input() -> list[dict]:
    print("Введи inbound'ы по одному на строку. Пустая строка завершает ввод.")
    print("Примеры:")
    print("  443 tcp raw web.max.ru")
    print("  443 xhttp sosok.vk.com")
    print("  vless grpc Reality www.nvidia.com любой порт")
    lines = []
    while True:
        line = input("> ").strip()
        if not line:
            break
        lines.append(line)
    if not lines:
        raise SystemExit("Не получено ни одной строки inbound'ов")
    return [parse_custom_spec_line(line) for line in lines]


def match_existing(
    rows: list[dict],
    *,
    protocol: str,
    network: str,
    security: str,
    sni: str = "",
    port: int | None = None,
    no_flow: bool | None = None,
) -> dict | None:
    wanted_sni = normalize_sni(sni)
    for row in rows:
        if not isinstance(row, dict):
            continue
        if no_flow is not None:
            marker_text = f"{row.get('remark') or ''} {row.get('tag') or ''}"
            if has_no_flow_marker(marker_text) != bool(no_flow):
                continue
        if str(row.get("protocol") or "").lower() != protocol:
            continue
        row_port = int(row.get("port") or 0)
        if port is not None and row_port != int(port):
            continue
        stream = row.get("streamSettings") or {}
        row_network = str(stream.get("network") or "").lower()
        row_security = str(stream.get("security") or "").lower()
        if row_network != network or row_security != security:
            continue
        if not wanted_sni:
            return row
        if security == "reality":
            reality = stream.get("realitySettings") or {}
            sni_values = {normalize_sni(x) for x in (reality.get("serverNames") or []) if str(x).strip()}
        elif security == "tls":
            tls = stream.get("tlsSettings") or {}
            sni_values = set()
            value = str(tls.get("serverName") or "").strip()
            if value:
                sni_values.add(normalize_sni(value))
            nested = tls.get("settings") or {}
            nested_value = str(nested.get("serverName") or "").strip()
            if nested_value:
                sni_values.add(normalize_sni(nested_value))
        else:
            sni_values = set()
        if wanted_sni in sni_values:
            return row
    return None


def make_payload_vless_xhttp_shared(opener, state: dict, rows: list[dict]) -> tuple[dict | None, str]:
    sni = "www.amd.com"
    existing = match_existing(rows, protocol="vless", network="xhttp", security="reality", sni=sni)
    if existing:
        return None, f"reuse existing VLESS XHTTP REALITY for {sni} (inbound #{existing.get('id')}, backend port {existing.get('port')}, external shared port 443)"
    port = choose_random_port(rows, forbidden={443, int(state["panel_port"]), int(state["http_frontend_local_port"])})
    payload = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": "[443] vless xhttp amd",
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none", "fallbacks": []},
        "streamSettings": {
            "network": "xhttp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": build_reality_settings(opener, state, sni),
            "xhttpSettings": {
                "path": "/",
                "host": "",
                "headers": {},
                "scMaxBufferedPosts": 30,
                "scMaxEachPostBytes": "1000000",
                "noSSEHeader": False,
                "xPaddingBytes": "100-1000",
                "mode": "auto",
            },
        },
        "sniffing": build_sniffing(False),
    }
    return payload, f"create VLESS XHTTP REALITY shared port 443 via SNI {sni} (backend port {port}, target {sni}:443)"


def make_payload_vmess_tls_direct(rows: list[dict], state: dict) -> tuple[dict | None, str]:
    tls_domain = get_public_tls_domain(state)
    existing = match_existing(
        rows,
        protocol="vmess",
        network="tcp",
        security="tls",
        sni=tls_domain,
        port=8443,
    )
    if existing:
        return None, "reuse existing VMESS TCP TLS on direct port 8443"
    try:
        port = require_fixed_port(rows, 8443)
        chosen_note = "create VMESS TCP TLS on direct port 8443"
    except SystemExit:
        port = choose_random_port(
            rows,
            forbidden={443, 8443, int(state["panel_port"]), int(state["http_frontend_local_port"])},
        )
        chosen_note = f"create VMESS TCP TLS on direct port {port} (8443 was busy)"
    tls_alpn = ["h2", "http/1.1"] if tls_domain else ["http/1.1"]
    remark = " ".join(part for part in ("[direct]", "vmess", "tcp", "tls", tls_domain or "selfsigned") if part)
    payload = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark,
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": "vmess",
        "settings": {"clients": []},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "externalProxy": [],
            "tlsSettings": {
                "serverName": tls_domain,
                "alpn": tls_alpn,
                "minVersion": "1.2",
                "maxVersion": "1.3",
                "cipherSuites": "",
                "rejectUnknownSni": False,
                "disableSystemRoot": False,
                "enableSessionResumption": False,
                "certificates": [
                    {
                        "certificateFile": DEFAULT_TLS_CERT,
                        "keyFile": DEFAULT_TLS_KEY,
                        "ocspStapling": 3600,
                        "usage": "encipherment",
                    }
                ],
                "settings": {
                    "allowInsecure": False,
                    "fingerprint": REALITY_FINGERPRINT,
                    "serverName": tls_domain,
                },
            },
            "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
        },
        "sniffing": build_sniffing(True),
    }
    if tls_domain:
        return payload, f"{chosen_note} with installer certificate for {tls_domain}"
    return payload, f"{chosen_note} with self-signed certificate"


def make_payload_trojan_tcp_reality(rows: list[dict], opener, state: dict) -> tuple[dict | None, str]:
    sni = "www.oracle.com"
    existing = match_existing(rows, protocol="trojan", network="tcp", security="reality", sni=sni)
    if existing:
        return None, f"reuse existing TROJAN TCP REALITY for {sni} (inbound #{existing.get('id')}, port {existing.get('port')})"
    port = choose_random_port(rows, forbidden={443, 8443, int(state["panel_port"]), int(state["http_frontend_local_port"])})
    payload = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": "trojan raw oracle",
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": "trojan",
        "settings": {"clients": [], "fallbacks": []},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": build_reality_settings(opener, state, sni),
            "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
        },
        "sniffing": build_sniffing(True),
    }
    return payload, f"create TROJAN TCP REALITY on direct port {port} with SNI/target {sni}"


def make_payload_vless_tcp_reality(rows: list[dict], opener, state: dict) -> tuple[dict | None, str]:
    sni = "www.amd.com"
    existing = match_existing(rows, protocol="vless", network="tcp", security="reality", sni=sni)
    if existing:
        return None, f"reuse existing VLESS TCP REALITY for {sni} (inbound #{existing.get('id')}, port {existing.get('port')})"
    port = choose_random_port(rows, forbidden={443, 8443, int(state["panel_port"]), int(state["http_frontend_local_port"])})
    payload = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": "vless raw amd",
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none", "fallbacks": []},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": build_reality_settings(opener, state, sni),
            "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
        },
        "sniffing": build_sniffing(True),
    }
    return payload, f"create VLESS TCP REALITY on direct port {port} with SNI/target {sni}"


CATALOG_REALITY_XHTTP_DOMAINS = [
    "www.yandex.ru",
    "rutube.ru",
    "www.wildberries.ru",
    "www.hp.com",
    "www.sberbank.ru",
    "www.intel.com",
    "www.avito.ru",
    "www.ozon.ru",
    "www.gosuslugi.ru",
    "vk.com",
]

CATALOG_REALITY_TCP_DOMAINS = [
    "www.yandex.ru",
    "rutube.ru",
    "www.wildberries.ru",
    "www.hp.com",
    "www.sberbank.ru",
    "www.intel.com",
    "www.avito.ru",
    "www.ozon.ru",
    "www.gosuslugi.ru",
    "vk.com",
]


SNI_POOL_FILE = Path(os.environ.get("VPNBOT_REALITY_SNI_POOL_FILE", "/usr/local/share/vpnbot/reality_sni_pool.json"))


def load_reality_server_name_pool() -> list[str]:
    try:
        payload = json.loads(SNI_POOL_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except Exception:
        return []
    if isinstance(payload, dict):
        payload = payload.get("serverNames") or payload.get("sni") or payload.get("items") or []
    if not isinstance(payload, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for item in payload:
        value = str(item or "").strip().lower()
        if value and value not in seen:
            result.append(value)
            seen.add(value)
    return result


REALITY_SERVER_NAME_POOL = load_reality_server_name_pool()


def build_catalog_group(title: str, entries: list[tuple[str, str, str]]) -> dict:
    return {
        "title": title,
        "items": [
            {"id": spec_id, "title": entry_title, "line": line}
            for spec_id, entry_title, line in entries
        ],
    }


def build_catalog_groups(state: dict) -> list[dict]:
    tls_domain = get_public_tls_domain(state)
    if not tls_domain:
        tls_domain = "www.amd.com"

    reality_tcp_items = []
    for domain in CATALOG_REALITY_TCP_DOMAINS:
        slug = slugify(domain)
        reality_tcp_items.append((f"catalog_vless_tcp_{slug}", f"443 vless tcp raw {domain}", f"443 vless tcp raw {domain}"))
        reality_tcp_items.append((f"catalog_vless_tcp_noflow_{slug}", f"443 vless tcp raw no-flow {domain}", f"443 vless tcp raw no-flow {domain}"))
        reality_tcp_items.append((f"catalog_trojan_tcp_{slug}", f"443 trojan tcp raw {domain}", f"443 trojan tcp raw {domain}"))

    reality_xhttp_items = []
    for domain in CATALOG_REALITY_XHTTP_DOMAINS:
        slug = slugify(domain)
        reality_xhttp_items.append((f"catalog_vless_xhttp_{slug}", f"443 vless xhttp raw {domain}", f"443 vless xhttp raw {domain}"))
        reality_xhttp_items.append((f"catalog_trojan_xhttp_{slug}", f"443 trojan xhttp raw {domain}", f"443 trojan xhttp raw {domain}"))

    tls_items = [
        ("catalog_vmess_tls_8443", f"8443 vmess tcp tls {tls_domain}", f"8443 vmess tcp tls {tls_domain}"),
        ("catalog_vless_tls_public", f"любой порт vless tcp tls {tls_domain}", f"vless tcp tls {tls_domain} любой порт"),
        ("catalog_trojan_tls_public", f"любой порт trojan tcp tls {tls_domain}", f"trojan tcp tls {tls_domain} любой порт"),
        ("catalog_vless_xhttp_tls_public", f"любой порт vless xhttp tls {tls_domain}", f"vless xhttp tls {tls_domain} любой порт"),
        ("catalog_trojan_xhttp_tls_public", f"любой порт trojan xhttp tls {tls_domain}", f"trojan xhttp tls {tls_domain} любой порт"),
        ("catalog_vmess_xhttp_tls_public", f"любой порт vmess xhttp tls {tls_domain}", f"vmess xhttp tls {tls_domain} любой порт"),
    ]

    return [
        build_catalog_group("Reality TCP", reality_tcp_items),
        build_catalog_group("Reality XHTTP", reality_xhttp_items),
        build_catalog_group("TLS", tls_items),
    ]


def apply_custom_specs(specs: list[dict]) -> int:
    opener, state = make_opener()
    login(opener, state)
    rows = list_inbounds(opener, state)
    prepared = assign_and_validate_custom_specs(specs, rows, state)
    created = []
    notes = []
    for spec in prepared:
        payload, note = build_payload_from_custom_spec(opener, state, spec)
        notes.append(note)
        if payload is None:
            continue
        obj = add_inbound(opener, state, payload)
        obj = ensure_clients_array_on_inbound(opener, state, obj, payload)
        obj["streamSettings"] = parse_json_field(obj.get("streamSettings"))
        created.append(obj)
        rows.append(obj)
    run_sync()
    print("VPnBot x-ui catalog result")
    print("==========================")
    for note in notes:
        print(f"- {note}")
    for spec in prepared:
        for resolution_note in spec.get("resolution_notes", []):
            print(f"- auto-resolve: {resolution_note}")
    if created:
        print("")
        print("Созданные inbound'ы:")
        for obj in created:
            stream = obj.get("streamSettings") or {}
            network = str(stream.get("network") or "").lower()
            security = str(stream.get("security") or "").lower()
            remark = str(obj.get("remark") or "")
            publication = parse_publication_spec(remark)
            if publication["mode"] == "shared" and publication.get("port"):
                mode = f"shared {publication['port']}"
            else:
                mode = "direct"
            extra = ""
            if security == "reality":
                reality = stream.get("realitySettings") or {}
                names = reality.get("serverNames") or []
                if names:
                    extra = f", sni={','.join(names)}, target={reality.get('dest')}"
            print(f"  • #{obj.get('id')} {obj.get('protocol')} {network}/{security or 'none'} port={obj.get('port')} mode={mode}{extra}")
    else:
        print("")
        print("Новых inbound'ов не понадобилось: подходящие уже существовали.")
    return 0


def print_reality_sni_pool() -> int:
    for idx, name in enumerate(list_reality_sni_pool(), 1):
        print(f"{idx}. {name}")
    return 0


def prompt_reality_line_from_sni() -> str:
    pool = list_reality_sni_pool()
    print("")
    print("Полный REALITY SNI pool:")
    for idx, name in enumerate(pool, 1):
        print(f"  {idx}. {name}")
    raw = input("Выбери номер SNI или введи домен из списка: ").strip()
    if not raw:
        return ""
    if raw.isdigit():
        idx = int(raw)
        if idx < 1 or idx > len(pool):
            raise SystemExit(f"SNI пункта {idx} нет")
        sni = pool[idx - 1]
    else:
        sni = normalize_sni(raw)
    protocol = input("Протокол [vless/trojan, default vless]: ").strip().lower() or "vless"
    network = input("Транспорт [tcp/xhttp, default tcp]: ").strip().lower() or "tcp"
    no_flow = False
    if protocol == "vless" and network == "tcp":
        no_flow = (input("VLESS TCP REALITY no-flow? [y/N]: ").strip().lower() in {"y", "yes", "1", "true", "да", "д"})
    mode = input("Публикация [direct-random/shared-random/443/8443, default direct-random]: ").strip().lower() or "direct-random"
    line = build_reality_line_from_sni(sni, protocol=protocol, network=network, no_flow=no_flow, mode=mode)
    print(f"Будет создана строка: {line}")
    return line


def menu() -> int:
    opener, state = make_opener()
    login(opener, state)
    catalog_groups = build_catalog_groups(state)
    options = []
    print("Выбери inbound'ы для 3x-ui:")
    for group in catalog_groups:
        print("")
        print(f"[{group['title']}]")
        for item in group["items"]:
            options.append(item)
            print(f"  {len(options)}. {item['title']}")
    print("")
    print("  s. выбрать dest/SNI из полного REALITY SNI pool")
    print("")
    raw = input("Номера или диапазоны через пробел, s = полный SNI pool, Enter = ничего не создавать: ").strip()
    if not raw:
        print("Пропускаю создание inbound'ов.")
        return 0
    if raw.lower() in {"s", "sni", "pool"}:
        line = prompt_reality_line_from_sni()
        if not line:
            print("Пропускаю создание inbound'ов.")
            return 0
        return apply_custom_specs([parse_custom_spec_line(line)])
    tokens = raw.replace(",", " ").split()
    indexes = []
    for token in tokens:
        if "-" in token:
            left, sep, right = token.partition("-")
            if not sep or not left or not right:
                raise SystemExit("Диапазон нужно писать в виде 1-4")
            try:
                start = int(left)
                end = int(right)
            except ValueError:
                raise SystemExit("Диапазоны должны состоять только из номеров пунктов")
            if start > end:
                raise SystemExit("В диапазоне левая граница должна быть меньше или равна правой")
            values = range(start, end + 1)
        else:
            try:
                values = [int(token)]
            except ValueError:
                raise SystemExit("Нужно ввести один или несколько номеров или диапазонов через пробел")

        for idx in values:
            if idx < 1 or idx > len(options):
                raise SystemExit(f"Пункта {idx} в меню нет")
            if idx not in indexes:
                indexes.append(idx)

    custom_specs = []
    for idx in indexes:
        line = options[idx - 1]["line"]
        if line not in custom_specs:
            custom_specs.append(line)
    specs = [parse_custom_spec_line(line) for line in custom_specs]
    return apply_custom_specs(specs)


def main(argv: list[str]) -> int:
    if len(argv) == 1:
        return menu()
    if argv[1] == "--list-sni":
        return print_reality_sni_pool()
    if argv[1] == "--line-from-sni":
        if len(argv) < 3:
            raise SystemExit("Usage: vpnbot-xui-presets --line-from-sni <sni> [vless|trojan] [tcp|xhttp] [direct-random|shared-random|443|8443] [--no-flow]")
        protocol = argv[3] if len(argv) > 3 and not argv[3].startswith("--") else "vless"
        network = argv[4] if len(argv) > 4 and not argv[4].startswith("--") else "tcp"
        mode = argv[5] if len(argv) > 5 and not argv[5].startswith("--") else "direct-random"
        print(build_reality_line_from_sni(argv[2], protocol=protocol, network=network, no_flow="--no-flow" in argv[3:], mode=mode))
        return 0
    if argv[1] == "--catalog-json":
        opener, state = make_opener()
        login(opener, state)
        print(json.dumps(build_catalog_groups(state), ensure_ascii=False, indent=2))
        return 0
    if argv[1] == "--apply-lines-json":
        if len(argv) < 3:
            raise SystemExit("Usage: vpnbot-xui-presets --apply-lines-json <file>")
        payload = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise SystemExit("Expected JSON array of catalog lines")
        custom_specs = []
        for line in payload:
            if not isinstance(line, str):
                continue
            text = line.strip()
            if text and text not in custom_specs:
                custom_specs.append(text)
        specs = [parse_custom_spec_line(line) for line in custom_specs]
        return apply_custom_specs(specs)
    if argv[1] == "--list":
        opener, state = make_opener()
        login(opener, state)
        for group in build_catalog_groups(state):
            print(group["title"] + ":")
            for item in group["items"]:
                print(f"  {item['title']}")
            print("")
        return 0
    raise SystemExit("Использование: vpnbot-xui-presets [--list]")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
