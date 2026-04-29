#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

BACKEND_MODE = os.environ.get("VPNBOT_VLESS_BACKEND", "3x-ui")
LEGACY_XUI_HELPER = os.environ.get("XUI_PRESET_HELPER", "/usr/local/bin/vpnbot-xui-presets")
XRAY_STATE_FILE = Path(os.environ.get("XRAY_CORE_INSTALLER_STATE_FILE", "/etc/vpnbot-xray-installer-state.json"))
XRAY_BIN = os.environ.get("XRAY_CORE_BIN", "/opt/vpnbot/xray-core/bin/xray")
XRAY_CONFDIR = Path(os.environ.get("XRAY_CORE_CONFIG_DIR", "/opt/vpnbot/xray-core/config"))
XRAY_ASSET_DIR = Path(os.environ.get("XRAY_CORE_SHARE_DIR", "/opt/vpnbot/xray-core/share"))
XRAY_MANAGED_INBOUNDS_FILE = Path(os.environ.get("XRAY_CORE_MANAGED_INBOUNDS_FILE", "/opt/vpnbot/xray-core/config/50_vpnbot_managed_inbounds.json"))
XRAY_SERVICE_NAME = os.environ.get("XRAY_CORE_SERVICE_NAME", "vpnbot-xray.service")
XRAY_SYNC_SCRIPT = os.environ.get("XRAY_SYNC_SCRIPT", "/usr/local/bin/vpnbot-xray-sync-routes")
XRAY_RESERVED_PORTS_SYSCTL_FILE = Path(os.environ.get("VPNBOT_XRAY_RESERVED_PORTS_SYSCTL_FILE", "/etc/sysctl.d/99-vpnbot-xray-reserved-ports.conf"))
XRAY_RESERVED_EXTRA_PORTS = os.environ.get("VPNBOT_XRAY_RESERVED_EXTRA_PORTS", "10086")
DEFAULT_TLS_CERT = os.environ.get("NGINX_SSL_CERT", "/etc/nginx/ssl/vpnbot/fullchain.pem")
DEFAULT_TLS_KEY = os.environ.get("NGINX_SSL_KEY", "/etc/nginx/ssl/vpnbot/privkey.pem")
PORT_MIN = 20000
PORT_MAX = 45000
REALITY_FINGERPRINT = "chrome"
XRAY_TCP_REALITY_DOMAINS = [
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
XRAY_PROTOCOL_LABELS = [
    ("vless", "VLESS"),
    ("vmess", "VMESS"),
    ("trojan", "TROJAN"),
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

MARK_RE = re.compile(r"\[(?P<value>direct|shared:\d+|\d+)\]", re.IGNORECASE)


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


def slugify(text: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", str(text or "").strip().lower()).strip("-")
    return value or "route"


def normalize_sni(value: str) -> str:
    return str(value or "").strip().lower()


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
        "publication": None,
    }

    if tokens and tokens[0].isdigit():
        spec["preferred_port"] = int(tokens[0])
        tokens = tokens[1:]
        lower_tokens = lower_tokens[1:]

    joined = " ".join(lower_tokens)
    if "любой порт" in joined or "any port" in joined:
        spec["any_port"] = True
    if (
        "случайный shared-порт" in joined
        or "случайный shared порт" in joined
        or "shared-random" in joined
        or "random-shared" in joined
    ):
        spec["publication"] = "shared-random"
    elif (
        "случайный direct-порт" in joined
        or "случайный direct порт" in joined
        or "direct-random" in joined
        or "random-direct" in joined
    ):
        spec["publication"] = "direct-random"
    if "no flow" in joined or "no-flow" in joined or "noflow" in joined:
        spec["no_flow"] = True

    for token in tokens:
        low = token.lower()
        if low in {"vless", "vmess", "trojan"}:
            spec["protocol"] = low
        elif low in {"tcp", "ws", "grpc", "xhttp"}:
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
        spec["security"] = "reality" if spec["domain"] and spec["network"] in {"tcp", "xhttp"} else "none"

    if spec["preferred_port"] is None and not spec["any_port"]:
        spec["any_port"] = True

    if spec["security"] in {"reality", "tls"} and not spec["domain"]:
        raise SystemExit(f"Для reality/tls нужен домен/SNI в строке: {original}")

    return spec


def load_xray_state() -> dict:
    if not XRAY_STATE_FILE.exists():
        return {}
    try:
        payload = json.loads(XRAY_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def get_public_tls_domain(state: dict) -> str:
    return str(state.get("public_domain") or state.get("app_domain") or "").strip().lower()


def parse_publication_spec(text: str) -> dict:
    m = MARK_RE.search(text or "")
    if not m:
        return {"mode": "direct", "port": None}
    raw = m.group("value").lower()
    if raw == "direct":
        return {"mode": "direct", "port": None}
    if raw.startswith("shared:"):
        return {"mode": "shared", "port": int(raw.split(":", 1)[1])}
    return {"mode": "shared", "port": int(raw)}


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


def load_xray_inbounds() -> tuple[dict, list[dict]]:
    if not XRAY_MANAGED_INBOUNDS_FILE.exists():
        payload = {"inbounds": []}
        return payload, []
    try:
        payload = json.loads(XRAY_MANAGED_INBOUNDS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Не удалось прочитать managed inbounds file {XRAY_MANAGED_INBOUNDS_FILE}: {exc}") from exc
    if not isinstance(payload, dict):
        payload = {"inbounds": []}
    rows = normalize_inbound_rows(payload.get("inbounds"))
    return payload, rows


def save_xray_inbounds(rows: list[dict]) -> None:
    payload = {"inbounds": rows}
    XRAY_MANAGED_INBOUNDS_FILE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


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


def sync_xray_reserved_ports(rows: list[dict]) -> None:
    ports: set[int] = parse_reserved_ports(XRAY_RESERVED_EXTRA_PORTS)
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port") or 0)
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    if not ports:
        return

    XRAY_RESERVED_PORTS_SYSCTL_FILE.parent.mkdir(parents=True, exist_ok=True)
    XRAY_RESERVED_PORTS_SYSCTL_FILE.write_text(
        "# VPnBot standalone Xray-core managed inbound/control ports.\n"
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
        raise SystemExit(f"Не удалось зарезервировать xray inbound-порты через sysctl: {message}")


def choose_random_port(rows: list[dict], *, forbidden: set[int] | None = None) -> int:
    used = {
        int(row.get("port") or 0)
        for row in rows
        if isinstance(row, dict) and int(row.get("port") or 0) > 0
    }
    used.update(forbidden or set())
    for _ in range(2000):
        port = random.randint(PORT_MIN, PORT_MAX)
        if port in used:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            sock.close()
            continue
        sock.close()
        return port
    raise SystemExit("Не удалось подобрать свободный TCP-порт для standalone Xray-core")


def iter_existing_actual_ports(rows: list[dict]) -> set[int]:
    return {
        int(row.get("port") or 0)
        for row in rows
        if isinstance(row, dict) and int(row.get("port") or 0) > 0
    }


def iter_existing_shared_ports(rows: list[dict]) -> set[int]:
    ports = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        publication = parse_publication_spec(str(row.get("tag") or ""))
        if publication["mode"] == "shared" and publication.get("port"):
            ports.add(int(publication["port"]))
    return ports


def extract_existing_route_keys(rows: list[dict]) -> dict[int, dict[str, set[str]]]:
    state: dict[int, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        publication = parse_publication_spec(str(row.get("tag") or ""))
        if publication["mode"] != "shared" or not publication.get("port"):
            continue
        shared_port = int(publication["port"])
        stream = row.get("streamSettings") or {}
        security = str(stream.get("security") or "").lower()
        bucket = state.setdefault(shared_port, {"sni": set(), "http_paths": set()})
        if security in {"reality", "tls"}:
            if security == "reality":
                reality = stream.get("realitySettings") or {}
                for name in reality.get("serverNames") or []:
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
            route_path = ""
            if network in {"xhttp", "httpupgrade", "splithttp"}:
                for key in ("xhttpSettings", "httpupgradeSettings", "splitHTTPSettings"):
                    route_path = str((stream.get(key) or {}).get("path") or "").strip()
                    if route_path:
                        break
            if route_path:
                bucket["http_paths"].add(route_path)
    return state


def custom_http_path(spec: dict) -> str:
    if str(spec.get("network") or "").lower() == "xhttp":
        return "/"
    base = slugify(spec["domain"] or f"{spec['protocol']}-{spec['network']}")
    return f"/{base}-{spec['network']}"


def build_xray_catalog_groups() -> list[dict]:
    state = load_xray_state()
    tls_domain = get_public_tls_domain(state) or "www.amd.com"

    reality_tcp_items = []
    for domain in XRAY_TCP_REALITY_DOMAINS:
        slug = slugify(domain)
        for port_label, line_prefix, title_prefix, mode_suffix in (
            ("443", "443", "443", ""),
            ("8443", "8443", "8443", ""),
            ("random_direct", "", "случайный direct-порт", " случайный direct-порт"),
            ("random_shared", "", "случайный shared-порт", " случайный shared-порт"),
        ):
            reality_tcp_items.append(
                {
                    "id": f"xray_vless_tcp_reality_{slug}_{port_label}",
                    "title": f"{title_prefix} VLESS TCP REALITY {domain}",
                    "line": f"{line_prefix + ' ' if line_prefix else ''}vless tcp raw {domain}{mode_suffix}",
                }
            )
            reality_tcp_items.append(
                {
                    "id": f"xray_vless_tcp_reality_noflow_{slug}_{port_label}",
                    "title": f"{title_prefix} VLESS TCP REALITY no-flow {domain}",
                    "line": f"{line_prefix + ' ' if line_prefix else ''}vless tcp raw no-flow {domain}{mode_suffix}",
                }
            )
            reality_tcp_items.append(
                {
                    "id": f"xray_trojan_tcp_reality_{slug}_{port_label}",
                    "title": f"{title_prefix} TROJAN TCP REALITY {domain}",
                    "line": f"{line_prefix + ' ' if line_prefix else ''}trojan tcp raw {domain}{mode_suffix}",
                }
            )

    reality_xhttp_items = []
    for domain in XRAY_TCP_REALITY_DOMAINS:
        slug = slugify(domain)
        for port_label, line_prefix, title_prefix, mode_suffix in (
            ("443", "443", "443", ""),
            ("8443", "8443", "8443", ""),
            ("random_direct", "", "случайный direct-порт", " случайный direct-порт"),
            ("random_shared", "", "случайный shared-порт", " случайный shared-порт"),
        ):
            reality_xhttp_items.append(
                {
                    "id": f"xray_vless_xhttp_reality_{slug}_{port_label}",
                    "title": f"{title_prefix} VLESS XHTTP REALITY {domain}",
                    "line": f"{line_prefix + ' ' if line_prefix else ''}vless xhttp raw {domain}{mode_suffix}",
                }
            )
            reality_xhttp_items.append(
                {
                    "id": f"xray_trojan_xhttp_reality_{slug}_{port_label}",
                    "title": f"{title_prefix} TROJAN XHTTP REALITY {domain}",
                    "line": f"{line_prefix + ' ' if line_prefix else ''}trojan xhttp raw {domain}{mode_suffix}",
                }
            )

    tls_items = [
        {"id": "xray_vmess_tls_8443", "title": f"8443 VMESS TCP TLS {tls_domain}", "line": f"8443 vmess tcp tls {tls_domain}"},
        {"id": "xray_vless_tls_public", "title": f"случайный direct-порт VLESS TCP TLS {tls_domain}", "line": f"vless tcp tls {tls_domain} случайный direct-порт"},
        {"id": "xray_trojan_tls_public", "title": f"случайный direct-порт TROJAN TCP TLS {tls_domain}", "line": f"trojan tcp tls {tls_domain} случайный direct-порт"},
        {"id": "xray_vless_xhttp_tls_public", "title": f"случайный direct-порт VLESS XHTTP TLS {tls_domain}", "line": f"vless xhttp tls {tls_domain} случайный direct-порт"},
        {"id": "xray_trojan_xhttp_tls_public", "title": f"случайный direct-порт TROJAN XHTTP TLS {tls_domain}", "line": f"trojan xhttp tls {tls_domain} случайный direct-порт"},
        {"id": "xray_vmess_xhttp_tls_public", "title": f"случайный direct-порт VMESS XHTTP TLS {tls_domain}", "line": f"vmess xhttp tls {tls_domain} случайный direct-порт"},
        {"id": "xray_vless_ws_tls_public", "title": f"случайный direct-порт VLESS WS TLS {tls_domain}", "line": f"vless ws tls {tls_domain} случайный direct-порт"},
        {"id": "xray_trojan_ws_tls_public", "title": f"случайный direct-порт TROJAN WS TLS {tls_domain}", "line": f"trojan ws tls {tls_domain} случайный direct-порт"},
        {"id": "xray_vmess_ws_tls_public", "title": f"случайный direct-порт VMESS WS TLS {tls_domain}", "line": f"vmess ws tls {tls_domain} случайный direct-порт"},
        {"id": "xray_vless_grpc_tls_public", "title": f"случайный direct-порт VLESS gRPC TLS {tls_domain}", "line": f"vless grpc tls {tls_domain} случайный direct-порт"},
        {"id": "xray_trojan_grpc_tls_public", "title": f"случайный direct-порт TROJAN gRPC TLS {tls_domain}", "line": f"trojan grpc tls {tls_domain} случайный direct-порт"},
        {"id": "xray_vmess_grpc_tls_public", "title": f"случайный direct-порт VMESS gRPC TLS {tls_domain}", "line": f"vmess grpc tls {tls_domain} случайный direct-порт"},
    ]

    items = []
    for group_items in (reality_tcp_items, reality_xhttp_items, tls_items):
        items.extend(group_items)
    return [
        {
            "title": "Standalone Xray-core: Reality TCP",
            "items": reality_tcp_items,
        },
        {
            "title": "Standalone Xray-core: Reality XHTTP",
            "items": reality_xhttp_items,
        },
        {
            "title": "Standalone Xray-core: TLS",
            "items": tls_items,
        },
    ]


def fetch_catalog_groups() -> list[dict]:
    if BACKEND_MODE == "3x-ui":
        if not Path(LEGACY_XUI_HELPER).exists():
            raise SystemExit(f"Legacy x-ui helper not found: {LEGACY_XUI_HELPER}")
        result = subprocess.run(
            [LEGACY_XUI_HELPER, "--catalog-json"],
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(result.stdout)
        return payload if isinstance(payload, list) else []
    return build_xray_catalog_groups()


def select_catalog_lines(groups: list[dict]) -> list[str]:
    options = []
    heading = (
        "Выбери inbound'ы для standalone Xray-core:"
        if BACKEND_MODE == "xray-core"
        else "Выбери inbound'ы для VLESS backend:"
    )
    print(heading)
    for group in groups:
        print("")
        print(f"[{group['title']}]")
        for item in group.get("items") or []:
            options.append(item)
            print(f"  {len(options)}. {item['title']}")
    print("")
    print("  s. выбрать dest/SNI из полного REALITY SNI pool")
    print("")
    raw = input("Номера или диапазоны через пробел, s = полный SNI pool, Enter = ничего не создавать: ").strip()
    if not raw:
        print("Пропускаю создание inbound'ов.")
        return []
    if raw.lower() in {"s", "sni", "pool"}:
        line = prompt_reality_line_from_sni()
        return [line] if line else []

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

    selected = []
    for idx in indexes:
        line = str(options[idx - 1].get("line") or "").strip()
        if line and line not in selected:
            selected.append(line)
    return selected


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


def apply_lines_via_xui(lines: list[str]) -> int:
    if not Path(LEGACY_XUI_HELPER).exists():
        raise SystemExit(f"Legacy x-ui helper not found: {LEGACY_XUI_HELPER}")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        json.dump(lines, tmp, ensure_ascii=False, indent=2)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            [LEGACY_XUI_HELPER, "--apply-lines-json", tmp_path],
            check=False,
            text=True,
        )
        return int(result.returncode or 0)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def get_xray_x25519() -> tuple[str, str]:
    result = subprocess.run(
        [XRAY_BIN, "x25519"],
        capture_output=True,
        text=True,
        check=False,
    )
    private_key = ""
    public_key = ""
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    for raw in output.splitlines():
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
    if not private_key or not public_key:
        raise SystemExit(f"Xray did not return a valid x25519 keypair. Output:\n{output.strip()}")
    return private_key, public_key


def match_existing_xray(
    rows: list[dict],
    *,
    protocol: str,
    network: str,
    security: str,
    sni: str,
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
            values = {normalize_sni(item) for item in (reality.get("serverNames") or []) if str(item).strip()}
        elif security == "tls":
            tls = stream.get("tlsSettings") or {}
            values = set()
            for candidate in list(tls.get("serverNames") or []) + [tls.get("serverName"), (tls.get("settings") or {}).get("serverName")]:
                normalized = normalize_sni(candidate)
                if normalized:
                    values.add(normalized)
        else:
            values = set()
        if wanted_sni in values:
            return row
    return None


def prepare_xray_specs(lines: list[str], rows: list[dict]) -> list[dict]:
    prepared = []
    occupied_actual_ports = set(iter_existing_actual_ports(rows))
    occupied_shared_ports = set(iter_existing_shared_ports(rows))
    existing_routes = extract_existing_route_keys(rows)
    new_routes: dict[int, dict[str, set[str]]] = {}
    preferred_counts: dict[int, int] = {}
    shared_random_groups: dict[tuple[str, str, str], list[dict]] = {}
    shared_random_ports: dict[tuple[str, str, str], int] = {}

    for line in lines:
        spec = parse_custom_spec_line(line)
        preferred = spec.get("preferred_port")
        if preferred is not None:
            preferred_counts[int(preferred)] = preferred_counts.get(int(preferred), 0) + 1
        if spec.get("publication") == "shared-random":
            group_key = (spec["network"], spec["security"], "random-shared")
            shared_random_groups.setdefault(group_key, []).append(spec)
        prepared.append(spec)

    for group_key, group_specs in shared_random_groups.items():
        if len(group_specs) > 1:
            port = choose_random_port(rows, forbidden=occupied_actual_ports | occupied_shared_ports)
            shared_random_ports[group_key] = port
            occupied_shared_ports.add(port)

    final_specs = []
    for line in lines:
        spec = parse_custom_spec_line(line)
        if spec["protocol"] not in {"vless", "vmess", "trojan"}:
            raise SystemExit(f"Для standalone Xray-core пока разрешены только VLESS/VMESS/TROJAN: {line}")
        if spec["network"] not in {"tcp", "xhttp", "ws", "grpc"}:
            raise SystemExit(f"Для standalone Xray-core сейчас разрешены TCP, WS, gRPC и XHTTP: {line}")
        if spec["security"] not in {"reality", "tls"}:
            raise SystemExit(f"Для standalone Xray-core сейчас разрешены только REALITY и TLS: {line}")
        if spec["protocol"] == "vmess" and spec["security"] == "reality":
            raise SystemExit(f"VMESS + REALITY не входит в текущий каталог возможностей installer: {line}")
        if spec["security"] == "reality" and spec["network"] not in {"tcp", "xhttp"}:
            raise SystemExit(f"Для standalone Xray-core REALITY сейчас разрешён только с TCP и XHTTP: {line}")
        spec.setdefault("resolution_notes", [])

        if spec.get("publication") == "shared-random":
            group_key = (spec["network"], spec["security"], "random-shared")
            shared_port = shared_random_ports.get(group_key)
            if shared_port:
                spec["mode"] = "shared"
                spec["external_port"] = shared_port
                spec["resolution_notes"].append(
                    f"случайный shared-порт для группы {spec['network']}/{spec['security']}: {shared_port}"
                )
                pending_bucket = new_routes.setdefault(shared_port, {"sni": set(), "http_paths": set()})
                if spec["security"] in {"reality", "tls"}:
                    pending_bucket["sni"].update(spec_route_sni_values(spec))
                else:
                    pending_bucket["http_paths"].add(custom_http_path(spec))
                backend_port = choose_random_port(rows, forbidden=occupied_actual_ports | occupied_shared_ports)
                spec["listen_port"] = backend_port
                occupied_actual_ports.add(backend_port)
                final_specs.append(spec)
                continue
            spec["resolution_notes"].append(
                "случайный shared-порт был выбран только для одного inbound; использую случайный direct-порт"
            )

        preferred_port = spec.get("preferred_port")
        if preferred_port is not None:
            preferred_port = int(preferred_port)
            wants_shared = (
                preferred_port in {443, 8443} or
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
                    replacement = choose_random_port(rows, forbidden=occupied_actual_ports | occupied_shared_ports)
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
                elif preferred_port in {443, 8443}:
                    spec["resolution_notes"].append(
                        f"публичный порт {preferred_port} публикуется через nginx shared stream"
                    )

                spec["external_port"] = shared_port
                pending_bucket = new_routes.setdefault(shared_port, {"sni": set(), "http_paths": set()})
                if spec["security"] in {"reality", "tls"}:
                    pending_bucket["sni"].update(spec_route_sni_values(spec))
                else:
                    pending_bucket["http_paths"].add(custom_http_path(spec))
                backend_port = choose_random_port(rows, forbidden=occupied_actual_ports | occupied_shared_ports)
                spec["listen_port"] = backend_port
                occupied_actual_ports.add(backend_port)
                occupied_shared_ports.add(shared_port)
                final_specs.append(spec)
                continue

        spec["mode"] = "direct"
        if preferred_port is not None:
            direct_port = int(preferred_port)
            if direct_port in occupied_actual_ports or direct_port in occupied_shared_ports:
                replacement = choose_random_port(rows, forbidden=occupied_actual_ports | occupied_shared_ports)
                spec["resolution_notes"].append(
                    f"желаемый direct-порт {direct_port} был занят, назначен {replacement}"
                )
                direct_port = replacement
            else:
                spec["resolution_notes"].append(
                    f"порт {direct_port} используется только одним inbound'ом, поэтому он будет опубликован как direct"
                )
        else:
            direct_port = choose_random_port(rows, forbidden=occupied_actual_ports | occupied_shared_ports)
            spec["resolution_notes"].append(
                f"порт не был задан явно, назначен свободный direct-порт {direct_port}"
            )
        spec["listen_port"] = direct_port
        occupied_actual_ports.add(direct_port)
        final_specs.append(spec)
    return final_specs


def build_xray_payload(spec: dict, rows: list[dict]) -> tuple[dict | None, str]:
    protocol = spec["protocol"]
    network = spec["network"]
    security = spec["security"]
    domain = str(spec.get("domain") or "").strip().lower()
    listen_port = int(spec["listen_port"])
    state = load_xray_state()
    public_tls_domain = get_public_tls_domain(state)

    existing = match_existing_xray(
        rows,
        protocol=protocol,
        network=network,
        security=security,
        sni=domain,
        port=listen_port if spec.get("mode") == "direct" else None,
        no_flow=bool(spec.get("no_flow")) if protocol == "vless" and network == "tcp" and security == "reality" else None,
    )
    if existing:
        return None, (
            f"reuse existing {protocol} {network} {security} for {domain} "
            f"(tag={existing.get('tag') or '<no-tag>'}, port={existing.get('port')})"
        )

    private_key, public_key = get_xray_x25519()
    short_id = "".join(random.choice("0123456789abcdef") for _ in range(16))
    tag = f"vpnbot-{protocol}-{network}-{security}-{slugify(domain)}-{listen_port}"

    if protocol == "vless":
        settings = {"clients": [], "decryption": "none", "fallbacks": []}
    elif protocol == "trojan":
        settings = {"clients": [], "fallbacks": []}
    elif protocol == "vmess":
        settings = {"clients": []}
    else:
        raise SystemExit(f"Неподдерживаемый протокол для xray-core helper: {protocol}")

    if security == "tls" and public_tls_domain and domain and domain != public_tls_domain:
        raise SystemExit(
            "Для TLS-inbound standalone xray-core installer сейчас использует сертификат, выпущенный на "
            f"{public_tls_domain}. Поэтому для TLS в каталоге укажи именно этот домен, "
            "либо сначала подготовь другой сертификат вручную."
        )

    publication_marker = (
        f"[shared:{int(spec['external_port'])}]"
        if spec.get("mode") == "shared" and spec.get("external_port")
        else "[direct]"
    )
    if spec.get("no_flow"):
        publication_marker = f"{publication_marker} no-flow"
    tag = f"{publication_marker} {tag}"
    use_proxy_protocol = bool(spec.get("mode") == "shared" and spec.get("external_port"))

    stream_settings = {
        "network": network,
        "security": security,
    }
    if use_proxy_protocol:
        stream_settings["sockopt"] = {"acceptProxyProtocol": True}

    if security == "reality":
        server_names = reality_server_names(domain)
        stream_settings["realitySettings"] = {
            "show": False,
            "xver": 0,
            "dest": f"{domain}:443",
            "serverNames": server_names,
            "privateKey": private_key,
            "minClientVer": "",
            "maxClientVer": "",
            "maxTimeDiff": 0,
            "shortIds": [short_id],
            "settings": {
                "publicKey": public_key,
                "fingerprint": REALITY_FINGERPRINT,
                "serverName": "",
                "spiderX": "/",
            },
        }
    elif security == "tls":
        alpn = ["h2", "http/1.1"] if network == "grpc" else ["http/1.1"]
        stream_settings["tlsSettings"] = {
            "serverName": domain,
            "alpn": alpn,
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
        stream_settings["tcpSettings"] = {
            "acceptProxyProtocol": use_proxy_protocol,
            "header": {
                "type": "none"
            }
        }
    elif network == "xhttp":
        stream_settings["xhttpSettings"] = {
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
        stream_settings["wsSettings"] = {
            "path": custom_http_path(spec),
            "headers": {},
        }
    elif network == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": slugify(domain or f"{protocol}-grpc"),
            "multiMode": False,
        }
    else:
        raise SystemExit(f"Неподдерживаемый транспорт для xray-core helper: {network}")

    payload = {
        "tag": tag,
        "listen": "0.0.0.0",
        "port": listen_port,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream_settings,
        "sniffing": {
            "enabled": security != "reality",
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False,
            "routeOnly": security != "reality",
        },
    }
    return payload, (
        f"create {protocol} {network} {security} on "
        f"{'shared port ' + str(spec['external_port']) if spec.get('mode') == 'shared' else 'direct port ' + str(listen_port)} "
        f"backend_port={listen_port}, sni/target={domain}:443"
    )


def validate_and_restart_xray() -> None:
    env = {"XRAY_LOCATION_ASSET": str(XRAY_ASSET_DIR), "XRAY_LOCATION_CONFDIR": str(XRAY_CONFDIR)}
    subprocess.run(
        [XRAY_BIN, "run", "-confdir", str(XRAY_CONFDIR), "-dump"],
        check=True,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(["systemctl", "restart", XRAY_SERVICE_NAME], check=True)
    subprocess.run(["systemctl", "is-active", "--quiet", XRAY_SERVICE_NAME], check=True)


def apply_lines_via_xray(lines: list[str]) -> int:
    _, rows = load_xray_inbounds()
    prepared = prepare_xray_specs(lines, rows)
    notes = []
    created = []
    new_rows = list(rows)
    for spec in prepared:
        payload, note = build_xray_payload(spec, new_rows)
        notes.append(note)
        if payload is None:
            continue
        created.append(payload)
        new_rows.append(payload)

    backup_text = ""
    if XRAY_MANAGED_INBOUNDS_FILE.exists():
        backup_text = XRAY_MANAGED_INBOUNDS_FILE.read_text(encoding="utf-8")
    try:
        save_xray_inbounds(new_rows)
        sync_xray_reserved_ports(new_rows)
        validate_and_restart_xray()
        subprocess.run([XRAY_SYNC_SCRIPT], check=True)
    except Exception as exc:
        if backup_text:
            XRAY_MANAGED_INBOUNDS_FILE.write_text(backup_text, encoding="utf-8")
        else:
            XRAY_MANAGED_INBOUNDS_FILE.unlink(missing_ok=True)
        try:
            sync_xray_reserved_ports(rows)
            validate_and_restart_xray()
            subprocess.run([XRAY_SYNC_SCRIPT], check=True)
        except Exception:
            pass
        raise SystemExit(f"Не удалось применить xray-core inbound'ы, откатил managed file: {exc}") from exc

    print("VPnBot standalone xray-core catalog result")
    print("==========================================")
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
            publication = parse_publication_spec(str(obj.get("tag") or ""))
            mode = f"shared {publication['port']}" if publication["mode"] == "shared" and publication.get("port") else "direct"
            server_names = []
            if security == "reality":
                server_names = (stream.get("realitySettings") or {}).get("serverNames") or []
            elif security == "tls":
                tls = stream.get("tlsSettings") or {}
                server_names = list(tls.get("serverNames") or [])
                if not server_names and tls.get("serverName"):
                    server_names = [tls.get("serverName")]
            print(
                f"  • tag={obj.get('tag')} {obj.get('protocol')} {network}/{security or 'none'} "
                f"port={obj.get('port')} mode={mode} sni={','.join(server_names)}"
            )
    else:
        print("")
        print("Новых inbound'ов не понадобилось: подходящие уже существовали.")
    return 0


def list_titles(groups: list[dict]) -> int:
    for group in groups:
        print(group["title"] + ":")
        for item in group.get("items") or []:
            print(f"  {item['title']}")
        print("")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--list-sni":
        return print_reality_sni_pool()
    if len(argv) > 1 and argv[1] == "--line-from-sni":
        if len(argv) < 3:
            raise SystemExit("Usage: vpnbot-vless-presets --line-from-sni <sni> [vless|trojan] [tcp|xhttp] [direct-random|shared-random|443|8443] [--no-flow]")
        protocol = argv[3] if len(argv) > 3 and not argv[3].startswith("--") else "vless"
        network = argv[4] if len(argv) > 4 and not argv[4].startswith("--") else "tcp"
        mode = argv[5] if len(argv) > 5 and not argv[5].startswith("--") else "direct-random"
        print(build_reality_line_from_sni(argv[2], protocol=protocol, network=network, no_flow="--no-flow" in argv[3:], mode=mode))
        return 0
    groups = fetch_catalog_groups()
    if len(argv) > 1 and argv[1] == "--list":
        return list_titles(groups)
    if len(argv) > 1 and argv[1] == "--catalog-json":
        print(json.dumps(groups, ensure_ascii=False, indent=2))
        return 0
    if len(argv) > 1 and argv[1] == "--apply-lines-json":
        if len(argv) < 3:
            raise SystemExit("Usage: vpnbot-vless-presets --apply-lines-json <file>")
        payload = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise SystemExit("Expected JSON array of catalog lines")
        lines = []
        for item in payload:
            if not isinstance(item, str):
                continue
            text = item.strip()
            if text and text not in lines:
                lines.append(text)
        if BACKEND_MODE == "3x-ui":
            return apply_lines_via_xui(lines)
        return apply_lines_via_xray(lines)
    lines = select_catalog_lines(groups)
    if not lines:
        return 0
    if BACKEND_MODE == "3x-ui":
        return apply_lines_via_xui(lines)
    return apply_lines_via_xray(lines)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
