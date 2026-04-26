#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ACCESS_LOG = Path(os.environ.get("XRAY_ONLINE_ACCESS_LOG", "/opt/vpnbot/xray-core/logs/access.log"))
BIND_HOST = os.environ.get("XRAY_ONLINE_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("XRAY_ONLINE_BIND_PORT", "10086"))
WINDOW_SECONDS = max(10, min(int(os.environ.get("XRAY_ONLINE_WINDOW_SECONDS", "180")), 3600))
BOOTSTRAP_BYTES = max(64 * 1024, min(int(os.environ.get("XRAY_ONLINE_BOOTSTRAP_BYTES", "524288")), 8 * 1024 * 1024))
POLL_INTERVAL = max(0.05, min(float(os.environ.get("XRAY_ONLINE_POLL_INTERVAL", "0.2")), 5.0))
MAX_IPS_PER_USER = max(1, min(int(os.environ.get("XRAY_ONLINE_MAX_IPS_PER_USER", "20")), 100))
XRAY_BIN = os.environ.get("XRAY_ONLINE_XRAY_BIN", "/opt/vpnbot/xray-core/bin/xray")
XRAY_API_SERVER = os.environ.get("XRAY_ONLINE_XRAY_API_SERVER", "127.0.0.1:10085")
STATS_INTERVAL = max(5.0, min(float(os.environ.get("XRAY_ONLINE_STATS_INTERVAL_SECONDS", "60")), 300.0))
ABUSE_AUDIT_WINDOW_SECONDS = max(60, min(int(os.environ.get("XRAY_ABUSE_AUDIT_WINDOW_SECONDS", "86400")), 7 * 86400))
ABUSE_AUDIT_MAX_EVENTS = max(1000, min(int(os.environ.get("XRAY_ABUSE_AUDIT_MAX_EVENTS", "50000")), 500000))
ABUSE_AUDIT_TOP_LIMIT = max(5, min(int(os.environ.get("XRAY_ABUSE_AUDIT_TOP_LIMIT", "20")), 100))

LOCK = threading.RLock()
CLIENTS: dict[str, dict] = {}
ABUSE_EVENTS: list[dict] = []
LAST_LINE_AT = 0.0
LAST_ERROR = ""
TRAFFIC = {
    "traffic_source": "xray_stats_unavailable",
    "traffic_up_bytes": 0,
    "traffic_down_bytes": 0,
    "traffic_total_bytes": 0,
    "load_bps": None,
    "stats_checked_at": "",
    "stats_last_error": "",
}


def utc_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).isoformat()


def parse_xray_ts(value: str) -> float | None:
    try:
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def normalize_ip(value: str) -> str | None:
    candidate = str(value or "").strip().strip("\"'(){}<>")
    if not candidate:
        return None

    lowered = candidate.lower()
    for prefix in ("tcp:", "udp:", "http:", "https:"):
        if lowered.startswith(prefix):
            candidate = candidate[len(prefix):].strip()
            lowered = candidate.lower()
            break

    probes = [candidate.strip("[]")]
    if candidate.startswith("[") and "]" in candidate:
        probes.append(candidate[1:candidate.index("]")])
    if "/" in candidate:
        probes.append(candidate.split("/", 1)[0].strip("[]"))
    if ":" in candidate and "." in candidate:
        host_part, _, maybe_port = candidate.rpartition(":")
        if host_part and maybe_port.isdigit():
            probes.append(host_part.strip("[]"))

    for probe in probes:
        probe = str(probe or "").strip()
        if not probe:
            continue
        try:
            return str(ipaddress.ip_address(probe))
        except Exception:
            continue
    return None


def extract_source_ip(line: str) -> str | None:
    match = re.match(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(?P<body>.*)$", line)
    body = match.group("body") if match else line
    before_accepted = body.split(" accepted ", 1)[0]

    for token in reversed(re.split(r"[\s,;]+", before_accepted)):
        ip = normalize_ip(token)
        if ip:
            return ip

    for match in re.finditer(r"(?:\d{1,3}\.){3}\d{1,3}", before_accepted):
        ip = normalize_ip(match.group(0))
        if ip:
            return ip
    return None


def normalize_host(value: str) -> str:
    host = str(value or "").strip().strip("\"'(){}<>[]")
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except Exception:
        return host.lower()


def parse_target_endpoint(value: str) -> dict | None:
    endpoint = str(value or "").strip().strip("\"'(){}<>")
    if not endpoint:
        return None

    protocol = ""
    lowered = endpoint.lower()
    for prefix in ("tcp:", "udp:", "http:", "https:"):
        if lowered.startswith(prefix):
            protocol = prefix[:-1]
            endpoint = endpoint[len(prefix):].strip()
            lowered = endpoint.lower()
            break

    host = ""
    port = 0
    if endpoint.startswith("[") and "]" in endpoint:
        host = endpoint[1:endpoint.index("]")]
        rest = endpoint[endpoint.index("]") + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    else:
        host_part, sep, port_part = endpoint.rpartition(":")
        if sep and port_part.isdigit():
            host = host_part
            port = int(port_part)
        else:
            host = endpoint

    host = normalize_host(host)
    if not host:
        return None
    if port < 0 or port > 65535:
        port = 0

    return {"protocol": protocol, "host": host, "port": port}


def extract_target(line: str) -> dict | None:
    if " accepted " not in line:
        return None
    after = line.split(" accepted ", 1)[1].strip()
    if not after:
        return None
    token = after.split(" [", 1)[0].strip().split()[0]
    return parse_target_endpoint(token)


def remember_abuse_event(email: str, ts: float, source_ip: str | None, target: dict | None) -> None:
    if not target:
        return
    ABUSE_EVENTS.append(
        {
            "ts": float(ts),
            "email": email,
            "source_ip": source_ip or "",
            "protocol": str(target.get("protocol") or ""),
            "host": str(target.get("host") or ""),
            "port": int(target.get("port") or 0),
        }
    )
    if len(ABUSE_EVENTS) > ABUSE_AUDIT_MAX_EVENTS * 2:
        del ABUSE_EVENTS[:-ABUSE_AUDIT_MAX_EVENTS]


def process_line(raw: str) -> None:
    global LAST_LINE_AT

    line = str(raw or "").strip()
    if " accepted " not in line or "email:" not in line:
        return

    ts_match = re.search(r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+", line)
    email_match = re.search(r"\bemail:\s*(?P<email>\S+)", line)
    if not ts_match or not email_match:
        return

    ts = parse_xray_ts(ts_match.group("ts"))
    if ts is None:
        return

    email = email_match.group("email").strip().strip("\"'[](){}<>")
    if not email:
        return

    source_ip = extract_source_ip(line)
    target = extract_target(line)
    now = time.time()
    with LOCK:
        entry = CLIENTS.setdefault(email, {"email": email, "ips": {}, "last_seen": 0.0})
        entry["last_seen"] = max(float(entry.get("last_seen") or 0.0), ts)
        if source_ip:
            ips = entry.setdefault("ips", {})
            ips[source_ip] = ts
            if len(ips) > MAX_IPS_PER_USER * 2:
                for ip, _ in sorted(ips.items(), key=lambda item: float(item[1]))[:-MAX_IPS_PER_USER]:
                    ips.pop(ip, None)
        remember_abuse_event(email, ts, source_ip, target)
        LAST_LINE_AT = now


def purge_stale(now: float | None = None) -> None:
    now = now or time.time()
    cutoff = now - WINDOW_SECONDS
    abuse_cutoff = now - ABUSE_AUDIT_WINDOW_SECONDS
    with LOCK:
        for email in list(CLIENTS.keys()):
            entry = CLIENTS.get(email) or {}
            if float(entry.get("last_seen") or 0.0) < cutoff:
                CLIENTS.pop(email, None)
                continue
            ips = entry.get("ips")
            if isinstance(ips, dict):
                for ip, seen in list(ips.items()):
                    try:
                        if float(seen) < cutoff:
                            ips.pop(ip, None)
                    except Exception:
                        ips.pop(ip, None)
        if ABUSE_EVENTS:
            ABUSE_EVENTS[:] = [
                item
                for item in ABUSE_EVENTS
                if float(item.get("ts") or 0.0) >= abuse_cutoff
            ][-ABUSE_AUDIT_MAX_EVENTS:]


def build_abuse_audit(
    window_seconds: int | None = None,
    email_filter: str = "",
    port_filter: int | None = None,
    target_filter: str = "",
) -> dict:
    now = time.time()
    window = max(60, min(int(window_seconds or ABUSE_AUDIT_WINDOW_SECONDS), 7 * 86400))
    cutoff = now - window
    email_filter = str(email_filter or "").strip()
    target_filter = normalize_host(target_filter)

    purge_stale(now)
    with LOCK:
        events = [
            dict(item)
            for item in ABUSE_EVENTS
            if float(item.get("ts") or 0.0) >= cutoff
        ]

    by_user: dict[str, dict] = {}
    matched = 0
    for item in events:
        email = str(item.get("email") or "").strip()
        if not email:
            continue
        if email_filter and email != email_filter:
            continue

        host = str(item.get("host") or "").strip()
        port = int(item.get("port") or 0)
        if port_filter is not None and port != port_filter:
            continue
        if target_filter and host != target_filter:
            continue

        matched += 1
        entry = by_user.setdefault(
            email,
            {
                "email": email,
                "event_count": 0,
                "ports": {},
                "targets": {},
                "source_ips": {},
                "last_seen": 0.0,
            },
        )
        entry["event_count"] += 1
        if port:
            entry["ports"][str(port)] = int(entry["ports"].get(str(port), 0)) + 1
        target_key = f"{host}:{port}" if port else host
        if target_key:
            entry["targets"][target_key] = int(entry["targets"].get(target_key, 0)) + 1
        source_ip = str(item.get("source_ip") or "").strip()
        if source_ip:
            entry["source_ips"][source_ip] = int(entry["source_ips"].get(source_ip, 0)) + 1
        entry["last_seen"] = max(float(entry.get("last_seen") or 0.0), float(item.get("ts") or 0.0))

    users = []
    for entry in by_user.values():
        ports = sorted(entry.pop("ports").items(), key=lambda item: int(item[1]), reverse=True)
        targets = sorted(entry.pop("targets").items(), key=lambda item: int(item[1]), reverse=True)
        source_ips = sorted(entry.pop("source_ips").items(), key=lambda item: int(item[1]), reverse=True)
        last_seen = float(entry.pop("last_seen") or 0.0)
        entry.update(
            {
                "unique_ports": len(ports),
                "unique_targets": len(targets),
                "source_ip_count": len(source_ips),
                "top_ports": [
                    {"port": int(port), "count": int(count)}
                    for port, count in ports[:ABUSE_AUDIT_TOP_LIMIT]
                    if str(port).isdigit()
                ],
                "top_targets": [
                    {"target": target, "count": int(count)}
                    for target, count in targets[:ABUSE_AUDIT_TOP_LIMIT]
                ],
                "source_ips": [
                    {"ip": ip, "count": int(count)}
                    for ip, count in source_ips[:ABUSE_AUDIT_TOP_LIMIT]
                ],
                "last_seen_at": utc_iso(last_seen) if last_seen else "",
                "last_seen_age_seconds": max(0, int(now - last_seen)) if last_seen else -1,
            }
        )
        users.append(entry)

    users.sort(
        key=lambda item: (
            int(item.get("unique_ports") or 0),
            int(item.get("unique_targets") or 0),
            int(item.get("event_count") or 0),
        ),
        reverse=True,
    )
    return {
        "ok": True,
        "source": "vpnbot_xray_abuse_audit",
        "is_recent_activity": True,
        "access_log": str(ACCESS_LOG),
        "window_seconds": window,
        "events_kept": len(events),
        "matched_events": matched,
        "filters": {
            "email": email_filter,
            "port": port_filter,
            "target": target_filter,
        },
        "top_limit": ABUSE_AUDIT_TOP_LIMIT,
        "users": users[:ABUSE_AUDIT_TOP_LIMIT],
    }


def extract_traffic_totals(payload: dict, *, prefix: str) -> dict:
    uplink = 0
    downlink = 0
    stats = payload.get("stat")
    if not isinstance(stats, list):
        return {"traffic_up_bytes": 0, "traffic_down_bytes": 0, "traffic_total_bytes": 0}

    for item in stats:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if prefix and not name.startswith(prefix):
            continue
        try:
            value = int(item.get("value") or 0)
        except Exception:
            value = 0
        if value <= 0:
            continue
        if name.endswith(">>>traffic>>>uplink"):
            uplink += value
        elif name.endswith(">>>traffic>>>downlink"):
            downlink += value

    return {
        "traffic_up_bytes": int(uplink),
        "traffic_down_bytes": int(downlink),
        "traffic_total_bytes": int(uplink + downlink),
    }


def query_xray_stats(pattern: str) -> dict:
    proc = subprocess.run(
        [
            XRAY_BIN,
            "api",
            "statsquery",
            f"--server={XRAY_API_SERVER}",
            "-pattern",
            pattern,
            "-reset=false",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"exit={proc.returncode}")[-500:])
    return json.loads(proc.stdout or "{}")


def poll_xray_stats_once() -> None:
    now = time.time()
    source = "xray_stats_inbound"
    payload = query_xray_stats("inbound>>>")
    totals = extract_traffic_totals(payload, prefix="inbound>>>")
    if int(totals.get("traffic_total_bytes") or 0) <= 0:
        source = "xray_stats_user_fallback"
        payload = query_xray_stats("user>>>")
        totals = extract_traffic_totals(payload, prefix="user>>>")

    with LOCK:
        previous_total = int(TRAFFIC.get("traffic_total_bytes") or 0)
        previous_checked_at = float(TRAFFIC.get("_checked_at_ts") or 0.0)
        new_total = int(totals.get("traffic_total_bytes") or 0)
        load_bps = None
        if previous_checked_at > 0 and new_total >= previous_total:
            delta_seconds = max(0.001, now - previous_checked_at)
            if delta_seconds >= max(5.0, STATS_INTERVAL * 0.5):
                load_bps = int(((new_total - previous_total) * 8) / delta_seconds)

        TRAFFIC.update(
            {
                "traffic_source": source,
                "traffic_up_bytes": int(totals.get("traffic_up_bytes") or 0),
                "traffic_down_bytes": int(totals.get("traffic_down_bytes") or 0),
                "traffic_total_bytes": new_total,
                "load_bps": load_bps,
                "stats_checked_at": utc_iso(now),
                "stats_last_error": "",
                "_checked_at_ts": now,
            }
        )


def stats_worker() -> None:
    global LAST_ERROR
    while True:
        try:
            poll_xray_stats_once()
        except Exception as exc:
            with LOCK:
                TRAFFIC["stats_last_error"] = f"{type(exc).__name__}: {exc}"
                LAST_ERROR = TRAFFIC["stats_last_error"]
        time.sleep(STATS_INTERVAL)


def snapshot(window_seconds: int | None = None) -> dict:
    now = time.time()
    window = max(10, min(int(window_seconds or WINDOW_SECONDS), 3600))
    cutoff = now - window
    purge_stale(now)

    details: dict[str, dict] = {}
    with LOCK:
        raw_items = list(CLIENTS.items())
        last_line_at = LAST_LINE_AT
        last_error = LAST_ERROR
        traffic = dict(TRAFFIC)
        abuse_events_kept = len(ABUSE_EVENTS)
        traffic.pop("_checked_at_ts", None)

    for email, entry in raw_items:
        try:
            last_seen = float(entry.get("last_seen") or 0.0)
        except Exception:
            continue
        if last_seen < cutoff:
            continue

        ips_raw = entry.get("ips") if isinstance(entry.get("ips"), dict) else {}
        ips = [
            ip
            for ip, _ in sorted(ips_raw.items(), key=lambda item: float(item[1]), reverse=True)
            if float(_) >= cutoff
        ][:MAX_IPS_PER_USER]

        details[email] = {
            "email": email,
            "ips": ips,
            "last_seen": last_seen,
            "last_seen_at": utc_iso(last_seen),
            "last_seen_age_seconds": max(0, int(now - last_seen)),
        }

    users = sorted(details.keys())
    max_age = max((item["last_seen_age_seconds"] for item in details.values()), default=-1)
    return {
        "ok": True,
        "source": "vpnbot_xray_online_tracker",
        "is_recent_activity": True,
        "access_log": str(ACCESS_LOG),
        "window_seconds": window,
        "online_count": len(users),
        "users": users,
        "details": details,
        "max_last_seen_age_seconds": max_age,
        "abuse_audit": {
            "endpoint": "/abuse",
            "window_seconds": ABUSE_AUDIT_WINDOW_SECONDS,
            "events_kept": abuse_events_kept,
        },
        **traffic,
        "tracker": {
            "bind": f"{BIND_HOST}:{BIND_PORT}",
            "started_at": STARTED_AT,
            "last_line_at": utc_iso(last_line_at) if last_line_at else "",
            "last_line_age_seconds": max(0, int(now - last_line_at)) if last_line_at else -1,
            "last_error": last_error,
        },
    }


def read_bootstrap_tail(path: Path) -> int:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return 0
    except Exception:
        return 0
    read_size = min(size, BOOTSTRAP_BYTES)
    if read_size <= 0:
        return size
    with path.open("rb") as fh:
        if size > read_size:
            fh.seek(size - read_size)
        text = fh.read().decode("utf-8", errors="replace")
    for line in text.splitlines():
        process_line(line)
    return size


def tail_access_log() -> None:
    global LAST_ERROR

    fh = None
    inode = None
    position = 0
    while True:
        try:
            stat = ACCESS_LOG.stat()
            current_inode = (stat.st_dev, stat.st_ino)
            if fh is None or inode != current_inode or stat.st_size < position:
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass
                ACCESS_LOG.parent.mkdir(parents=True, exist_ok=True)
                position = read_bootstrap_tail(ACCESS_LOG)
                fh = ACCESS_LOG.open("r", encoding="utf-8", errors="replace")
                fh.seek(position)
                inode = current_inode

            line = fh.readline()
            if line:
                process_line(line)
                position = fh.tell()
                continue

            purge_stale()
            time.sleep(POLL_INTERVAL)
        except Exception as exc:
            with LOCK:
                LAST_ERROR = f"{type(exc).__name__}: {exc}"
            try:
                if fh is not None:
                    fh.close()
            except Exception:
                pass
            fh = None
            inode = None
            position = 0
            time.sleep(1.0)


class Handler(BaseHTTPRequestHandler):
    server_version = "vpnbot-xray-online-tracker/1.0"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/health", "/ready"}:
            self._send_json(200, {"ok": True, "source": "vpnbot_xray_online_tracker", "started_at": STARTED_AT})
            return
        if parsed.path in {"/", "/online", "/stats"}:
            query = parse_qs(parsed.query)
            window = None
            if "window" in query and query["window"]:
                try:
                    window = int(query["window"][0])
                except Exception:
                    window = None
            self._send_json(200, snapshot(window))
            return
        if parsed.path == "/abuse":
            query = parse_qs(parsed.query)
            window = None
            port = None
            if "window" in query and query["window"]:
                try:
                    window = int(query["window"][0])
                except Exception:
                    window = None
            if "port" in query and query["port"]:
                try:
                    port = int(query["port"][0])
                except Exception:
                    port = None
            email = query.get("email", [""])[0]
            target = query.get("target", [""])[0]
            self._send_json(200, build_abuse_audit(window, email, port, target))
            return
        self._send_json(404, {"ok": False, "error": "not_found"})


STARTED_AT = utc_iso()


def main() -> None:
    worker = threading.Thread(target=tail_access_log, name="xray-access-log-tail", daemon=True)
    worker.start()
    stats = threading.Thread(target=stats_worker, name="xray-stats-poll", daemon=True)
    stats.start()
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()