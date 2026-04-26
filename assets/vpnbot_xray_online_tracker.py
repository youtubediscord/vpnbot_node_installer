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
ABUSE_MULTI_IP_OBSERVE_IPS = max(2, int(os.environ.get("XRAY_ABUSE_MULTI_IP_OBSERVE_IPS", "2")))
ABUSE_MULTI_IP_SUSPICIOUS_IPS = max(
    ABUSE_MULTI_IP_OBSERVE_IPS,
    int(os.environ.get("XRAY_ABUSE_MULTI_IP_SUSPICIOUS_IPS", "4")),
)
ABUSE_MULTI_IP_HIGH_IPS = max(
    ABUSE_MULTI_IP_SUSPICIOUS_IPS,
    int(os.environ.get("XRAY_ABUSE_MULTI_IP_HIGH_IPS", "8")),
)
ABUSE_MULTI_IP_CRITICAL_IPS = max(
    ABUSE_MULTI_IP_HIGH_IPS,
    int(os.environ.get("XRAY_ABUSE_MULTI_IP_CRITICAL_IPS", "12")),
)
ABUSE_MULTI_IP_MIN_PREFIXES = max(1, int(os.environ.get("XRAY_ABUSE_MULTI_IP_MIN_PREFIXES", "3")))
ABUSE_MULTI_IP_TOP_LIMIT = max(5, min(int(os.environ.get("XRAY_ABUSE_MULTI_IP_TOP_LIMIT", "30")), 100))
ABUSE_MULTI_IP_WINDOWS = sorted(
    {
        max(10, min(int(item.strip()), 3600))
        for item in os.environ.get("XRAY_ABUSE_MULTI_IP_WINDOWS", "30,60,180").split(",")
        if item.strip().isdigit()
    }
    or {30, 60, 180}
)
ABUSE_MULTI_IP_HISTORY_FILE = Path(
    os.environ.get(
        "XRAY_ABUSE_MULTI_IP_HISTORY_FILE",
        "/var/lib/vpnbot-xray-online/multi_ip_history.json",
    )
)
ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS = max(
    3600,
    min(int(os.environ.get("XRAY_ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS", str(14 * 86400))), 90 * 86400),
)
ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS = max(
    300,
    min(int(os.environ.get("XRAY_ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS", "86400")), 7 * 86400),
)
ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS = max(
    30,
    min(int(os.environ.get("XRAY_ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS", "120")), 3600),
)
ABUSE_MULTI_IP_HISTORY_SAVE_INTERVAL_SECONDS = max(
    5.0,
    min(float(os.environ.get("XRAY_ABUSE_MULTI_IP_HISTORY_SAVE_INTERVAL_SECONDS", "30")), 300.0),
)

LOCK = threading.RLock()
CLIENTS: dict[str, dict] = {}
ABUSE_EVENTS: list[dict] = []
MULTI_IP_HISTORY: dict[str, dict] = {"users": {}}
USER_TRAFFIC: dict[str, dict] = {}
USER_TRAFFIC_HISTORY: dict[str, list[dict]] = {}
HISTORY_DIRTY = False
LAST_HISTORY_SAVE_AT = 0.0
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


def load_multi_ip_history() -> None:
    global MULTI_IP_HISTORY
    try:
        payload = json.loads(ABUSE_MULTI_IP_HISTORY_FILE.read_text(encoding="utf-8") or "{}")
    except FileNotFoundError:
        payload = {}
    except Exception:
        payload = {}

    if not isinstance(payload, dict):
        payload = {}
    users = payload.get("users")
    if not isinstance(users, dict):
        users = {}
    MULTI_IP_HISTORY = {"users": users}


def save_multi_ip_history(force: bool = False) -> None:
    global HISTORY_DIRTY, LAST_HISTORY_SAVE_AT

    now = time.time()
    if not force and (not HISTORY_DIRTY or now - LAST_HISTORY_SAVE_AT < ABUSE_MULTI_IP_HISTORY_SAVE_INTERVAL_SECONDS):
        return

    with LOCK:
        payload = json.loads(json.dumps(MULTI_IP_HISTORY, ensure_ascii=False))
        HISTORY_DIRTY = False
        LAST_HISTORY_SAVE_AT = now

    try:
        ABUSE_MULTI_IP_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = ABUSE_MULTI_IP_HISTORY_FILE.with_name(
            f".{ABUSE_MULTI_IP_HISTORY_FILE.name}.{os.getpid()}.tmp"
        )
        tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
        os.replace(tmp, ABUSE_MULTI_IP_HISTORY_FILE)
    except Exception:
        with LOCK:
            HISTORY_DIRTY = True


def _history_user(email: str) -> dict:
    users = MULTI_IP_HISTORY.setdefault("users", {})
    entry = users.setdefault(email, {"ips": {}, "risk_events": []})
    if not isinstance(entry.get("ips"), dict):
        entry["ips"] = {}
    if not isinstance(entry.get("risk_events"), list):
        entry["risk_events"] = []
    return entry


def remember_multi_ip_history(email: str, ts: float, source_ip: str | None) -> None:
    global HISTORY_DIRTY
    if not source_ip:
        return

    entry = _history_user(email)
    ips = entry.setdefault("ips", {})
    item = ips.setdefault(source_ip, {"first_seen": float(ts), "last_seen": 0.0, "count": 0})
    try:
        item["first_seen"] = min(float(item.get("first_seen") or ts), float(ts))
    except Exception:
        item["first_seen"] = float(ts)
    item["last_seen"] = max(float(item.get("last_seen") or 0.0), float(ts))
    item["count"] = int(item.get("count") or 0) + 1
    entry["last_seen"] = max(float(entry.get("last_seen") or 0.0), float(ts))
    HISTORY_DIRTY = True


def record_multi_ip_risk_event(
    email: str,
    now: float,
    *,
    risk_level: str,
    ip_count: int,
    prefix_count: int,
    new_ip_count: int,
    burst_score: int,
) -> dict:
    global HISTORY_DIRTY

    entry = _history_user(email)
    events = entry.setdefault("risk_events", [])
    cutoff = now - ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS
    events[:] = [
        item
        for item in events
        if isinstance(item, dict) and float(item.get("ts") or 0.0) >= cutoff
    ]

    risk_level = str(risk_level or "normal")
    if risk_level in {"suspicious", "high", "critical"}:
        last_event_ts = float(entry.get("last_risk_event_at") or 0.0)
        if now - last_event_ts >= ABUSE_MULTI_IP_RISK_EVENT_MIN_INTERVAL_SECONDS:
            events.append(
                {
                    "ts": float(now),
                    "risk_level": risk_level,
                    "ip_count": int(ip_count),
                    "prefix_count": int(prefix_count),
                    "new_ip_count": int(new_ip_count),
                    "burst_score": int(burst_score),
                }
            )
            entry["last_risk_event_at"] = float(now)
            HISTORY_DIRTY = True

    level_counts: dict[str, int] = {}
    for item in events:
        level = str(item.get("risk_level") or "")
        if level:
            level_counts[level] = int(level_counts.get(level, 0)) + 1

    return {
        "repeat_count": len(events),
        "repeat_level_counts": level_counts,
        "last_risk_seen_at": utc_iso(float(events[-1].get("ts"))) if events else "",
    }


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


def ip_prefix(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except Exception:
        return None

    try:
        if ip.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/56", strict=False))
    except Exception:
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
            remember_multi_ip_history(email, ts, source_ip)
        remember_abuse_event(email, ts, source_ip, target)
        LAST_LINE_AT = now


def purge_stale(now: float | None = None) -> None:
    global HISTORY_DIRTY
    now = now or time.time()
    cutoff = now - WINDOW_SECONDS
    abuse_cutoff = now - ABUSE_AUDIT_WINDOW_SECONDS
    with LOCK:
        history_users = MULTI_IP_HISTORY.setdefault("users", {})
        history_ip_cutoff = now - ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS
        history_event_cutoff = now - ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS
        for email in list(history_users.keys()):
            history_entry = history_users.get(email) or {}
            history_ips = history_entry.get("ips") if isinstance(history_entry.get("ips"), dict) else {}
            for ip, item in list(history_ips.items()):
                if not isinstance(item, dict) or float(item.get("last_seen") or 0.0) < history_ip_cutoff:
                    history_ips.pop(ip, None)
                    HISTORY_DIRTY = True
            events = history_entry.get("risk_events") if isinstance(history_entry.get("risk_events"), list) else []
            history_entry["risk_events"] = [
                item
                for item in events
                if isinstance(item, dict) and float(item.get("ts") or 0.0) >= history_event_cutoff
            ]
            if not history_ips and not history_entry["risk_events"]:
                history_users.pop(email, None)
                HISTORY_DIRTY = True

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


def _multi_ip_risk_level(ip_count: int, prefix_count: int) -> str:
    if ip_count >= ABUSE_MULTI_IP_CRITICAL_IPS:
        return "critical"
    if ip_count >= ABUSE_MULTI_IP_HIGH_IPS:
        return "high"
    if ip_count >= ABUSE_MULTI_IP_SUSPICIOUS_IPS:
        return "suspicious"
    if ip_count >= ABUSE_MULTI_IP_OBSERVE_IPS:
        return "observe"
    return "normal"


def _multi_ip_risk_score(ip_count: int, prefix_count: int, event_count: int) -> int:
    score = ip_count * 10 + prefix_count * 8
    if event_count >= 100:
        score += 20
    elif event_count >= 30:
        score += 10
    return int(score)


def _window_ip_stats(ips_raw: dict, now: float, windows: list[int], history_ips: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for window in windows:
        cutoff = now - int(window)
        ips = [
            ip
            for ip, seen in sorted(ips_raw.items(), key=lambda item: float(item[1]), reverse=True)
            if float(seen) >= cutoff
        ][:MAX_IPS_PER_USER]
        prefixes = sorted({prefix for ip in ips for prefix in [ip_prefix(ip)] if prefix})
        new_ips = []
        known_ips = []
        for ip in ips:
            history_item = history_ips.get(ip) if isinstance(history_ips, dict) else None
            first_seen = float((history_item or {}).get("first_seen") or 0.0) if isinstance(history_item, dict) else 0.0
            if first_seen >= cutoff:
                new_ips.append(ip)
            else:
                known_ips.append(ip)
        out[str(window)] = {
            "window_seconds": int(window),
            "ip_count": len(ips),
            "prefix_count": len(prefixes),
            "new_ip_count": len(new_ips),
            "known_ip_count": len(known_ips),
            "ips": ips,
            "new_ips": new_ips,
            "prefixes": prefixes,
        }
    return out


def _event_stats_by_window(events: list[dict], now: float, windows: list[int]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for window in windows:
        cutoff = now - int(window)
        filtered = [
            item
            for item in events
            if float(item.get("ts") or 0.0) >= cutoff
        ]
        targets = set()
        ports = set()
        for item in filtered:
            host = str(item.get("host") or "").strip()
            port = int(item.get("port") or 0)
            if host or port:
                targets.add(f"{host}:{port}" if port else host)
            if port:
                ports.add(port)
        out[str(window)] = {
            "window_seconds": int(window),
            "event_count": len(filtered),
            "target_count": len(targets),
            "port_count": len(ports),
        }
    return out


def _traffic_window_stats(email: str, now: float, windows: list[int]) -> dict[str, dict]:
    with LOCK:
        samples = [
            dict(item)
            for item in USER_TRAFFIC_HISTORY.get(email, [])
            if isinstance(item, dict)
        ]

    samples.sort(key=lambda item: float(item.get("ts") or 0.0))
    out: dict[str, dict] = {}
    latest = samples[-1] if samples else None

    for window in windows:
        window = int(window)
        cutoff = now - window
        baseline = None
        for sample in samples:
            ts = float(sample.get("ts") or 0.0)
            if ts <= cutoff:
                baseline = sample
            else:
                break

        if baseline is None:
            for sample in samples:
                if float(sample.get("ts") or 0.0) >= cutoff:
                    baseline = sample
                    break

        delta_total = 0
        delta_up = 0
        delta_down = 0
        rate_bps = None
        covered_seconds = 0
        complete = False
        if latest is not None and baseline is not None and latest is not baseline:
            latest_total = int(latest.get("traffic_total_bytes") or 0)
            baseline_total = int(baseline.get("traffic_total_bytes") or 0)
            latest_up = int(latest.get("traffic_up_bytes") or 0)
            baseline_up = int(baseline.get("traffic_up_bytes") or 0)
            latest_down = int(latest.get("traffic_down_bytes") or 0)
            baseline_down = int(baseline.get("traffic_down_bytes") or 0)
            if latest_total >= baseline_total:
                delta_total = latest_total - baseline_total
                delta_up = max(0, latest_up - baseline_up)
                delta_down = max(0, latest_down - baseline_down)
                covered_seconds = max(0, int(float(latest.get("ts") or 0.0) - float(baseline.get("ts") or 0.0)))
                if covered_seconds > 0:
                    rate_bps = int((delta_total * 8) / covered_seconds)
                complete = (
                    abs(float(baseline.get("ts") or 0.0) - cutoff) <= 5.0
                    and covered_seconds <= window + 5
                )

        out[str(window)] = {
            "window_seconds": window,
            "traffic_up_bytes": int(delta_up),
            "traffic_down_bytes": int(delta_down),
            "traffic_total_bytes": int(delta_total),
            "average_bps": rate_bps,
            "covered_seconds": int(covered_seconds),
            "complete": bool(complete),
        }

    return out


def _traffic_load_level(load_bps: int | None, window_total_bytes: int) -> str:
    load = int(load_bps or 0)
    window_total = int(window_total_bytes or 0)
    if load >= 100_000_000 or window_total >= 2 * 1024 * 1024 * 1024:
        return "heavy"
    if load >= 50_000_000 or window_total >= 1024 * 1024 * 1024:
        return "high"
    if load >= 10_000_000 or window_total >= 256 * 1024 * 1024:
        return "noticeable"
    if load >= 1_000_000 or window_total >= 32 * 1024 * 1024:
        return "normal"
    return "low"


def _traffic_priority(load_bps: int | None, window_total_bytes: int) -> int:
    load = int(load_bps or 0)
    window_total = int(window_total_bytes or 0)
    return int(load // 1000 + window_total // (1024 * 1024))


def _burst_score(
    *,
    ip_count: int,
    prefix_count: int,
    new_ip_count: int,
    event_count: int,
    short_ip_count: int,
    repeat_count: int,
) -> int:
    score = ip_count * 8 + prefix_count * 8 + new_ip_count * 14 + short_ip_count * 10
    if event_count >= 500:
        score += 35
    elif event_count >= 100:
        score += 20
    elif event_count >= 30:
        score += 10
    if repeat_count >= 3:
        score += 25
    elif repeat_count >= 1:
        score += 10
    return int(score)


def build_multi_ip_abuse(window_seconds: int | None = None) -> dict:
    now = time.time()
    window = max(10, min(int(window_seconds or WINDOW_SECONDS), 3600))
    windows = sorted({*ABUSE_MULTI_IP_WINDOWS, window})
    main_window = str(window)
    history_cutoff = now - max(windows)
    purge_stale(now)

    with LOCK:
        client_items = [(email, dict(entry)) for email, entry in CLIENTS.items()]
        history_users = json.loads(json.dumps(MULTI_IP_HISTORY.get("users") or {}, ensure_ascii=False))
        traffic_by_email = json.loads(json.dumps(USER_TRAFFIC, ensure_ascii=False))
        abuse_events = [
            dict(item)
            for item in ABUSE_EVENTS
            if float(item.get("ts") or 0.0) >= history_cutoff
        ]

    users = []
    counters = {"observe": 0, "suspicious": 0, "high": 0, "critical": 0}

    for email, entry in client_items:
        try:
            last_seen = float(entry.get("last_seen") or 0.0)
        except Exception:
            continue
        if last_seen < now - window:
            continue

        ips_raw = entry.get("ips") if isinstance(entry.get("ips"), dict) else {}
        history_entry = history_users.get(email) if isinstance(history_users.get(email), dict) else {}
        history_ips = history_entry.get("ips") if isinstance(history_entry.get("ips"), dict) else {}
        window_stats = _window_ip_stats(ips_raw, now, windows, history_ips)
        recent_window = window_stats.get(main_window) or {}
        recent_ips = list(recent_window.get("ips") or [])
        ip_count = len(recent_ips)
        if ip_count < ABUSE_MULTI_IP_OBSERVE_IPS:
            continue

        prefixes = list(recent_window.get("prefixes") or [])
        prefix_count = int(recent_window.get("prefix_count") or 0)
        new_ip_count = int(recent_window.get("new_ip_count") or 0)
        known_ip_count = int(recent_window.get("known_ip_count") or 0)
        email_events = [
            item
            for item in abuse_events
            if str(item.get("email") or "").strip() == email
        ]
        event_windows = _event_stats_by_window(email_events, now, windows)
        event_info = event_windows.get(main_window) or {}
        traffic = traffic_by_email.get(email) if isinstance(traffic_by_email.get(email), dict) else {}
        traffic_windows = _traffic_window_stats(email, now, windows)
        traffic_window = traffic_windows.get(main_window) or {}
        load_bps = (
            int(traffic.get("load_bps"))
            if traffic.get("load_bps") is not None
            else None
        )
        window_traffic_total = int(traffic_window.get("traffic_total_bytes") or 0)
        traffic_level = _traffic_load_level(load_bps, window_traffic_total)
        traffic_priority = _traffic_priority(load_bps, window_traffic_total)
        event_count = int(event_info.get("event_count") or 0)
        target_count = int(event_info.get("target_count") or 0)
        port_count = int(event_info.get("port_count") or 0)
        risk_level = _multi_ip_risk_level(ip_count, prefix_count)
        short_window_key = str(min(windows))
        short_ip_count = int((window_stats.get(short_window_key) or {}).get("ip_count") or 0)
        history_summary = record_multi_ip_risk_event(
            email,
            now,
            risk_level="normal",
            ip_count=ip_count,
            prefix_count=prefix_count,
            new_ip_count=new_ip_count,
            burst_score=0,
        )
        repeat_count = int(history_summary.get("repeat_count") or 0)
        burst_score = _burst_score(
            ip_count=ip_count,
            prefix_count=prefix_count,
            new_ip_count=new_ip_count,
            event_count=event_count,
            short_ip_count=short_ip_count,
            repeat_count=repeat_count,
        )
        history_summary = record_multi_ip_risk_event(
            email,
            now,
            risk_level=risk_level,
            ip_count=ip_count,
            prefix_count=prefix_count,
            new_ip_count=new_ip_count,
            burst_score=burst_score,
        )
        repeat_count = int(history_summary.get("repeat_count") or repeat_count)
        if risk_level in counters:
            counters[risk_level] += 1

        reasons = [f"{ip_count} IP за {window} секунд"]
        if short_ip_count >= ABUSE_MULTI_IP_SUSPICIOUS_IPS:
            reasons.append(f"{short_ip_count} IP уже за {short_window_key} секунд")
        if new_ip_count >= ABUSE_MULTI_IP_SUSPICIOUS_IPS:
            reasons.append(f"{new_ip_count} новых IP за {window} секунд")
        if prefix_count:
            reasons.append(f"{prefix_count} разных подсетей")
        if repeat_count >= 2:
            reasons.append(f"{repeat_count} повторов риска за {ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS // 3600 or 1} ч")
        if event_count >= 30:
            reasons.append(f"{event_count} подключений/записей access.log")
        if target_count >= 10:
            reasons.append(f"{target_count} разных целей")
        if risk_level in {"high", "critical"} and prefix_count < ABUSE_MULTI_IP_MIN_PREFIXES:
            reasons.append("много IP, но мало разных подсетей: проверьте вручную")

        users.append(
            {
                "email": email,
                "risk_level": risk_level,
                "evidence_strength": "strong" if prefix_count >= ABUSE_MULTI_IP_MIN_PREFIXES else "medium",
                "risk_score": _multi_ip_risk_score(ip_count, prefix_count, event_count),
                "burst_score": burst_score,
                "ip_count": ip_count,
                "prefix_count": prefix_count,
                "new_ip_count": new_ip_count,
                "known_ip_count": known_ip_count,
                "prefixes": prefixes[:ABUSE_AUDIT_TOP_LIMIT],
                "ips": recent_ips,
                "new_ips": list(recent_window.get("new_ips") or [])[:ABUSE_AUDIT_TOP_LIMIT],
                "window_ip_counts": window_stats,
                "window_event_counts": event_windows,
                "repeat_count": repeat_count,
                "repeat_level_counts": history_summary.get("repeat_level_counts") or {},
                "last_risk_seen_at": str(history_summary.get("last_risk_seen_at") or ""),
                "event_count": event_count,
                "target_count": target_count,
                "port_count": port_count,
                "traffic": {
                    "traffic_source": str(traffic.get("traffic_source") or ""),
                    "traffic_up_bytes": int(traffic.get("traffic_up_bytes") or 0),
                    "traffic_down_bytes": int(traffic.get("traffic_down_bytes") or 0),
                    "traffic_total_bytes": int(traffic.get("traffic_total_bytes") or 0),
                    "load_bps": load_bps,
                    "load_level": traffic_level,
                    "traffic_priority": traffic_priority,
                    "window_traffic": traffic_window,
                    "window_traffic_counts": traffic_windows,
                    "stats_checked_at": str(traffic.get("stats_checked_at") or ""),
                },
                "last_seen_at": utc_iso(last_seen) if last_seen else "",
                "last_seen_age_seconds": max(0, int(now - last_seen)) if last_seen else -1,
                "reasons": reasons,
            }
        )

    risk_order = {"critical": 4, "high": 3, "suspicious": 2, "observe": 1, "normal": 0}
    users.sort(
        key=lambda item: (
            int(((item.get("traffic") or {}).get("traffic_priority") or 0)),
            int(((item.get("traffic") or {}).get("load_bps") or 0)),
            int((((item.get("traffic") or {}).get("window_traffic") or {}).get("traffic_total_bytes") or 0)),
            risk_order.get(str(item.get("risk_level") or ""), 0),
            int(item.get("burst_score") or 0),
            int(item.get("risk_score") or 0),
            int(item.get("ip_count") or 0),
        ),
        reverse=True,
    )
    save_multi_ip_history()

    return {
        "ok": True,
        "source": "vpnbot_xray_multi_ip_abuse",
        "is_recent_activity": True,
        "access_log": str(ACCESS_LOG),
        "window_seconds": window,
        "thresholds": {
            "observe_ips": ABUSE_MULTI_IP_OBSERVE_IPS,
            "suspicious_ips": ABUSE_MULTI_IP_SUSPICIOUS_IPS,
            "high_ips": ABUSE_MULTI_IP_HIGH_IPS,
            "critical_ips": ABUSE_MULTI_IP_CRITICAL_IPS,
            "min_prefixes": ABUSE_MULTI_IP_MIN_PREFIXES,
            "windows": windows,
            "repeat_window_seconds": ABUSE_MULTI_IP_REPEAT_WINDOW_SECONDS,
            "known_ip_ttl_seconds": ABUSE_MULTI_IP_KNOWN_IP_TTL_SECONDS,
        },
        "counts": counters,
        "suspect_count": len(users),
        "top_limit": ABUSE_MULTI_IP_TOP_LIMIT,
        "users": users[:ABUSE_MULTI_IP_TOP_LIMIT],
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


def extract_user_traffic(payload: dict) -> dict[str, dict]:
    users: dict[str, dict] = {}
    stats = payload.get("stat")
    if not isinstance(stats, list):
        return users

    for item in stats:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name.startswith("user>>>") or ">>>traffic>>>" not in name:
            continue
        parts = name.split(">>>")
        if len(parts) < 4:
            continue
        email = str(parts[1] or "").strip()
        direction = str(parts[-1] or "").strip().lower()
        if not email:
            continue
        try:
            value = int(item.get("value") or 0)
        except Exception:
            value = 0
        if value < 0:
            value = 0

        entry = users.setdefault(
            email,
            {
                "traffic_up_bytes": 0,
                "traffic_down_bytes": 0,
                "traffic_total_bytes": 0,
            },
        )
        if direction == "uplink":
            entry["traffic_up_bytes"] += value
        elif direction == "downlink":
            entry["traffic_down_bytes"] += value

    for entry in users.values():
        entry["traffic_total_bytes"] = int(entry.get("traffic_up_bytes") or 0) + int(
            entry.get("traffic_down_bytes") or 0
        )
    return users


def update_user_traffic(user_totals: dict[str, dict], now: float) -> None:
    with LOCK:
        max_history_age = max([*ABUSE_MULTI_IP_WINDOWS, WINDOW_SECONDS]) + max(STATS_INTERVAL * 3, 180.0)
        history_cutoff = now - max_history_age
        for email, totals in user_totals.items():
            new_total = int(totals.get("traffic_total_bytes") or 0)
            new_up = int(totals.get("traffic_up_bytes") or 0)
            new_down = int(totals.get("traffic_down_bytes") or 0)
            previous = USER_TRAFFIC.get(email) or {}
            previous_total = int(previous.get("traffic_total_bytes") or 0)
            previous_checked_at = float(previous.get("_checked_at_ts") or 0.0)
            load_bps = None
            if previous_checked_at > 0 and new_total >= previous_total:
                delta_seconds = max(0.001, now - previous_checked_at)
                if delta_seconds >= max(5.0, STATS_INTERVAL * 0.5):
                    load_bps = int(((new_total - previous_total) * 8) / delta_seconds)

            USER_TRAFFIC[email] = {
                "traffic_source": "xray_stats_user",
                "traffic_up_bytes": new_up,
                "traffic_down_bytes": new_down,
                "traffic_total_bytes": new_total,
                "load_bps": load_bps,
                "stats_checked_at": utc_iso(now),
                "_checked_at_ts": now,
            }
            history = USER_TRAFFIC_HISTORY.setdefault(email, [])
            history.append(
                {
                    "ts": float(now),
                    "traffic_up_bytes": new_up,
                    "traffic_down_bytes": new_down,
                    "traffic_total_bytes": new_total,
                }
            )
            history[:] = [
                item
                for item in history
                if isinstance(item, dict) and float(item.get("ts") or 0.0) >= history_cutoff
            ][-200:]


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
    user_payload = None
    if int(totals.get("traffic_total_bytes") or 0) <= 0:
        source = "xray_stats_user_fallback"
        user_payload = query_xray_stats("user>>>")
        totals = extract_traffic_totals(user_payload, prefix="user>>>")
    else:
        try:
            user_payload = query_xray_stats("user>>>")
        except Exception:
            user_payload = None

    if isinstance(user_payload, dict):
        update_user_traffic(extract_user_traffic(user_payload), now)

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
        user_traffic = json.loads(json.dumps(USER_TRAFFIC, ensure_ascii=False))
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
            "traffic": user_traffic.get(email) if isinstance(user_traffic.get(email), dict) else {},
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
            "multi_ip_endpoint": "/abuse/multi-ip",
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
            save_multi_ip_history()
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
        if parsed.path == "/abuse/multi-ip":
            query = parse_qs(parsed.query)
            window = None
            if "window" in query and query["window"]:
                try:
                    window = int(query["window"][0])
                except Exception:
                    window = None
            self._send_json(200, build_multi_ip_abuse(window))
            return
        self._send_json(404, {"ok": False, "error": "not_found"})


STARTED_AT = utc_iso()


def main() -> None:
    load_multi_ip_history()
    worker = threading.Thread(target=tail_access_log, name="xray-access-log-tail", daemon=True)
    worker.start()
    stats = threading.Thread(target=stats_worker, name="xray-stats-poll", daemon=True)
    stats.start()
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
