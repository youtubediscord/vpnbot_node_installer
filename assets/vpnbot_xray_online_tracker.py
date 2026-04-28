#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import hashlib
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


TRACKER_VERSION = "2026-04-28.3"
ACCESS_LOG = Path(os.environ.get("XRAY_ONLINE_ACCESS_LOG", "/opt/vpnbot/xray-core/logs/access.log"))
MANAGED_INBOUNDS_FILE = Path(
    os.environ.get(
        "XRAY_MANAGED_INBOUNDS_FILE",
        "/opt/vpnbot/xray-core/config/50_vpnbot_managed_inbounds.json",
    )
)
BIND_HOST = os.environ.get("XRAY_ONLINE_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("XRAY_ONLINE_BIND_PORT", "10086"))
WINDOW_SECONDS = max(10, min(int(os.environ.get("XRAY_ONLINE_WINDOW_SECONDS", "180")), 3600))
BOOTSTRAP_BYTES = max(64 * 1024, min(int(os.environ.get("XRAY_ONLINE_BOOTSTRAP_BYTES", "524288")), 8 * 1024 * 1024))
POLL_INTERVAL = max(0.05, min(float(os.environ.get("XRAY_ONLINE_POLL_INTERVAL", "0.2")), 5.0))
MAINTENANCE_INTERVAL = max(
    1.0,
    min(float(os.environ.get("XRAY_ONLINE_MAINTENANCE_INTERVAL_SECONDS", "5")), 60.0),
)
MAX_LOG_LINES_PER_SECOND = max(
    50,
    min(int(os.environ.get("XRAY_ONLINE_MAX_LOG_LINES_PER_SECOND", "300")), 5000),
)
LOG_SAMPLE_EVERY_OVER_LIMIT = max(
    0,
    min(int(os.environ.get("XRAY_ONLINE_LOG_SAMPLE_EVERY_OVER_LIMIT", "25")), 1000),
)
MAX_IPS_PER_USER = max(1, min(int(os.environ.get("XRAY_ONLINE_MAX_IPS_PER_USER", "20")), 100))
XRAY_BIN = os.environ.get("XRAY_ONLINE_XRAY_BIN", "/opt/vpnbot/xray-core/bin/xray")
XRAY_API_SERVER = os.environ.get("XRAY_ONLINE_XRAY_API_SERVER", "127.0.0.1:10085")
STATS_INTERVAL = max(5.0, min(float(os.environ.get("XRAY_ONLINE_STATS_INTERVAL_SECONDS", "120")), 300.0))
USER_STATS_INTERVAL = max(
    STATS_INTERVAL,
    min(float(os.environ.get("XRAY_ONLINE_USER_STATS_INTERVAL_SECONDS", "300")), 1800.0),
)
SS_BIN = os.environ.get("XRAY_ONLINE_SS_BIN", "ss")
PER_IP_TRAFFIC_STALE_SECONDS = max(
    15.0,
    min(float(os.environ.get("XRAY_ABUSE_PER_IP_TRAFFIC_STALE_SECONDS", "180")), 900.0),
)
PER_IP_TRAFFIC_MAX_SS_LINES = max(
    1000,
    min(int(os.environ.get("XRAY_ABUSE_PER_IP_TRAFFIC_MAX_SS_LINES", "50000")), 500000),
)
CONNECTION_TOP_CACHE_TTL_SECONDS = max(
    5.0,
    min(float(os.environ.get("XRAY_CONNECTION_TOP_CACHE_TTL_SECONDS", "30")), 300.0),
)
CONNECTION_TOP_LIMIT = max(
    3,
    min(int(os.environ.get("XRAY_CONNECTION_TOP_LIMIT", "10")), 50),
)
CONNECTION_TOP_MAX_ROWS = max(
    10_000,
    min(int(os.environ.get("XRAY_CONNECTION_TOP_MAX_ROWS", "80000")), 1_000_000),
)
CONN_GUARD_STATE_DIR = Path(
    os.environ.get("XRAY_CONN_GUARD_STATE_DIR", "/var/lib/vpnbot-xray-conn-guard")
)
CONN_GUARD_BAN_STATE_FILE = Path(
    os.environ.get("XRAY_CONN_GUARD_BAN_STATE_FILE", str(CONN_GUARD_STATE_DIR / "bans.json"))
)
CONN_GUARD_EVENTS_FILE = Path(
    os.environ.get("XRAY_CONN_GUARD_EVENTS_FILE", str(CONN_GUARD_STATE_DIR / "events.jsonl"))
)
SOCKET_OVERLOAD_EVENTS_FILE = Path(
    os.environ.get(
        "XRAY_SOCKET_OVERLOAD_EVENTS_FILE",
        "/var/lib/vpnbot-xray-online/socket_overload_events.jsonl",
    )
)
SOCKET_OVERLOAD_AUTO_HEAL_ENABLED = (
    str(os.environ.get("XRAY_SOCKET_OVERLOAD_AUTO_HEAL_ENABLED", "1")).strip().lower() in {"1", "true", "yes", "on"}
)
SOCKET_OVERLOAD_WARN_ROWS = max(
    1000,
    int(os.environ.get("XRAY_SOCKET_OVERLOAD_WARN_ROWS", "40000") or "40000"),
)
SOCKET_OVERLOAD_CONSECUTIVE = max(
    2,
    min(int(os.environ.get("XRAY_SOCKET_OVERLOAD_CONSECUTIVE", "2") or "2"), 10),
)
SOCKET_OVERLOAD_GUARD_SERVICE = os.environ.get(
    "XRAY_SOCKET_OVERLOAD_GUARD_SERVICE",
    "vpnbot-xray-conn-guard.service",
)
SOCKET_OVERLOAD_XRAY_SERVICE = os.environ.get(
    "XRAY_SOCKET_OVERLOAD_XRAY_SERVICE",
    "vpnbot-xray.service",
)
SOCKET_OVERLOAD_GUARD_RESTART_COOLDOWN_SECONDS = max(
    60,
    min(int(os.environ.get("XRAY_SOCKET_OVERLOAD_GUARD_RESTART_COOLDOWN_SECONDS", "300") or "300"), 3600),
)
SOCKET_OVERLOAD_XRAY_RESTART_COOLDOWN_SECONDS = max(
    300,
    min(int(os.environ.get("XRAY_SOCKET_OVERLOAD_XRAY_RESTART_COOLDOWN_SECONDS", "1800") or "1800"), 86400),
)
SOCKET_OVERLOAD_XRAY_AFTER_GUARD_SECONDS = max(
    30,
    min(int(os.environ.get("XRAY_SOCKET_OVERLOAD_XRAY_AFTER_GUARD_SECONDS", "60") or "60"), 1800),
)
TRUTHY_VALUES = {"1", "true", "yes", "on"}
PER_IP_ACTIVE_BPS = max(0, int(os.environ.get("XRAY_ABUSE_PER_IP_ACTIVE_BPS", "1000000")))
PER_IP_HEAVY_BPS = max(PER_IP_ACTIVE_BPS, int(os.environ.get("XRAY_ABUSE_PER_IP_HEAVY_BPS", "5000000")))
ABUSE_AUDIT_REQUESTED = str(os.environ.get("XRAY_ABUSE_AUDIT_ENABLED", "0")).strip().lower() in TRUTHY_VALUES
# Не включать в production обычной переменной XRAY_ABUSE_AUDIT_ENABLED.
# Этот аудит хранит цели/порты по каждой строке access.log и оказался слишком
# дорогим на горячих нодах. Для multi-IP abuse достаточно смены IP и текущего
# per-IP трафика, поэтому подробный target-аудит заперт отдельным force-флагом.
ABUSE_AUDIT_FORCE_ENABLE = (
    str(os.environ.get("XRAY_ABUSE_AUDIT_FORCE_ENABLE", "0")).strip().lower() in TRUTHY_VALUES
)
ABUSE_AUDIT_ENABLED = ABUSE_AUDIT_REQUESTED and ABUSE_AUDIT_FORCE_ENABLE
ABUSE_AUDIT_DISABLED_REASON = (
    "locked_high_overhead"
    if ABUSE_AUDIT_REQUESTED and not ABUSE_AUDIT_FORCE_ENABLE
    else "default_off_high_overhead"
    if not ABUSE_AUDIT_ENABLED
    else ""
)
ABUSE_HISTORY_TOUCH_INTERVAL_SECONDS = max(
    0.0,
    min(float(os.environ.get("XRAY_ABUSE_HISTORY_TOUCH_INTERVAL_SECONDS", "5")), 300.0),
)
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
ABUSE_MULTI_IP_CACHE_TTL_SECONDS = max(
    0.0,
    min(float(os.environ.get("XRAY_ABUSE_MULTI_IP_CACHE_TTL_SECONDS", "10")), 60.0),
)

LOCK = threading.RLock()
CLIENTS: dict[str, dict] = {}
ABUSE_EVENTS: list[dict] = []
MULTI_IP_HISTORY: dict[str, dict] = {"users": {}}
USER_TRAFFIC: dict[str, dict] = {}
USER_TRAFFIC_HISTORY: dict[str, list[dict]] = {}
IP_TRAFFIC: dict[str, dict] = {}
IP_TRAFFIC_HISTORY: dict[str, list[dict]] = {}
SOCKET_TRAFFIC_SAMPLES: dict[str, dict] = {}
SOCKET_TRAFFIC_STATUS: dict[str, object] = {
    "status": "unknown",
    "checked_at": "",
    "checked_at_ts": 0.0,
    "socket_rows_seen": 0,
    "max_ss_lines": PER_IP_TRAFFIC_MAX_SS_LINES,
    "unavailable_reason": "",
}
SOCKET_OVERLOAD_STATE: dict[str, object] = {
    "consecutive_high": 0,
    "last_socket_rows_seen": 0,
    "last_checked_at": "",
    "last_checked_at_ts": 0.0,
    "last_guard_restart_at": "",
    "last_guard_restart_at_ts": 0.0,
    "last_xray_restart_at": "",
    "last_xray_restart_at_ts": 0.0,
    "last_action": "",
    "last_error": "",
}
MULTI_IP_ABUSE_CACHE: dict[str, tuple[float, dict]] = {}
CONNECTION_TOP_CACHE: tuple[float, dict] | None = None
HISTORY_DIRTY = False
LAST_HISTORY_SAVE_AT = 0.0
LAST_LINE_AT = 0.0
LAST_ERROR = ""
PROCESSED_LOG_LINES = 0
SKIPPED_LOG_LINES = 0
LAST_USER_STATS_AT = 0.0
TRAFFIC = {
    "traffic_source": "xray_stats_unavailable",
    "traffic_up_bytes": 0,
    "traffic_down_bytes": 0,
    "traffic_total_bytes": 0,
    "load_bps": None,
    "stats_checked_at": "",
    "stats_last_error": "",
}


def script_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except Exception:
        return ""


def health_payload() -> dict:
    per_ip_status = _socket_traffic_status_snapshot(time.time())
    auto_guard = _socket_overload_health_snapshot(time.time())
    connection_guard = _connection_guard_health_snapshot(time.time())
    return {
        "ok": True,
        "source": "vpnbot_xray_online_tracker",
        "version": TRACKER_VERSION,
        "started_at": STARTED_AT,
        "features": {
            "online": True,
            "abuse_audit": ABUSE_AUDIT_ENABLED,
            "abuse_multi_ip": True,
            "multi_ip_cache": ABUSE_MULTI_IP_CACHE_TTL_SECONDS > 0,
            "per_ip_traffic": True,
            "connection_top": True,
        },
        "abuse_audit": {
            "enabled": ABUSE_AUDIT_ENABLED,
            "requested": ABUSE_AUDIT_REQUESTED,
            "force_enabled": ABUSE_AUDIT_FORCE_ENABLE,
            "disabled_reason": ABUSE_AUDIT_DISABLED_REASON,
        },
        "multi_ip_cache_ttl_seconds": ABUSE_MULTI_IP_CACHE_TTL_SECONDS,
        "abuse_history_touch_interval_seconds": ABUSE_HISTORY_TOUCH_INTERVAL_SECONDS,
        "per_ip_traffic": {
            "source": "ss_tcp_info",
            "status": per_ip_status.get("status") or "unknown",
            "checked_at": per_ip_status.get("checked_at") or "",
            "checked_age_seconds": int(per_ip_status.get("checked_age_seconds") or -1),
            "socket_rows_seen": int(per_ip_status.get("socket_rows_seen") or 0),
            "ss_bin": SS_BIN,
            "active_bps": PER_IP_ACTIVE_BPS,
            "heavy_bps": PER_IP_HEAVY_BPS,
            "stale_seconds": PER_IP_TRAFFIC_STALE_SECONDS,
            "max_ss_lines": PER_IP_TRAFFIC_MAX_SS_LINES,
            "unavailable_reason": per_ip_status.get("unavailable_reason") or "",
        },
        "connection_top": {
            "endpoint": "/connections/top",
            "cache_ttl_seconds": CONNECTION_TOP_CACHE_TTL_SECONDS,
            "top_limit": CONNECTION_TOP_LIMIT,
            "max_rows": CONNECTION_TOP_MAX_ROWS,
        },
        "auto_guard": auto_guard,
        "connection_guard": connection_guard,
        "access_log": str(ACCESS_LOG),
        "script_path": str(Path(__file__)),
        "script_sha256": script_sha256(),
        "bind": f"{BIND_HOST}:{BIND_PORT}",
        "window_seconds": WINDOW_SECONDS,
        "maintenance_interval_seconds": MAINTENANCE_INTERVAL,
        "max_log_lines_per_second": MAX_LOG_LINES_PER_SECOND,
        "log_sample_every_over_limit": LOG_SAMPLE_EVERY_OVER_LIMIT,
        "processed_log_lines": PROCESSED_LOG_LINES,
        "skipped_log_lines": SKIPPED_LOG_LINES,
        "stats_interval_seconds": STATS_INTERVAL,
        "user_stats_interval_seconds": USER_STATS_INTERVAL,
        "xray_api_server": XRAY_API_SERVER,
    }


def utc_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).isoformat()


def _tail_jsonl(path: Path, limit: int = 20) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: list[dict] = []
    for raw in lines[-max(1, limit) :]:
        try:
            item = json.loads(raw)
        except Exception:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _load_connection_guard_bans(now: float) -> list[dict]:
    try:
        payload = json.loads(CONN_GUARD_BAN_STATE_FILE.read_text(encoding="utf-8") or "{}")
    except Exception:
        return []
    bans = payload.get("bans") if isinstance(payload, dict) else []
    out: list[dict] = []
    for item in bans if isinstance(bans, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            expires_at_ts = float(item.get("expires_at_ts") or 0.0)
        except Exception:
            expires_at_ts = 0.0
        if expires_at_ts > now:
            out.append(dict(item))
    return out


def _connection_guard_health_snapshot(now: float) -> dict:
    bans = _load_connection_guard_bans(now)
    events = _tail_jsonl(CONN_GUARD_EVENTS_FILE, limit=20)
    return {
        "enabled": True,
        "state_dir": str(CONN_GUARD_STATE_DIR),
        "ban_state_file": str(CONN_GUARD_BAN_STATE_FILE),
        "events_file": str(CONN_GUARD_EVENTS_FILE),
        "active_ban_count": len(bans),
        "active_bans": bans[:20],
        "recent_events": events[-10:],
    }


def _socket_overload_health_snapshot(now: float) -> dict:
    with LOCK:
        state = dict(SOCKET_OVERLOAD_STATE)
    state.update(
        {
            "enabled": SOCKET_OVERLOAD_AUTO_HEAL_ENABLED,
            "warn_rows": SOCKET_OVERLOAD_WARN_ROWS,
            "consecutive_threshold": SOCKET_OVERLOAD_CONSECUTIVE,
            "guard_service": SOCKET_OVERLOAD_GUARD_SERVICE,
            "xray_service": SOCKET_OVERLOAD_XRAY_SERVICE,
            "events_file": str(SOCKET_OVERLOAD_EVENTS_FILE),
            "recent_events": _tail_jsonl(SOCKET_OVERLOAD_EVENTS_FILE, limit=10),
        }
    )
    checked_at_ts = float(state.get("last_checked_at_ts") or 0.0)
    state["last_checked_age_seconds"] = int(max(0, now - checked_at_ts)) if checked_at_ts > 0 else -1
    return state


def _append_socket_overload_event(event: dict) -> None:
    try:
        SOCKET_OVERLOAD_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ts": int(time.time()),
            "at": utc_iso(),
            **event,
        }
        with SOCKET_OVERLOAD_EVENTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass


def _systemctl_restart(service_name: str, timeout_seconds: int = 20) -> tuple[bool, str]:
    if not service_name:
        return False, "empty service name"
    proc = subprocess.run(
        ["systemctl", "restart", service_name],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    text = (proc.stderr or proc.stdout or "").strip()
    return proc.returncode == 0, text[-500:]


def _maybe_handle_socket_overload(now: float, socket_rows: int, *, limited: bool) -> None:
    if not SOCKET_OVERLOAD_AUTO_HEAL_ENABLED:
        return

    with LOCK:
        state = SOCKET_OVERLOAD_STATE
        state["last_socket_rows_seen"] = int(max(0, socket_rows))
        state["last_checked_at"] = utc_iso(now)
        state["last_checked_at_ts"] = float(now)
        if socket_rows >= SOCKET_OVERLOAD_WARN_ROWS:
            state["consecutive_high"] = int(state.get("consecutive_high") or 0) + 1
        else:
            state["consecutive_high"] = 0
            state["last_error"] = ""
            return

        consecutive = int(state.get("consecutive_high") or 0)
        last_guard = float(state.get("last_guard_restart_at_ts") or 0.0)
        last_xray = float(state.get("last_xray_restart_at_ts") or 0.0)

    if consecutive < SOCKET_OVERLOAD_CONSECUTIVE:
        return

    action = ""
    service = ""
    if now - last_guard >= SOCKET_OVERLOAD_GUARD_RESTART_COOLDOWN_SECONDS:
        action = "restart_connection_guard"
        service = SOCKET_OVERLOAD_GUARD_SERVICE
    elif (
        last_guard > 0
        and now - last_guard >= SOCKET_OVERLOAD_XRAY_AFTER_GUARD_SECONDS
        and now - last_xray >= SOCKET_OVERLOAD_XRAY_RESTART_COOLDOWN_SECONDS
    ):
        action = "restart_xray"
        service = SOCKET_OVERLOAD_XRAY_SERVICE
    else:
        return

    ok, detail = _systemctl_restart(service)
    event = {
        "event": action,
        "service": service,
        "ok": ok,
        "socket_rows_seen": int(socket_rows),
        "warn_rows": SOCKET_OVERLOAD_WARN_ROWS,
        "consecutive_high": consecutive,
        "limited": bool(limited),
        "detail": detail,
    }
    with LOCK:
        SOCKET_OVERLOAD_STATE["last_action"] = action
        SOCKET_OVERLOAD_STATE["last_error"] = "" if ok else detail
        if action == "restart_connection_guard":
            SOCKET_OVERLOAD_STATE["last_guard_restart_at"] = utc_iso(now)
            SOCKET_OVERLOAD_STATE["last_guard_restart_at_ts"] = float(now)
        elif action == "restart_xray":
            SOCKET_OVERLOAD_STATE["last_xray_restart_at"] = utc_iso(now)
            SOCKET_OVERLOAD_STATE["last_xray_restart_at_ts"] = float(now)
    _append_socket_overload_event(event)


def _set_socket_traffic_status(
    status: str,
    now: float,
    *,
    reason: str = "",
    socket_rows: int = 0,
) -> None:
    with LOCK:
        SOCKET_TRAFFIC_STATUS.clear()
        SOCKET_TRAFFIC_STATUS.update(
            {
                "status": str(status or "unknown"),
                "checked_at": utc_iso(now),
                "checked_at_ts": float(now),
                "socket_rows_seen": int(max(0, socket_rows)),
                "max_ss_lines": PER_IP_TRAFFIC_MAX_SS_LINES,
                "unavailable_reason": str(reason or ""),
            }
        )


def _socket_traffic_status_snapshot(now: float | None = None) -> dict[str, object]:
    with LOCK:
        status = dict(SOCKET_TRAFFIC_STATUS)
    checked_at_ts = float(status.get("checked_at_ts") or 0.0)
    if now is not None and checked_at_ts > 0:
        status["checked_age_seconds"] = max(0, int(float(now) - checked_at_ts))
    else:
        status["checked_age_seconds"] = -1
    status["max_ss_lines"] = PER_IP_TRAFFIC_MAX_SS_LINES
    return status


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
    previous_last_seen = float(item.get("last_seen") or 0.0)
    if (
        previous_last_seen > 0
        and ABUSE_HISTORY_TOUCH_INTERVAL_SECONDS > 0
        and float(ts) - previous_last_seen < ABUSE_HISTORY_TOUCH_INTERVAL_SECONDS
    ):
        return
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
    before_accepted = line.split(" accepted ", 1)[0]

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
    if not ABUSE_AUDIT_ENABLED:
        return
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


def process_line(raw: str, *, parse_timestamp: bool = False) -> None:
    global LAST_LINE_AT, PROCESSED_LOG_LINES

    line = str(raw or "").strip()
    if " accepted " not in line or "email:" not in line:
        return

    now = time.time()
    ts = now
    if parse_timestamp:
        ts_match = _LOG_TS_RE.search(line)
        if ts_match:
            ts = parse_xray_ts(ts_match.group("ts")) or now

    email_match = _LOG_EMAIL_RE.search(line)
    if not email_match:
        return

    email = email_match.group("email").strip().strip("\"'[](){}<>")
    if not email:
        return

    source_ip = extract_source_ip(line)
    target = extract_target(line) if ABUSE_AUDIT_ENABLED else None
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
        PROCESSED_LOG_LINES += 1


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

        ip_traffic_cutoff = now - PER_IP_TRAFFIC_STALE_SECONDS
        for ip, item in list(IP_TRAFFIC.items()):
            if not isinstance(item, dict) or float(item.get("checked_at_ts") or 0.0) < ip_traffic_cutoff:
                IP_TRAFFIC.pop(ip, None)
        history_cutoff = now - (max([*ABUSE_MULTI_IP_WINDOWS, WINDOW_SECONDS]) + max(STATS_INTERVAL * 3, 180.0))
        for ip, samples in list(IP_TRAFFIC_HISTORY.items()):
            if not isinstance(samples, list):
                IP_TRAFFIC_HISTORY.pop(ip, None)
                continue
            samples[:] = [
                item
                for item in samples
                if isinstance(item, dict) and float(item.get("ts") or 0.0) >= history_cutoff
            ][-200:]
            if not samples:
                IP_TRAFFIC_HISTORY.pop(ip, None)
        socket_cutoff = now - max(PER_IP_TRAFFIC_STALE_SECONDS, STATS_INTERVAL * 3)
        for key, item in list(SOCKET_TRAFFIC_SAMPLES.items()):
            if not isinstance(item, dict) or float(item.get("ts") or 0.0) < socket_cutoff:
                SOCKET_TRAFFIC_SAMPLES.pop(key, None)


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

    if not ABUSE_AUDIT_ENABLED:
        return {
            "ok": True,
            "source": "vpnbot_xray_abuse_audit",
            "enabled": False,
            "is_recent_activity": True,
            "access_log": str(ACCESS_LOG),
            "window_seconds": window,
            "events_kept": 0,
            "matched_events": 0,
            "filters": {
                "email": email_filter,
                "port": port_filter,
                "target": target_filter,
            },
            "top_limit": ABUSE_AUDIT_TOP_LIMIT,
            "users": [],
        }

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
        "enabled": True,
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
    sorted_ips = sorted(ips_raw.items(), key=lambda item: float(item[1]), reverse=True)
    for window in windows:
        cutoff = now - int(window)
        ips = [
            ip
            for ip, seen in sorted_ips
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


def _traffic_window_stats_from_samples(samples: list[dict], now: float, windows: list[int]) -> dict[str, dict]:
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


def _traffic_window_stats(email: str, now: float, windows: list[int]) -> dict[str, dict]:
    with LOCK:
        samples = [
            dict(item)
            for item in USER_TRAFFIC_HISTORY.get(email, [])
            if isinstance(item, dict)
        ]
    return _traffic_window_stats_from_samples(samples, now, windows)


def _per_ip_traffic_window_stats(ip: str, now: float, windows: list[int]) -> dict[str, dict]:
    with LOCK:
        samples = [
            dict(item)
            for item in IP_TRAFFIC_HISTORY.get(ip, [])
            if isinstance(item, dict)
        ]

    out: dict[str, dict] = {}
    for window in windows:
        cutoff = now - int(window)
        filtered = [
            item
            for item in samples
            if float(item.get("ts") or 0.0) >= cutoff
        ]
        down = sum(int(item.get("delta_down_bytes") or 0) for item in filtered)
        up = sum(int(item.get("delta_up_bytes") or 0) for item in filtered)
        max_load = max((int(item.get("load_bps") or 0) for item in filtered), default=0)
        max_down_load = max((int(item.get("load_down_bps") or 0) for item in filtered), default=0)
        out[str(window)] = {
            "window_seconds": int(window),
            "traffic_down_bytes": int(down),
            "traffic_up_bytes": int(up),
            "traffic_total_bytes": int(down + up),
            "max_load_bps": int(max_load),
            "max_load_down_bps": int(max_down_load),
            "sample_count": len(filtered),
        }
    return out


def _per_ip_traffic_for_ips(ips: list[str], now: float, windows: list[int]) -> dict[str, object]:
    stale_cutoff = now - PER_IP_TRAFFIC_STALE_SECONDS
    rows: list[dict] = []
    status = _socket_traffic_status_snapshot(now)
    with LOCK:
        current = {
            ip: dict(IP_TRAFFIC.get(ip) or {})
            for ip in ips
            if isinstance(IP_TRAFFIC.get(ip), dict)
            and float((IP_TRAFFIC.get(ip) or {}).get("checked_at_ts") or 0.0) >= stale_cutoff
        }

    for ip in ips:
        item = current.get(ip) or {}
        windows_payload = _per_ip_traffic_window_stats(ip, now, windows)
        load_bps = int(item.get("load_bps") or 0)
        load_down_bps = int(item.get("load_down_bps") or 0)
        row = {
            "ip": ip,
            "connection_count": int(item.get("connection_count") or 0),
            "load_bps": load_bps,
            "load_down_bps": load_down_bps,
            "load_up_bps": int(item.get("load_up_bps") or 0),
            "delta_down_bytes": int(item.get("delta_down_bytes") or 0),
            "delta_up_bytes": int(item.get("delta_up_bytes") or 0),
            "checked_at": str(item.get("checked_at") or ""),
            "checked_age_seconds": max(0, int(now - float(item.get("checked_at_ts") or now))) if item else -1,
            "is_active": load_bps >= PER_IP_ACTIVE_BPS,
            "is_heavy": load_bps >= PER_IP_HEAVY_BPS,
            "local_ports": item.get("local_ports") if isinstance(item.get("local_ports"), list) else [],
            "window_traffic_counts": windows_payload,
        }
        rows.append(row)

    rows.sort(
        key=lambda item: (
            int(item.get("load_bps") or 0),
            int(item.get("connection_count") or 0),
            int(item.get("delta_down_bytes") or 0),
        ),
        reverse=True,
    )
    total_bps = sum(int(item.get("load_bps") or 0) for item in rows)
    total_down_bps = sum(int(item.get("load_down_bps") or 0) for item in rows)
    active_count = sum(1 for item in rows if bool(item.get("is_active")))
    heavy_count = sum(1 for item in rows if bool(item.get("is_heavy")))
    top_bps = int(rows[0].get("load_bps") or 0) if rows else 0
    top_share = float(top_bps / total_bps) if total_bps > 0 else 0.0
    top_rows = [
        item
        for item in rows
        if int(item.get("connection_count") or 0) > 0 or int(item.get("load_bps") or 0) > 0
    ][:10]
    return {
        "source": "ss_tcp_info",
        "status": status.get("status") or "unknown",
        "checked_at": status.get("checked_at") or "",
        "checked_age_seconds": int(status.get("checked_age_seconds") or -1),
        "socket_rows_seen": int(status.get("socket_rows_seen") or 0),
        "max_ss_lines": PER_IP_TRAFFIC_MAX_SS_LINES,
        "unavailable_reason": status.get("unavailable_reason") or "",
        "active_bps_threshold": PER_IP_ACTIVE_BPS,
        "heavy_bps_threshold": PER_IP_HEAVY_BPS,
        "stale_seconds": PER_IP_TRAFFIC_STALE_SECONDS,
        "observed_ip_count": len([item for item in rows if int(item.get("connection_count") or 0) > 0]),
        "active_ip_count": active_count,
        "heavy_ip_count": heavy_count,
        "total_bps": int(total_bps),
        "total_down_bps": int(total_down_bps),
        "top_ip_bps": int(top_bps),
        "top_ip_share": round(top_share, 4),
        "top_ips": top_rows,
    }


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


def _get_multi_ip_abuse_cache(cache_key: str, now: float) -> dict | None:
    if ABUSE_MULTI_IP_CACHE_TTL_SECONDS <= 0:
        return None
    with LOCK:
        cached = MULTI_IP_ABUSE_CACHE.get(cache_key)
        if cached is None:
            return None
        cached_at, payload = cached
        if now - float(cached_at or 0.0) > ABUSE_MULTI_IP_CACHE_TTL_SECONDS:
            MULTI_IP_ABUSE_CACHE.pop(cache_key, None)
            return None
        return json.loads(json.dumps(payload, ensure_ascii=False))


def _store_multi_ip_abuse_cache(cache_key: str, now: float, payload: dict) -> None:
    if ABUSE_MULTI_IP_CACHE_TTL_SECONDS <= 0:
        return
    with LOCK:
        MULTI_IP_ABUSE_CACHE[cache_key] = (
            now,
            json.loads(json.dumps(payload, ensure_ascii=False)),
        )


def _risk_from_per_ip_traffic(
    base_risk: str,
    *,
    ip_count: int,
    new_ip_count: int,
    repeat_count: int,
    per_ip_traffic: dict,
) -> tuple[str, str]:
    active_count = int(per_ip_traffic.get("active_ip_count") or 0)
    heavy_count = int(per_ip_traffic.get("heavy_ip_count") or 0)
    observed_count = int(per_ip_traffic.get("observed_ip_count") or 0)
    total_bps = int(per_ip_traffic.get("total_bps") or 0)
    top_share = float(per_ip_traffic.get("top_ip_share") or 0.0)

    if observed_count <= 0:
        return base_risk, "ip_count_only"

    if total_bps <= 0:
        if base_risk in {"critical", "high"}:
            if repeat_count >= 3 or new_ip_count >= ABUSE_MULTI_IP_HIGH_IPS:
                return "suspicious", "many_ips_no_current_ip_traffic"
            return "observe", "many_ips_no_current_ip_traffic"
        return base_risk, "many_ips_no_current_ip_traffic"

    if heavy_count >= 2:
        if ip_count >= ABUSE_MULTI_IP_HIGH_IPS or active_count >= 3:
            return "critical", "many_ips_heavy"
        return "high", "few_ips_heavy"

    if active_count >= 3:
        if ip_count >= ABUSE_MULTI_IP_CRITICAL_IPS and new_ip_count >= ABUSE_MULTI_IP_SUSPICIOUS_IPS:
            return "critical", "many_ips_active"
        return "high", "many_ips_active"

    if active_count == 2:
        if ip_count >= ABUSE_MULTI_IP_CRITICAL_IPS and repeat_count >= 3:
            return "high", "two_ips_active_repeated"
        return "suspicious", "two_ips_active"

    if active_count <= 1 and total_bps > 0:
        if base_risk in {"critical", "high"}:
            if repeat_count >= 3 or new_ip_count >= ABUSE_MULTI_IP_HIGH_IPS:
                return "suspicious", "single_active_ip_churn"
            return "observe", "single_active_ip_churn"
        return base_risk, "single_active_ip_churn"

    if total_bps > 0 and top_share >= 0.9:
        if base_risk in {"critical", "high"}:
            return "suspicious", "one_ip_dominates"
        return base_risk, "one_ip_dominates"

    return base_risk, "ip_count_only"


def build_multi_ip_abuse(window_seconds: int | None = None) -> dict:
    now = time.time()
    window = max(10, min(int(window_seconds or WINDOW_SECONDS), 3600))
    cache_key = str(window)
    cached = _get_multi_ip_abuse_cache(cache_key, now)
    if cached is not None:
        cached["cache"] = {
            "hit": True,
            "ttl_seconds": ABUSE_MULTI_IP_CACHE_TTL_SECONDS,
            "age_seconds": max(0.0, now - float(cached.get("generated_at_ts") or now)),
        }
        return cached

    windows = sorted({*ABUSE_MULTI_IP_WINDOWS, window})
    main_window = str(window)
    history_cutoff = now - max(windows)
    purge_stale(now)

    with LOCK:
        client_items = [(email, dict(entry)) for email, entry in CLIENTS.items()]
        history_users = json.loads(json.dumps(MULTI_IP_HISTORY.get("users") or {}, ensure_ascii=False))
        traffic_by_email = json.loads(json.dumps(USER_TRAFFIC, ensure_ascii=False))
        traffic_history_by_email = {
            str(email): [dict(sample) for sample in samples if isinstance(sample, dict)]
            for email, samples in USER_TRAFFIC_HISTORY.items()
            if isinstance(samples, list)
        }
        abuse_events = [
            dict(item)
            for item in ABUSE_EVENTS
            if float(item.get("ts") or 0.0) >= history_cutoff
        ]

    abuse_events_by_email: dict[str, list[dict]] = {}
    for item in abuse_events:
        email = str(item.get("email") or "").strip()
        if not email:
            continue
        abuse_events_by_email.setdefault(email, []).append(item)

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
        email_events = abuse_events_by_email.get(email) or []
        event_windows = _event_stats_by_window(email_events, now, windows)
        event_info = event_windows.get(main_window) or {}
        traffic = traffic_by_email.get(email) if isinstance(traffic_by_email.get(email), dict) else {}
        traffic_windows = _traffic_window_stats_from_samples(
            traffic_history_by_email.get(email) or [],
            now,
            windows,
        )
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
        base_risk_level = _multi_ip_risk_level(ip_count, prefix_count)
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
        per_ip_traffic = _per_ip_traffic_for_ips(recent_ips, now, windows)
        risk_level, traffic_pattern = _risk_from_per_ip_traffic(
            base_risk_level,
            ip_count=ip_count,
            new_ip_count=new_ip_count,
            repeat_count=repeat_count,
            per_ip_traffic=per_ip_traffic,
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
        active_ip_count = int(per_ip_traffic.get("active_ip_count") or 0)
        heavy_ip_count = int(per_ip_traffic.get("heavy_ip_count") or 0)
        top_ip_share = float(per_ip_traffic.get("top_ip_share") or 0.0)
        if heavy_ip_count >= 2:
            reasons.append(f"{heavy_ip_count} IP одновременно качают много")
        elif active_ip_count >= 2:
            reasons.append(f"{active_ip_count} IP одновременно активны по трафику")
        elif traffic_pattern in {"single_active_ip_churn", "one_ip_dominates"}:
            reasons.append("трафик сейчас в основном у одного IP: похоже на смену IP, проверить вручную")
        elif traffic_pattern == "many_ips_no_current_ip_traffic":
            reasons.append("много IP без текущей IP-нагрузки: похоже на idle/смену IP, проверить вручную")
        if risk_level in {"high", "critical"} and prefix_count < ABUSE_MULTI_IP_MIN_PREFIXES:
            reasons.append("много IP, но мало разных подсетей: проверьте вручную")

        users.append(
            {
                "email": email,
                "risk_level": risk_level,
                "base_risk_level": base_risk_level,
                "traffic_pattern": traffic_pattern,
                "evidence_strength": (
                    "strong"
                    if (heavy_ip_count >= 2 or active_ip_count >= 3) and prefix_count >= ABUSE_MULTI_IP_MIN_PREFIXES
                    else "medium"
                ),
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
                "per_ip_traffic": per_ip_traffic,
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

    payload = {
        "ok": True,
        "source": "vpnbot_xray_multi_ip_abuse",
        "is_recent_activity": True,
        "access_log": str(ACCESS_LOG),
        "generated_at": utc_iso(now),
        "generated_at_ts": now,
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
        "cache": {
            "hit": False,
            "ttl_seconds": ABUSE_MULTI_IP_CACHE_TTL_SECONDS,
            "age_seconds": 0.0,
        },
    }
    _store_multi_ip_abuse_cache(cache_key, now, payload)
    return payload


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


_LOG_TS_RE = re.compile(r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+")
_LOG_EMAIL_RE = re.compile(r"\bemail:\s*(?P<email>\S+)")
_SS_ENDPOINT_RE = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")
_SS_BYTES_SENT_RE = re.compile(r"\bbytes_sent:(?P<value>\d+)\b")
_SS_BYTES_RECEIVED_RE = re.compile(r"\bbytes_received:(?P<value>\d+)\b")
_SHARED_PORT_RE = re.compile(r"\[shared:(?P<port>\d{1,5})\]")


def _parse_ss_endpoint(value: str) -> tuple[str, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("[") and "]:" in text:
        host = text[1:text.index("]:")]
        port_text = text[text.index("]:") + 2:]
    else:
        match = _SS_ENDPOINT_RE.match(text)
        if not match:
            return None
        host = match.group("host")
        port_text = match.group("port")
    ip = normalize_ip(host)
    if not ip:
        return None
    try:
        port = int(port_text)
    except Exception:
        port = 0
    return ip, port


def _parse_ss_endpoint_fast(value: str) -> tuple[str, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("[") and "]:" in text:
        host = text[1:text.index("]:")]
        port_text = text[text.index("]:") + 2:]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep:
            return None
    host = host.strip().strip("[]").lower()
    if not host:
        return None
    try:
        port = int(port_text)
    except Exception:
        return None
    return host, port


def _is_loopback_ip(value: str) -> bool:
    text = str(value or "").strip().lower()
    return text == "::1" or text == "localhost" or text.startswith("127.") or text.startswith("::ffff:127.")


def _managed_public_ports() -> set[int]:
    try:
        data = json.loads(MANAGED_INBOUNDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return set()

    ports: set[int] = set()
    for inbound in data.get("inbounds") or []:
        if not isinstance(inbound, dict) or inbound.get("enable") is False:
            continue
        marker_text = " ".join(
            str(inbound.get(key) or "")
            for key in ("tag", "remark", "name")
        )
        for match in _SHARED_PORT_RE.finditer(marker_text):
            try:
                shared_port = int(match.group("port") or 0)
            except Exception:
                shared_port = 0
            if 0 < shared_port <= 65535:
                ports.add(shared_port)
        try:
            port = int(inbound.get("port") or 0)
        except Exception:
            port = 0
        if port <= 0 or port > 65535:
            continue
        listen = str(inbound.get("listen") or "0.0.0.0").strip().lower()
        if listen in {"127.0.0.1", "::1", "localhost"}:
            continue
        ports.add(port)
    return ports


def _counter_rows(counter: dict, limit: int = CONNECTION_TOP_LIMIT) -> list[dict]:
    rows = []
    if hasattr(counter, "most_common"):
        items = counter.most_common(limit)
    else:
        items = sorted(counter.items(), key=lambda item: int(item[1] or 0), reverse=True)[:limit]
    for key, count in items:
        rows.append({"key": str(key), "count": int(count)})
    return rows


def _connection_top_payload(now: float) -> dict:
    import collections

    global CONNECTION_TOP_CACHE
    with LOCK:
        cached = CONNECTION_TOP_CACHE
        if cached is not None and (now - float(cached[0])) <= CONNECTION_TOP_CACHE_TTL_SECONDS:
            return dict(cached[1])

    public_ports = _managed_public_ports()
    local_ports = collections.Counter()
    peer_ports = collections.Counter()
    peer_ips = collections.Counter()
    public_peer_ips = collections.Counter()
    other_peer_ips = collections.Counter()
    local_api = 0
    rows_seen = 0
    limited = False
    per_port_peer_ips: dict[int, collections.Counter] = {}

    proc = subprocess.Popen(
        [SS_BIN, "-Hant", "state", "established"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            rows_seen += 1
            if rows_seen > CONNECTION_TOP_MAX_ROWS:
                limited = True
                proc.kill()
                break

            parts = raw.split()
            if len(parts) < 4:
                continue
            local = _parse_ss_endpoint_fast(parts[2])
            peer = _parse_ss_endpoint_fast(parts[3])
            if not local or not peer:
                continue
            local_ip, local_port = local
            peer_ip, peer_port = peer
            local_ports[local_port] += 1
            peer_ports[peer_port] += 1
            peer_ips[peer_ip] += 1

            if _is_loopback_ip(local_ip) or _is_loopback_ip(peer_ip):
                if local_port in {10085, 10086} or peer_port in {10085, 10086}:
                    local_api += 1

            if local_port in public_ports:
                if not _is_loopback_ip(peer_ip):
                    public_peer_ips[peer_ip] += 1
                    per_port_peer_ips.setdefault(local_port, collections.Counter())[peer_ip] += 1
            else:
                other_peer_ips[peer_ip] += 1

        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    finally:
        if proc.stdout is not None:
            proc.stdout.close()

    top_local_ports = []
    for port, count in local_ports.most_common(CONNECTION_TOP_LIMIT):
        port_int = int(port)
        top_local_ports.append(
            {
                "port": port_int,
                "count": int(count),
                "managed_public": port_int in public_ports,
                "top_peer_ips": _counter_rows(per_port_peer_ips.get(port_int, collections.Counter()), 5),
            }
        )

    payload = {
        "ok": True,
        "source": "ss_established_top",
        "version": TRACKER_VERSION,
        "checked_at": utc_iso(now),
        "checked_at_ts": now,
        "rows_seen": rows_seen,
        "limited": limited,
        "max_rows": CONNECTION_TOP_MAX_ROWS,
        "managed_public_ports": sorted(public_ports),
        "local_api_established": local_api,
        "top_local_ports": top_local_ports,
        "top_peer_ips": _counter_rows(peer_ips),
        "top_public_peer_ips": _counter_rows(public_peer_ips),
        "top_other_peer_ips": _counter_rows(other_peer_ips),
        "top_peer_ports": _counter_rows(peer_ports),
    }
    with LOCK:
        CONNECTION_TOP_CACHE = (now, payload)
    return dict(payload)


def _known_recent_client_ips(now: float) -> set[str]:
    cutoff = now - max(WINDOW_SECONDS, max(ABUSE_MULTI_IP_WINDOWS or [WINDOW_SECONDS]))
    out: set[str] = set()
    with LOCK:
        for entry in CLIENTS.values():
            ips = entry.get("ips") if isinstance(entry, dict) and isinstance(entry.get("ips"), dict) else {}
            for ip, seen in ips.items():
                try:
                    if float(seen) >= cutoff:
                        out.add(str(ip))
                except Exception:
                    continue
    return out


def _established_socket_count_limited(limit: int) -> tuple[int, bool]:
    """Посчитать TCP-сокеты до лимита перед дорогим ss -i обходом."""
    proc = subprocess.Popen(
        [SS_BIN, "-Htn", "state", "established"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    count = 0
    limited = False
    try:
        assert proc.stdout is not None
        for _line in proc.stdout:
            count += 1
            if count > limit:
                limited = True
                proc.kill()
                break
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
    return count, limited


def query_socket_ip_traffic(now: float) -> dict[str, dict]:
    known_ips = _known_recent_client_ips(now)
    if not known_ips:
        _set_socket_traffic_status("idle", now, reason="no_recent_client_ips")
        return {}

    socket_rows, socket_rows_limited = _established_socket_count_limited(PER_IP_TRAFFIC_MAX_SS_LINES)
    _maybe_handle_socket_overload(now, socket_rows, limited=socket_rows_limited)
    if socket_rows_limited:
        _set_socket_traffic_status(
            "skipped",
            now,
            reason="too_many_established_sockets",
            socket_rows=socket_rows,
        )
        return {}

    proc = subprocess.run(
        [SS_BIN, "-Htin", "state", "established"],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    if proc.returncode != 0:
        _set_socket_traffic_status("error", now, reason="ss_failed", socket_rows=socket_rows)
        raise RuntimeError((proc.stderr or proc.stdout or f"exit={proc.returncode}")[-500:])

    sockets: list[dict] = []
    current: dict | None = None
    for raw in (proc.stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        is_socket_row = (
            len(parts) >= 4
            and parts[0].isdigit()
            and parts[1].isdigit()
            and ":" in parts[2]
            and ":" in parts[3]
        )
        if is_socket_row:
            local = _parse_ss_endpoint(parts[2])
            peer = _parse_ss_endpoint(parts[3])
            current = None
            if local and peer:
                local_ip, local_port = local
                peer_ip, peer_port = peer
                if peer_ip in known_ips and not _is_loopback_ip(local_ip) and not _is_loopback_ip(peer_ip):
                    current = {
                        "key": f"{local_ip}:{local_port}>{peer_ip}:{peer_port}",
                        "ip": peer_ip,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "peer_port": peer_port,
                        "bytes_sent": 0,
                        "bytes_received": 0,
                    }
                    sockets.append(current)
            continue

        if current is None:
            continue
        sent_match = _SS_BYTES_SENT_RE.search(line)
        received_match = _SS_BYTES_RECEIVED_RE.search(line)
        if sent_match:
            current["bytes_sent"] = int(sent_match.group("value"))
        if received_match:
            current["bytes_received"] = int(received_match.group("value"))

    with LOCK:
        previous_samples = dict(SOCKET_TRAFFIC_SAMPLES)

    by_ip: dict[str, dict] = {}
    next_samples: dict[str, dict] = {}
    for item in sockets:
        key = str(item.get("key") or "")
        ip = str(item.get("ip") or "")
        if not key or not ip:
            continue
        sent = int(item.get("bytes_sent") or 0)
        received = int(item.get("bytes_received") or 0)
        previous = previous_samples.get(key) if isinstance(previous_samples.get(key), dict) else {}
        previous_ts = float(previous.get("ts") or 0.0)
        previous_sent = int(previous.get("bytes_sent") or 0)
        previous_received = int(previous.get("bytes_received") or 0)
        delta_seconds = max(0.001, now - previous_ts) if previous_ts > 0 else 0.0
        delta_sent = sent - previous_sent if previous_ts > 0 and sent >= previous_sent else 0
        delta_received = received - previous_received if previous_ts > 0 and received >= previous_received else 0
        down_bps = int((delta_sent * 8) / delta_seconds) if delta_seconds > 0 else None
        up_bps = int((delta_received * 8) / delta_seconds) if delta_seconds > 0 else None

        entry = by_ip.setdefault(
            ip,
            {
                "ip": ip,
                "connection_count": 0,
                "socket_bytes_sent": 0,
                "socket_bytes_received": 0,
                "delta_down_bytes": 0,
                "delta_up_bytes": 0,
                "load_down_bps": 0,
                "load_up_bps": 0,
                "load_bps": 0,
                "local_ports": {},
                "checked_at_ts": now,
                "checked_at": utc_iso(now),
                "source": "ss_tcp_info",
            },
        )
        entry["connection_count"] = int(entry.get("connection_count") or 0) + 1
        entry["socket_bytes_sent"] = int(entry.get("socket_bytes_sent") or 0) + sent
        entry["socket_bytes_received"] = int(entry.get("socket_bytes_received") or 0) + received
        entry["delta_down_bytes"] = int(entry.get("delta_down_bytes") or 0) + max(0, delta_sent)
        entry["delta_up_bytes"] = int(entry.get("delta_up_bytes") or 0) + max(0, delta_received)
        if down_bps is not None:
            entry["load_down_bps"] = int(entry.get("load_down_bps") or 0) + max(0, down_bps)
        if up_bps is not None:
            entry["load_up_bps"] = int(entry.get("load_up_bps") or 0) + max(0, up_bps)
        entry["load_bps"] = int(entry.get("load_down_bps") or 0) + int(entry.get("load_up_bps") or 0)
        local_ports = entry.setdefault("local_ports", {})
        local_port_key = str(int(item.get("local_port") or 0))
        if local_port_key != "0":
            local_ports[local_port_key] = int(local_ports.get(local_port_key) or 0) + 1

        next_samples[key] = {
            "ts": now,
            "ip": ip,
            "bytes_sent": sent,
            "bytes_received": received,
        }

    for entry in by_ip.values():
        ports = sorted(
            [
                {"port": int(port), "connection_count": int(count)}
                for port, count in (entry.get("local_ports") or {}).items()
                if str(port).isdigit()
            ],
            key=lambda item: int(item.get("connection_count") or 0),
            reverse=True,
        )
        entry["local_ports"] = ports[:10]
        entry["is_active"] = int(entry.get("load_bps") or 0) >= PER_IP_ACTIVE_BPS
        entry["is_heavy"] = int(entry.get("load_bps") or 0) >= PER_IP_HEAVY_BPS

    with LOCK:
        SOCKET_TRAFFIC_SAMPLES.clear()
        SOCKET_TRAFFIC_SAMPLES.update(next_samples)
        max_history_age = max([*ABUSE_MULTI_IP_WINDOWS, WINDOW_SECONDS]) + max(STATS_INTERVAL * 3, 180.0)
        history_cutoff = now - max_history_age
        for ip, entry in by_ip.items():
            IP_TRAFFIC[ip] = dict(entry)
            history = IP_TRAFFIC_HISTORY.setdefault(ip, [])
            history.append(
                {
                    "ts": now,
                    "load_bps": int(entry.get("load_bps") or 0),
                    "load_down_bps": int(entry.get("load_down_bps") or 0),
                    "load_up_bps": int(entry.get("load_up_bps") or 0),
                    "delta_down_bytes": int(entry.get("delta_down_bytes") or 0),
                    "delta_up_bytes": int(entry.get("delta_up_bytes") or 0),
                    "connection_count": int(entry.get("connection_count") or 0),
                }
            )
            history[:] = [
                sample
                for sample in history
                if isinstance(sample, dict) and float(sample.get("ts") or 0.0) >= history_cutoff
            ][-200:]

    _set_socket_traffic_status("ok", now, socket_rows=socket_rows)
    return by_ip


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
    global LAST_ERROR, LAST_USER_STATS_AT
    now = time.time()
    source = "xray_stats_inbound"
    payload = query_xray_stats("inbound>>>")
    totals = extract_traffic_totals(payload, prefix="inbound>>>")
    user_payload = None
    should_query_user_stats = now - LAST_USER_STATS_AT >= USER_STATS_INTERVAL
    if int(totals.get("traffic_total_bytes") or 0) <= 0 and should_query_user_stats:
        source = "xray_stats_user_fallback"
        user_payload = query_xray_stats("user>>>")
        LAST_USER_STATS_AT = now
        totals = extract_traffic_totals(user_payload, prefix="user>>>")
    elif should_query_user_stats:
        try:
            user_payload = query_xray_stats("user>>>")
            LAST_USER_STATS_AT = now
        except Exception:
            user_payload = None

    if isinstance(user_payload, dict):
        update_user_traffic(extract_user_traffic(user_payload), now)

    try:
        query_socket_ip_traffic(now)
        with LOCK:
            if str(LAST_ERROR or "").startswith("socket_traffic:"):
                LAST_ERROR = ""
    except Exception as exc:
        with LOCK:
            LAST_ERROR = f"socket_traffic:{type(exc).__name__}: {exc}"

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
            "per_ip_traffic": _per_ip_traffic_for_ips(ips, now, [window]),
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
            "enabled": ABUSE_AUDIT_ENABLED,
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
        process_line(line, parse_timestamp=True)
    return size


def tail_access_log() -> None:
    global LAST_ERROR, SKIPPED_LOG_LINES

    fh = None
    inode = None
    position = 0
    last_maintenance_at = 0.0
    line_window_started_at = time.time()
    line_seen_in_window = 0
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
                now = time.time()
                if now - line_window_started_at >= 1.0:
                    line_window_started_at = now
                    line_seen_in_window = 0
                line_seen_in_window += 1
                should_process = line_seen_in_window <= MAX_LOG_LINES_PER_SECOND
                if (
                    not should_process
                    and LOG_SAMPLE_EVERY_OVER_LIMIT > 0
                    and line_seen_in_window % LOG_SAMPLE_EVERY_OVER_LIMIT == 0
                ):
                    should_process = True
                if should_process:
                    process_line(line)
                else:
                    with LOCK:
                        SKIPPED_LOG_LINES += 1
                position = fh.tell()
                continue

            now = time.time()
            if now - last_maintenance_at >= MAINTENANCE_INTERVAL:
                purge_stale(now)
                save_multi_ip_history()
                last_maintenance_at = now
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
    server_version = f"vpnbot-xray-online-tracker/{TRACKER_VERSION}"

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
            self._send_json(200, health_payload())
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
        if parsed.path == "/connections/top":
            self._send_json(200, _connection_top_payload(time.time()))
            return
        self._send_json(404, {"ok": False, "error": "not_found"})


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


STARTED_AT = utc_iso()


def main() -> None:
    load_multi_ip_history()
    worker = threading.Thread(target=tail_access_log, name="xray-access-log-tail", daemon=True)
    worker.start()
    stats = threading.Thread(target=stats_worker, name="xray-stats-poll", daemon=True)
    stats.start()
    server = ReusableThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
