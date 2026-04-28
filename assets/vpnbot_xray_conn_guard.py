#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


MANAGED_INBOUNDS_FILE = Path(
    os.environ.get(
        "XRAY_CORE_MANAGED_INBOUNDS_FILE",
        "/opt/vpnbot/xray-core/config/50_vpnbot_managed_inbounds.json",
    )
)
ENABLED = str(os.environ.get("XRAY_CONN_GUARD_ENABLED", "1")).strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
MAX_PER_IP = max(1, int(os.environ.get("XRAY_CONN_GUARD_MAX_PER_IP", "3000") or "3000"))
IPV6_MAX_PER_IP = max(1, int(os.environ.get("XRAY_CONN_GUARD_IPV6_MAX_PER_IP", str(MAX_PER_IP)) or MAX_PER_IP))
CHAIN = os.environ.get("XRAY_CONN_GUARD_CHAIN", "VPNBOT_XRAY_CONN_GUARD")
BAN_ENABLED = str(os.environ.get("XRAY_CONN_GUARD_BAN_ENABLED", "1")).strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
BAN_CONNECTIONS = max(
    100,
    int(os.environ.get("XRAY_CONN_GUARD_BAN_CONNECTIONS", str(MAX_PER_IP)) or MAX_PER_IP),
)
BAN_TOTAL_STATES = max(
    100,
    int(os.environ.get("XRAY_CONN_GUARD_BAN_TOTAL_STATES", "700") or "700"),
)
BAN_BAD_STATES = max(
    50,
    int(os.environ.get("XRAY_CONN_GUARD_BAN_BAD_STATES", "350") or "350"),
)
BAN_SECONDS = max(60, min(int(os.environ.get("XRAY_CONN_GUARD_BAN_SECONDS", "3600") or "3600"), 86400))
SCAN_MAX_ROWS = max(
    1000,
    min(int(os.environ.get("XRAY_CONN_GUARD_SCAN_MAX_ROWS", "80000") or "80000"), 1_000_000),
)
STATE_DIR = Path(os.environ.get("XRAY_CONN_GUARD_STATE_DIR", "/var/lib/vpnbot-xray-conn-guard"))
BAN_STATE_FILE = Path(os.environ.get("XRAY_CONN_GUARD_BAN_STATE_FILE", str(STATE_DIR / "bans.json")))
EVENTS_FILE = Path(os.environ.get("XRAY_CONN_GUARD_EVENTS_FILE", str(STATE_DIR / "events.jsonl")))
SHARED_PORT_RE = re.compile(r"\[shared:(?P<port>\d{1,5})\]")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
BAD_TCP_STATES = {
    "CLOSE-WAIT",
    "CLOSING",
    "FIN-WAIT-1",
    "FIN-WAIT-2",
    "LAST-ACK",
    "SYN-RECV",
}


def _run(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def _utc_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).isoformat()


def _cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _ensure_state_dir() -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _load_bans(now: float) -> list[dict]:
    try:
        payload = json.loads(BAN_STATE_FILE.read_text(encoding="utf-8") or "{}")
    except Exception:
        payload = {}
    items = payload.get("bans") if isinstance(payload, dict) else []
    out: list[dict] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            expires_at = float(item.get("expires_at_ts") or 0)
            port = int(item.get("port") or 0)
        except Exception:
            continue
        ip = str(item.get("ip") or "").strip()
        if not ip or _is_loopback_ip(ip) or port <= 0 or port > 65535 or expires_at <= now:
            continue
        out.append(item)
    return out


def _save_bans(items: list[dict]) -> None:
    _ensure_state_dir()
    payload = {
        "updated_at": _utc_iso(),
        "bans": items,
    }
    tmp = BAN_STATE_FILE.with_suffix(BAN_STATE_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(BAN_STATE_FILE)


def _append_event(event: dict) -> None:
    _ensure_state_dir()
    payload = {
        "ts": int(time.time()),
        "at": _utc_iso(),
        **event,
    }
    try:
        with EVENTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass


def _parse_ss_endpoint(value: str) -> tuple[str, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("["):
        end = text.rfind("]:")
        if end <= 0:
            return None
        host = text[1:end]
        port_text = text[end + 2 :]
    else:
        if ":" not in text:
            return None
        host, port_text = text.rsplit(":", 1)
    try:
        port = int(port_text)
    except Exception:
        return None
    if port <= 0 or port > 65535:
        return None
    if host.startswith("::ffff:"):
        host = host[len("::ffff:") :]
    return host, port


def _is_ipv6(ip: str) -> bool:
    return ":" in str(ip or "") and bool(_IPV6_RE.match(str(ip or "")))


def _is_loopback_ip(ip: str) -> bool:
    text = str(ip or "").strip().lower()
    return text == "::1" or text == "localhost" or text.startswith("127.") or text.startswith("::ffff:127.")


def _scan_abusive_ips(ports: list[int]) -> tuple[list[dict], int, bool]:
    if not BAN_ENABLED or not ports or not _cmd_exists("ss"):
        return [], 0, False
    public_ports = set(int(port) for port in ports)
    established_counts: dict[tuple[str, int], int] = {}
    total_counts: dict[tuple[str, int], int] = {}
    bad_counts: dict[tuple[str, int], int] = {}
    state_counts: dict[tuple[str, int], dict[str, int]] = {}
    rows_seen = 0
    limited = False
    proc = subprocess.Popen(
        ["ss", "-Hant"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            rows_seen += 1
            if rows_seen > SCAN_MAX_ROWS:
                limited = True
                proc.kill()
                break
            parts = raw.split()
            if len(parts) < 5:
                continue
            state = str(parts[0] or "").strip().upper()
            if state in {"LISTEN", "UNCONN"}:
                continue
            local = _parse_ss_endpoint(parts[3])
            peer = _parse_ss_endpoint(parts[4])
            if not local or not peer:
                continue
            _local_ip, local_port = local
            peer_ip, peer_port = peer
            if local_port not in public_ports:
                continue
            if peer_port > 0 and peer_port < 1024:
                continue
            if _is_loopback_ip(peer_ip):
                continue
            key = (peer_ip, local_port)
            total_counts[key] = total_counts.get(key, 0) + 1
            if state == "ESTAB":
                established_counts[key] = established_counts.get(key, 0) + 1
            if state in BAD_TCP_STATES:
                bad_counts[key] = bad_counts.get(key, 0) + 1
            per_state = state_counts.setdefault(key, {})
            per_state[state] = per_state.get(state, 0) + 1
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    finally:
        if proc.stdout is not None:
            proc.stdout.close()

    offenders = []
    for key, total_count in total_counts.items():
        ip, port = key
        established_count = int(established_counts.get(key, 0))
        bad_count = int(bad_counts.get(key, 0))
        reason = ""
        threshold = 0
        trigger_count = 0
        if established_count >= BAN_CONNECTIONS:
            reason = "too_many_established_connections_from_one_ip"
            threshold = BAN_CONNECTIONS
            trigger_count = established_count
        elif bad_count >= BAN_BAD_STATES:
            reason = "too_many_closing_tcp_states_from_one_ip"
            threshold = BAN_BAD_STATES
            trigger_count = bad_count
        elif total_count >= BAN_TOTAL_STATES:
            reason = "too_many_tcp_states_from_one_ip"
            threshold = BAN_TOTAL_STATES
            trigger_count = total_count
        if reason:
            offenders.append(
                {
                    "ip": ip,
                    "port": int(port),
                    "connection_count": int(established_count),
                    "total_state_count": int(total_count),
                    "bad_state_count": int(bad_count),
                    "trigger_count": int(trigger_count),
                    "threshold": int(threshold),
                    "reason": reason,
                    "state_counts": dict(sorted(state_counts.get(key, {}).items())),
                }
            )
    offenders.sort(key=lambda item: int(item.get("trigger_count") or item.get("connection_count") or 0), reverse=True)
    return offenders, rows_seen, limited


def _managed_public_ports() -> list[int]:
    try:
        data = json.loads(MANAGED_INBOUNDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

    ports: set[int] = set()
    for inbound in data.get("inbounds") or []:
        if not isinstance(inbound, dict) or inbound.get("enable") is False:
            continue
        marker_text = " ".join(
            str(inbound.get(key) or "")
            for key in ("tag", "remark", "name")
        )
        for match in SHARED_PORT_RE.finditer(marker_text):
            try:
                shared_port = int(match.group("port") or 0)
            except Exception:
                shared_port = 0
            if 0 < shared_port <= 65535:
                ports.add(shared_port)
        if SHARED_PORT_RE.search(marker_text):
            continue
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
    return sorted(ports)


def _ensure_chain(tool: str) -> bool:
    if _run([tool, "-N", CHAIN]).returncode not in {0, 1}:
        return False
    _run([tool, "-F", CHAIN])
    if _run([tool, "-C", "INPUT", "-j", CHAIN]).returncode != 0:
        _run([tool, "-I", "INPUT", "1", "-j", CHAIN])
    return True


def _add_ban_rule(tool: str, item: dict) -> bool:
    ip = str(item.get("ip") or "").strip()
    try:
        port = int(item.get("port") or 0)
    except Exception:
        port = 0
    if not ip or port <= 0 or port > 65535:
        return False
    if _is_loopback_ip(ip):
        return False
    if tool == "iptables" and _is_ipv6(ip):
        return False
    if tool == "ip6tables" and not _is_ipv6(ip):
        return False
    comment = (
        f"vpnbot auto-ban until={int(float(item.get('expires_at_ts') or 0))} "
        f"count={int(item.get('connection_count') or 0)}"
    )
    result = _run(
        [
            tool,
            "-A",
            CHAIN,
            "-s",
            ip,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "comment",
            "--comment",
            comment[:240],
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
    )
    if result.returncode != 0:
        print(f"{tool}: failed to ban {ip}:{port}: {(result.stderr or result.stdout or '').strip()[:240]}")
        return False
    return True


def _add_limit_rule(tool: str, port: int, limit: int, mask: str) -> bool:
    result = _run(
        [
            tool,
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "--syn",
            "--dport",
            str(port),
            "-m",
            "connlimit",
            "--connlimit-above",
            str(limit),
            "--connlimit-mask",
            mask,
            "--connlimit-saddr",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
    )
    if result.returncode != 0:
        print(f"{tool}: failed to guard port {port}: {(result.stderr or result.stdout or '').strip()[:240]}")
        return False
    return True


def _disable_tool(tool: str) -> None:
    if not _cmd_exists(tool):
        return
    if _run([tool, "-C", "INPUT", "-j", CHAIN]).returncode == 0:
        _run([tool, "-D", "INPUT", "-j", CHAIN])
    _run([tool, "-F", CHAIN])


def _apply_tool(tool: str, ports: list[int], limit: int, mask: str, bans: list[dict]) -> bool:
    if not _cmd_exists(tool):
        print(f"{tool}: unavailable, skipped")
        return False
    if not _ensure_chain(tool):
        print(f"{tool}: failed to create chain {CHAIN}, skipped")
        return False
    installed_bans = 0
    for item in bans:
        if _add_ban_rule(tool, item):
            installed_bans += 1
    installed = 0
    for port in ports:
        if _add_limit_rule(tool, port, limit, mask):
            installed += 1
    print(
        f"{tool}: guarded {installed}/{len(ports)} port(s), "
        f"active_bans={installed_bans}, max_per_ip={limit}, chain={CHAIN}"
    )
    return installed > 0 or installed_bans > 0


def _drop_existing_connections(ip: str, port: int) -> None:
    if not ip or port <= 0:
        return
    if _cmd_exists("ss"):
        _run(["ss", "-K", "dst", ip, "sport", "=", f":{port}"])
        _run(["ss", "-K", "src", ip, "dport", "=", f":{port}"])
        _run(["ss", "-K", "state", "established", "src", ip, "sport", f":{port}"])
        _run(["ss", "-K", "state", "established", "dst", ip, "dport", f":{port}"])
    if _cmd_exists("conntrack"):
        _run(["conntrack", "-D", "-p", "tcp", "--orig-src", ip, "--dport", str(port)])
        _run(["conntrack", "-D", "-p", "tcp", "--reply-src", ip, "--sport", str(port)])


def _refresh_dynamic_bans(ports: list[int]) -> list[dict]:
    now = time.time()
    existing = _load_bans(now)
    by_key: dict[tuple[str, int], dict] = {}
    for item in existing:
        try:
            by_key[(str(item.get("ip") or ""), int(item.get("port") or 0))] = item
        except Exception:
            continue

    offenders, rows_seen, limited = _scan_abusive_ips(ports)
    new_count = 0
    extended_count = 0
    for offender in offenders:
        ip = str(offender.get("ip") or "")
        if _is_loopback_ip(ip):
            continue
        port = int(offender.get("port") or 0)
        key = (ip, port)
        expires_at = now + BAN_SECONDS
        if key in by_key:
            item = by_key[key]
            item["connection_count"] = max(
                int(item.get("connection_count") or 0),
                int(offender.get("connection_count") or 0),
            )
            item["total_state_count"] = max(
                int(item.get("total_state_count") or 0),
                int(offender.get("total_state_count") or 0),
            )
            item["bad_state_count"] = max(
                int(item.get("bad_state_count") or 0),
                int(offender.get("bad_state_count") or 0),
            )
            item["trigger_count"] = max(
                int(item.get("trigger_count") or 0),
                int(offender.get("trigger_count") or 0),
            )
            item["threshold"] = int(offender.get("threshold") or item.get("threshold") or BAN_CONNECTIONS)
            item["reason"] = str(offender.get("reason") or item.get("reason") or "too_many_tcp_states_from_one_ip")
            item["state_counts"] = offender.get("state_counts") or item.get("state_counts") or {}
            item["last_seen_at"] = _utc_iso(now)
            item["last_seen_at_ts"] = now
            if float(item.get("expires_at_ts") or 0) < expires_at:
                item["expires_at"] = _utc_iso(expires_at)
                item["expires_at_ts"] = expires_at
                extended_count += 1
        else:
            item = {
                **offender,
                "reason": str(offender.get("reason") or "too_many_tcp_states_from_one_ip"),
                "created_at": _utc_iso(now),
                "created_at_ts": now,
                "last_seen_at": _utc_iso(now),
                "last_seen_at_ts": now,
                "expires_at": _utc_iso(expires_at),
                "expires_at_ts": expires_at,
                "ban_seconds": BAN_SECONDS,
                "threshold": int(offender.get("threshold") or BAN_CONNECTIONS),
            }
            by_key[key] = item
            new_count += 1
            _append_event(
                {
                    "event": "temporary_ip_ban",
                    "ip": ip,
                    "port": port,
                    "connection_count": int(offender.get("connection_count") or 0),
                    "total_state_count": int(offender.get("total_state_count") or 0),
                    "bad_state_count": int(offender.get("bad_state_count") or 0),
                    "trigger_count": int(offender.get("trigger_count") or 0),
                    "threshold": int(offender.get("threshold") or BAN_CONNECTIONS),
                    "reason": str(offender.get("reason") or "too_many_tcp_states_from_one_ip"),
                    "state_counts": offender.get("state_counts") or {},
                    "ban_seconds": BAN_SECONDS,
                    "expires_at": item["expires_at"],
                    "rows_seen": rows_seen,
                    "limited": limited,
                }
            )
            _drop_existing_connections(ip, port)

    bans = sorted(
        by_key.values(),
        key=lambda item: (int(item.get("connection_count") or 0), float(item.get("expires_at_ts") or 0)),
        reverse=True,
    )
    _save_bans(bans)
    if offenders or existing:
        print(
            "dynamic bans: "
            f"active={len(bans)} new={new_count} extended={extended_count} "
            f"offenders={len(offenders)} rows_seen={rows_seen} limited={limited} "
            f"established_threshold={BAN_CONNECTIONS} total_threshold={BAN_TOTAL_STATES} "
            f"bad_threshold={BAN_BAD_STATES} seconds={BAN_SECONDS}"
        )
    return bans


def main() -> None:
    if not ENABLED:
        _disable_tool("iptables")
        _disable_tool("ip6tables")
        print("connection guard disabled")
        return

    ports = _managed_public_ports()
    if not ports:
        print(f"no public managed inbound ports found in {MANAGED_INBOUNDS_FILE}")
        return

    bans = _refresh_dynamic_bans(ports)
    ok4 = _apply_tool("iptables", ports, MAX_PER_IP, "32", bans)
    ok6 = _apply_tool("ip6tables", ports, IPV6_MAX_PER_IP, "128", bans)
    if not ok4 and not ok6:
        raise SystemExit("no iptables backend was available for connection guard")


if __name__ == "__main__":
    main()
