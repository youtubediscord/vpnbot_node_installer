#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
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
SHARED_PORT_RE = re.compile(r"\[shared:(?P<port>\d{1,5})\]")


def _run(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def _cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


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


def _apply_tool(tool: str, ports: list[int], limit: int, mask: str) -> bool:
    if not _cmd_exists(tool):
        print(f"{tool}: unavailable, skipped")
        return False
    if not _ensure_chain(tool):
        print(f"{tool}: failed to create chain {CHAIN}, skipped")
        return False
    installed = 0
    for port in ports:
        if _add_limit_rule(tool, port, limit, mask):
            installed += 1
    print(f"{tool}: guarded {installed}/{len(ports)} port(s), max_per_ip={limit}, chain={CHAIN}")
    return installed > 0


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

    ok4 = _apply_tool("iptables", ports, MAX_PER_IP, "32")
    ok6 = _apply_tool("ip6tables", ports, IPV6_MAX_PER_IP, "128")
    if not ok4 and not ok6:
        raise SystemExit("no iptables backend was available for connection guard")


if __name__ == "__main__":
    main()
