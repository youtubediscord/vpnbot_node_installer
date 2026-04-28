#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any


TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off"}
MANAGED_TAGS = {
    "vpnbot-allow-ru-egress-domains",
    "vpnbot-block-ru-domains",
    "vpnbot-block-ru-ips",
}


def env_bool(name: str, default: bool = True) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if raw in TRUTHY:
        return True
    if raw in FALSY:
        return False
    return default


def split_list(value: str) -> list[str]:
    out: list[str] = []
    for item in str(value or "").replace("\n", ",").split(","):
        item = item.strip()
        if item and item not in out:
            out.append(item)
    return out


def exact_legacy_rule(rule: dict[str, Any], key: str, values: list[str]) -> bool:
    if rule.get("type") != "field" or rule.get("outboundTag") != "block":
        return False
    if rule.get("ruleTag"):
        return False
    return set(rule.get(key) or []) == set(values)


def rule_covers(rule: dict[str, Any], key: str, values: list[str]) -> bool:
    if rule.get("type") != "field" or rule.get("outboundTag") != "block":
        return False
    present = set(rule.get(key) or [])
    return bool(values) and set(values).issubset(present)


def download_file(url: str, target: Path, *, timeout: int = 20) -> bool:
    if not url:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        req = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "vpnbot-xray-heal/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp, tmp.open("wb") as fh:
            shutil.copyfileobj(resp, fh)
        if tmp.stat().st_size <= 0:
            return False
        if target.exists() and target.read_bytes() == tmp.read_bytes():
            return False
        tmp.replace(target)
        return True
    finally:
        tmp.unlink(missing_ok=True)


def build_default_rules(share_dir: Path) -> tuple[list[str], list[str], list[str]]:
    default_domains = [
        "regexp:\\.ru$",
        "regexp:\\.su$",
        "regexp:\\.xn--p1ai$",
        "domain:ya.ru",
        "domain:yandex.com",
        "domain:yandex.net",
        "domain:yastatic.net",
        "domain:vk.com",
    ]
    default_ips = ["geoip:ru"]

    external_enabled = env_bool("VPNBOT_XRAY_BLOCK_RU_EXTERNAL_GEOSITE", default=True)
    external_file = str(os.environ.get("VPNBOT_XRAY_RU_GEOSITE_FILE", "")).strip()
    external_tag = str(os.environ.get("VPNBOT_XRAY_RU_GEOSITE_TAG", "")).strip()
    if external_enabled and external_file and external_tag and (share_dir / external_file).is_file():
        default_domains.insert(0, f"ext:{external_file}:{external_tag}")

    domains = default_domains + split_list(os.environ.get("VPNBOT_XRAY_BLOCK_RU_EXTRA_DOMAINS", ""))
    ips = default_ips + split_list(os.environ.get("VPNBOT_XRAY_BLOCK_RU_EXTRA_IPS", ""))
    allow_domains = split_list(os.environ.get("VPNBOT_XRAY_RU_EGRESS_ALLOW_DOMAINS", ""))
    return domains, ips, allow_domains


def load_routing(path: Path) -> dict[str, Any]:
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    routing = payload.setdefault("routing", {})
    if not isinstance(routing, dict):
        raise ValueError(f"{path}: routing must be an object")
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError(f"{path}: routing.rules must be an array")
    return payload


def heal_routing(path: Path, share_dir: Path) -> tuple[dict[str, Any], dict[str, Any], bool]:
    payload = load_routing(path)
    before = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    routing = payload["routing"]
    rules = routing["rules"]
    domains, ips, allow_domains = build_default_rules(share_dir)
    enabled = env_bool("VPNBOT_XRAY_BLOCK_RU_EGRESS", default=True)

    if enabled:
        strategy = str(routing.get("domainStrategy") or "").strip()
        if strategy not in {"IPIfNonMatch", "IPOnDemand"}:
            routing["domainStrategy"] = "IPIfNonMatch"

        managed: list[tuple[str, str, list[str], dict[str, Any]]] = []
        if allow_domains:
            managed.append(
                (
                    "vpnbot-allow-ru-egress-domains",
                    "domain",
                    allow_domains,
                    {
                        "type": "field",
                        "domain": allow_domains,
                        "outboundTag": "direct",
                        "ruleTag": "vpnbot-allow-ru-egress-domains",
                    },
                )
            )
        managed.extend(
            [
                (
                    "vpnbot-block-ru-domains",
                    "domain",
                    domains,
                    {
                        "type": "field",
                        "domain": domains,
                        "outboundTag": "block",
                        "ruleTag": "vpnbot-block-ru-domains",
                    },
                ),
                (
                    "vpnbot-block-ru-ips",
                    "ip",
                    ips,
                    {
                        "type": "field",
                        "ip": ips,
                        "outboundTag": "block",
                        "ruleTag": "vpnbot-block-ru-ips",
                    },
                ),
            ]
        )
        for tag, key, values, rule in reversed(managed):
            tagged_index = next(
                (idx for idx, existing in enumerate(rules) if isinstance(existing, dict) and existing.get("ruleTag") == tag),
                None,
            )
            if tagged_index is not None:
                rules[tagged_index] = rule
                continue

            legacy_index = next(
                (
                    idx
                    for idx, existing in enumerate(rules)
                    if isinstance(existing, dict) and exact_legacy_rule(existing, key, values)
                ),
                None,
            )
            if legacy_index is not None:
                rules[legacy_index] = rule
                continue

            if not any(rule_covers(existing, key, values) for existing in rules if isinstance(existing, dict)):
                rules.insert(0, rule)
    else:
        rules[:] = [
            rule
            for rule in rules
            if not (
                isinstance(rule, dict)
                and (
                    rule.get("ruleTag") in MANAGED_TAGS
                    or exact_legacy_rule(rule, "domain", domains)
                    or exact_legacy_rule(rule, "ip", ips)
                )
            )
        ]

    after = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    summary = {
        "enabled": enabled,
        "allow_domains": allow_domains,
        "domains": domains,
        "ips": ips,
        "domainStrategy": routing.get("domainStrategy"),
    }
    return payload, summary, before != after


def run(cmd: list[str], *, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return proc.returncode, proc.stdout.strip()


def service_active(service_name: str) -> str:
    if not service_name:
        return "unknown"
    code, out = run(["systemctl", "is-active", service_name], timeout=15)
    return out.strip() if out else f"exit:{code}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair VPnBot Xray routing and shared route state")
    parser.add_argument("--check", action="store_true", help="validate and report only; do not write files or restart services")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON report")
    parser.add_argument("--no-sync", action="store_true", help="do not run the nginx route sync helper")
    parser.add_argument("--no-restart", action="store_true", help="write files but do not restart Xray")
    args = parser.parse_args()

    confdir = Path(os.environ.get("XRAY_CORE_CONFIG_DIR", "/opt/vpnbot/xray-core/config"))
    share_dir = Path(os.environ.get("XRAY_CORE_SHARE_DIR", "/opt/vpnbot/xray-core/share"))
    routing_path = Path(os.environ.get("XRAY_CORE_ROUTING_FILE", str(confdir / "10_routing.json")))
    xray_bin = Path(os.environ.get("XRAY_CORE_BIN", "/opt/vpnbot/xray-core/bin/xray"))
    service_name = os.environ.get("XRAY_CORE_SERVICE_NAME", "vpnbot-xray.service")
    sync_script = Path(os.environ.get("XRAY_SYNC_SCRIPT", "/usr/local/bin/vpnbot-xray-sync-routes"))
    geosite_url = os.environ.get("VPNBOT_XRAY_RU_GEOSITE_URL", "")
    geosite_file = os.environ.get("VPNBOT_XRAY_RU_GEOSITE_FILE", "roscomvpn-geosite.dat")

    report: dict[str, Any] = {
        "routing_file": str(routing_path),
        "share_dir": str(share_dir),
        "service": service_name,
        "check": args.check,
    }
    backup_path = ""

    try:
        geosite_target = share_dir / geosite_file
        geosite_changed = False
        if env_bool("VPNBOT_XRAY_BLOCK_RU_EXTERNAL_GEOSITE", default=True) and geosite_url and not args.check:
            try:
                geosite_changed = download_file(geosite_url, geosite_target)
            except Exception as exc:
                report["geosite_error"] = str(exc)
        report["geosite_exists"] = geosite_target.is_file()
        report["geosite_changed"] = geosite_changed

        payload, routing_summary, routing_changed = heal_routing(routing_path, share_dir)
        report.update(routing_summary)
        report["routing_changed"] = routing_changed

        if not args.check and routing_changed:
            routing_path.parent.mkdir(parents=True, exist_ok=True)
            if routing_path.exists():
                backup_path = f"{routing_path}.bak.heal_{time.strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(routing_path, backup_path)
            routing_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report["backup"] = backup_path

        needs_restart = bool(geosite_changed or routing_changed)
        if needs_restart and not args.check:
            code, out = run([str(xray_bin), "run", "-confdir", str(confdir), "-test"], timeout=60)
            report["xray_test_code"] = code
            report["xray_test_tail"] = out[-1000:]
            if code != 0:
                if backup_path:
                    shutil.copy2(backup_path, routing_path)
                report["restored"] = bool(backup_path)
                raise RuntimeError("xray config test failed")
            if not args.no_restart:
                code, out = run(["systemctl", "restart", service_name], timeout=60)
                report["xray_restart_code"] = code
                report["xray_restart_tail"] = out[-1000:]
                if code != 0:
                    raise RuntimeError("xray service restart failed")

        if not args.no_sync and not args.check and sync_script.exists():
            code, out = run([str(sync_script)], timeout=90)
            report["sync_code"] = code
            report["sync_tail"] = out[-1000:]
            if code != 0:
                raise RuntimeError("route sync failed")

        report["xray_active"] = service_active(service_name)
        ok = report["xray_active"] == "active"
        report["ok"] = ok
    except Exception as exc:
        report["ok"] = False
        report["error"] = str(exc)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        status = "OK" if report.get("ok") else "ERROR"
        print(
            f"{status} routing_changed={report.get('routing_changed')} "
            f"geosite_changed={report.get('geosite_changed')} "
            f"xray_active={report.get('xray_active')} "
            f"allow={','.join(report.get('allow_domains') or [])}"
        )
        if report.get("backup"):
            print(f"backup={report['backup']}")
        if report.get("error"):
            print(f"error={report['error']}", file=sys.stderr)
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
