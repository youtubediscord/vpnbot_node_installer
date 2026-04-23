#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import zlib
from pathlib import Path
from typing import Any


DEFAULT_MANAGED_FILE = "/opt/vpnbot/xray-core/config/50_vpnbot_managed_inbounds.json"
DEFAULT_XRAY_BIN = "/opt/vpnbot/xray-core/bin/xray"
DEFAULT_XRAY_CONFDIR = "/opt/vpnbot/xray-core/config"
DEFAULT_XRAY_ASSET_DIR = "/opt/vpnbot/xray-core/share"
DEFAULT_API_SERVER = "127.0.0.1:10085"
DEFAULT_XRAY_SERVICE_NAME = "vpnbot-xray.service"
DEFAULT_HANDLER_MISMATCH_RESTART_COOLDOWN_SECONDS = 900
DEFAULT_RESTART_STATE_FILE = "/var/lib/vpnbot-xrayctl/restart_state.json"


class XrayCtlError(RuntimeError):
    pass


def _json_response(payload: dict[str, Any], *, exit_code: int = 0) -> int:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    return exit_code


def _load_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"inbounds": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception as exc:
        raise XrayCtlError(f"failed to parse managed JSON: {exc}") from exc
    if not isinstance(payload, dict):
        payload = {}
    if not isinstance(payload.get("inbounds"), list):
        payload["inbounds"] = []
    return payload


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    current_mode = None
    if path.exists():
        try:
            current_mode = path.stat().st_mode & 0o777
        except OSError:
            current_mode = None
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        if current_mode is not None:
            os.chmod(tmp_name, current_mode)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _stable_inbound_id(inbound: dict[str, Any]) -> int:
    raw_id = inbound.get("id")
    try:
        value = int(raw_id)
        if value > 0:
            return value
    except Exception:
        pass
    key = f"{inbound.get('tag') or ''}|{inbound.get('port') or ''}|{inbound.get('protocol') or ''}"
    value = zlib.crc32(key.encode("utf-8")) & 0x7FFFFFFF
    return value or 1


def _normalize_protocol(protocol: Any) -> str:
    proto = str(protocol or "").strip().lower()
    if proto == "ss":
        return "shadowsocks"
    if proto == "hy2":
        return "hysteria2"
    return proto


def _client_identifier_field(protocol: Any) -> str:
    proto = _normalize_protocol(protocol)
    if proto in {"trojan", "shadowsocks", "hysteria2"}:
        return "password"
    return "id"


def _extract_client_identifier(client: dict[str, Any], protocol: Any) -> str:
    preferred = _client_identifier_field(protocol)
    for key in (preferred, "id", "password", "uuid"):
        value = client.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _build_client_identity_fields(protocol: Any, identifier: str) -> dict[str, str]:
    proto = _normalize_protocol(protocol)
    if proto in {"vless", "vmess"}:
        return {"id": identifier}
    if proto in {"trojan", "shadowsocks", "hysteria2"}:
        return {"id": identifier, "password": identifier}
    if proto == "tuic":
        return {"id": identifier, "uuid": identifier, "password": identifier}
    return {"id": identifier}


def _normalize_inbound(inbound: dict[str, Any]) -> dict[str, Any]:
    obj = dict(inbound)
    obj.setdefault("enable", True)
    obj.setdefault("remark", obj.get("tag") or f"Xray inbound {obj.get('port') or ''}".strip())
    obj["id"] = _stable_inbound_id(obj)
    for key in ("settings", "streamSettings", "sniffing", "allocate"):
        value = obj.get(key)
        if isinstance(value, str):
            try:
                obj[key] = json.loads(value)
            except Exception:
                obj[key] = {}
        elif not isinstance(value, (dict, list)):
            obj[key] = {}
    settings = obj.setdefault("settings", {})
    if isinstance(settings, dict) and not isinstance(settings.get("clients"), list):
        settings["clients"] = []
    return obj


def _compact_inbound_for_client(inbound: dict[str, Any], client: dict[str, Any]) -> dict[str, Any]:
    obj = json.loads(json.dumps(inbound, ensure_ascii=False))
    settings = obj.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        obj["settings"] = settings
    settings["clients"] = [client]
    return obj


def _find_raw_inbound(payload: dict[str, Any], inbound_id: int) -> dict[str, Any] | None:
    for raw in payload.get("inbounds") or []:
        if isinstance(raw, dict) and _stable_inbound_id(raw) == int(inbound_id):
            return raw
    return None


def _find_client(user_id: int, inbound: dict[str, Any]) -> dict[str, Any] | None:
    settings = inbound.get("settings") or {}
    clients = settings.get("clients", []) if isinstance(settings, dict) else []
    if not isinstance(clients, list):
        return None
    try:
        port = int(inbound.get("port") or 0)
    except Exception:
        port = 0
    candidates = {
        f"tele{int(user_id)}_port{port}",
        f"tele{int(user_id)}",
        str(int(user_id)),
    }
    prefix = f"tele{int(user_id)}_port"
    for client in clients:
        if not isinstance(client, dict):
            continue
        email = str(client.get("email") or "").strip()
        if email in candidates or email.startswith(prefix):
            return client
    return None


def _client_email(user_id: int, inbound: dict[str, Any]) -> str:
    return f"tele{int(user_id)}_port{int(inbound.get('port') or 0)}"


def _client_flow(inbound: dict[str, Any]) -> str:
    stream = inbound.get("streamSettings") or {}
    if not isinstance(stream, dict):
        stream = {}
    network = str(stream.get("network") or "").lower()
    security = str(stream.get("security") or "").lower()
    if network == "tcp" and security in {"reality", "xtls"}:
        return "xtls-rprx-vision"
    return ""


def _run(args: list[str], *, timeout: int = 30, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _api_user_count(output: str, verb: str) -> int | None:
    match = re.search(rf"\b{re.escape(verb)}\s+(\d+)\s+user", str(output or ""), re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def _api_added_no_users(output: str) -> bool:
    count = _api_user_count(output, "Added")
    return count == 0 if count is not None else "Added 0 user" in str(output or "")


def _api_removed_no_users(output: str) -> bool:
    count = _api_user_count(output, "Removed")
    return count == 0 if count is not None else "Removed 0 user" in str(output or "")


def _api_reports_duplicate(out: str, err: str) -> bool:
    return "already exists" in f"{out}\n{err}".lower()


def _api_reports_handler_missing(out: str, err: str) -> bool:
    text = f"{out}\n{err}".lower()
    return "handler not found" in text and "failed to get handler" in text


def _validate_config(ns: argparse.Namespace) -> None:
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(ns.xray_asset_dir)
    env["XRAY_LOCATION_CONFDIR"] = str(ns.xray_confdir)
    code, out, err = _run(
        [str(ns.xray_bin), "run", "-confdir", str(ns.xray_confdir), "-dump"],
        timeout=60,
        env=env,
    )
    if code != 0:
        raise XrayCtlError(f"xray config validation failed: exit={code} stdout={out[-500:]} stderr={err[-500:]}")


def _api_user_action_payload(inbound: dict[str, Any], client: dict[str, Any]) -> dict[str, Any]:
    settings = json.loads(json.dumps(inbound.get("settings") or {}, ensure_ascii=False))
    if not isinstance(settings, dict):
        settings = {}
    settings["clients"] = [client]
    return {
        "inbounds": [
            {
                "tag": inbound.get("tag"),
                "listen": inbound.get("listen") or "0.0.0.0",
                "port": int(inbound.get("port") or 0),
                "protocol": inbound.get("protocol"),
                "settings": settings,
            }
        ]
    }


def _write_temp_api_payload(payload: dict[str, Any]) -> Path:
    fd, tmp_name = tempfile.mkstemp(prefix="vpnbot-xray-api-", suffix=".json", dir="/tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return Path(tmp_name)


def _api_add_user(ns: argparse.Namespace, api_payload: dict[str, Any]) -> tuple[int, str, str]:
    tmp_path = _write_temp_api_payload(api_payload)
    try:
        return _run([str(ns.xray_bin), "api", "adu", f"--server={ns.api_server}", str(tmp_path)], timeout=30)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _api_remove_user(ns: argparse.Namespace, tag: str, email: str) -> tuple[int, str, str]:
    return _run(
        [str(ns.xray_bin), "api", "rmu", f"--server={ns.api_server}", f"-tag={tag}", email],
        timeout=30,
    )


def _load_restart_state(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    result: dict[str, float] = {}
    for key, value in payload.items():
        try:
            result[str(key)] = float(value)
        except Exception:
            continue
    return result


def _save_restart_state(path: Path, payload: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _restart_state_path(ns: argparse.Namespace) -> Path:
    raw = str(getattr(ns, "restart_state_file", "") or "").strip()
    return Path(raw or DEFAULT_RESTART_STATE_FILE)


def _restart_xray_service(ns: argparse.Namespace) -> None:
    code, out, err = _run(
        ["systemctl", "restart", str(ns.xray_service_name)],
        timeout=60,
    )
    if code != 0:
        raise XrayCtlError(
            f"failed to restart xray service {ns.xray_service_name}: "
            f"exit={code} stdout={out[-500:]} stderr={err[-500:]}"
        )
    code, out, err = _run(
        ["systemctl", "is-active", str(ns.xray_service_name)],
        timeout=20,
    )
    if code != 0 or str(out or "").strip() != "active":
        raise XrayCtlError(
            f"xray service {ns.xray_service_name} did not become active after restart: "
            f"exit={code} stdout={out[-200:]} stderr={err[-200:]}"
        )


def _maybe_restart_xray_service_for_handler_mismatch(ns: argparse.Namespace) -> None:
    state_path = _restart_state_path(ns)
    state = _load_restart_state(state_path)
    service_name = str(ns.xray_service_name)
    cooldown = max(60, int(getattr(ns, "handler_mismatch_restart_cooldown_seconds", DEFAULT_HANDLER_MISMATCH_RESTART_COOLDOWN_SECONDS)))
    now = time.time()
    last_restart_at = float(state.get(service_name) or 0.0)
    if last_restart_at > 0.0:
        age = max(0.0, now - last_restart_at)
        if age < cooldown:
            left = max(1, int(cooldown - age))
            raise XrayCtlError(
                f"xray handler-mismatch restart skipped by cooldown for service {service_name}: "
                f"{left}s left"
            )

    _restart_xray_service(ns)
    state[service_name] = now
    _save_restart_state(state_path, state)


def _lock_path(ns: argparse.Namespace) -> Path:
    if ns.lock_file:
        return Path(ns.lock_file)
    return Path(f"{ns.managed_file}.lock")


class _FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fh = None

    def __enter__(self) -> "_FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = self.path.open("a+", encoding="utf-8")
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fh is not None:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()


def _compact_inbound_for_listing(inbound: dict[str, Any]) -> dict[str, Any]:
    compact = json.loads(json.dumps(inbound, ensure_ascii=False))
    settings = compact.get("settings")
    if not isinstance(settings, dict):
        settings = {}
        compact["settings"] = settings
    clients = settings.get("clients", [])
    client_count = len(clients) if isinstance(clients, list) else 0
    settings["clients"] = []
    compact["client_count"] = client_count
    return compact


def cmd_list_inbounds(ns: argparse.Namespace) -> dict[str, Any]:
    payload = _load_payload(Path(ns.managed_file))
    inbounds = [_normalize_inbound(raw) for raw in payload.get("inbounds") or [] if isinstance(raw, dict)]
    if ns.compact:
        inbounds = [_compact_inbound_for_listing(inbound) for inbound in inbounds]
    return {"ok": True, "inbounds": inbounds, "count": len(inbounds)}


def cmd_ensure_client(ns: argparse.Namespace) -> dict[str, Any]:
    path = Path(ns.managed_file)
    with _FileLock(_lock_path(ns)):
        original_payload = _load_payload(path)
        payload = json.loads(json.dumps(original_payload, ensure_ascii=False))
        raw = _find_raw_inbound(payload, int(ns.inbound_id))
        if raw is None:
            raise XrayCtlError(f"inbound {ns.inbound_id} not found")
        inbound = _normalize_inbound(raw)
        existing = _find_client(int(ns.user_id), inbound)
        if existing:
            return {
                "ok": True,
                "changed": False,
                "inbound": _compact_inbound_for_client(inbound, existing),
                "client": existing,
            }

        proto = _normalize_protocol(inbound.get("protocol"))
        identifier = str(uuid.uuid4())
        new_client: dict[str, Any] = {
            **_build_client_identity_fields(proto, identifier),
            "email": _client_email(int(ns.user_id), inbound),
        }
        flow = _client_flow(inbound)
        if proto == "vless" and flow:
            new_client["flow"] = flow

        settings = raw.setdefault("settings", {})
        if not isinstance(settings, dict):
            settings = {}
            raw["settings"] = settings
        clients = settings.setdefault("clients", [])
        if not isinstance(clients, list):
            clients = []
            settings["clients"] = clients
        clients.append(new_client)

        _atomic_write(path, payload)
        try:
            _validate_config(ns)
            api_payload = _api_user_action_payload(inbound, new_client)
            code, out, err = _api_add_user(ns, api_payload)
            restarted_for_handler_mismatch = False
            if code != 0 and _api_reports_handler_missing(out, err):
                _maybe_restart_xray_service_for_handler_mismatch(ns)
                restarted_for_handler_mismatch = True
                code, out, err = _api_add_user(ns, api_payload)
            if code != 0:
                raise XrayCtlError(f"xray api add user failed: exit={code} stdout={out[-500:]} stderr={err[-500:]}")
            repaired_duplicate = False
            if _api_added_no_users(out):
                tag = str(inbound.get("tag") or "").strip()
                email = str(new_client.get("email") or "").strip()
                if _api_reports_handler_missing(out, err) and not restarted_for_handler_mismatch:
                    _maybe_restart_xray_service_for_handler_mismatch(ns)
                    restarted_for_handler_mismatch = True
                    retry_code, retry_out, retry_err = _api_add_user(ns, api_payload)
                    if retry_code == 0 and not _api_added_no_users(retry_out):
                        out, err = retry_out, retry_err
                    elif retry_code != 0:
                        raise XrayCtlError(
                            "xray handler-mismatch add retry failed after restart: "
                            f"exit={retry_code} stdout={retry_out[-500:]} stderr={retry_err[-500:]}"
                        )
                if _api_reports_duplicate(out, err) and tag and email:
                    rm_code, rm_out, rm_err = _api_remove_user(ns, tag, email)
                    if rm_code == 0:
                        retry_code, retry_out, retry_err = _api_add_user(ns, api_payload)
                        if retry_code == 0 and not _api_added_no_users(retry_out):
                            repaired_duplicate = True
                            out, err = retry_out, retry_err
                        else:
                            raise XrayCtlError(
                                "xray duplicate repair add retry failed: "
                                f"exit={retry_code} stdout={retry_out[-500:]} stderr={retry_err[-500:]}"
                            )
                    else:
                        raise XrayCtlError(
                            "xray duplicate repair remove failed: "
                            f"exit={rm_code} stdout={rm_out[-500:]} stderr={rm_err[-500:]}"
                        )
                if not repaired_duplicate:
                    raise XrayCtlError(f"xray api did not add user: stdout={out[-500:]} stderr={err[-500:]}")
        except Exception:
            _atomic_write(path, original_payload)
            raise

        updated_payload = _load_payload(path)
        updated_raw = _find_raw_inbound(updated_payload, int(ns.inbound_id)) or raw
        return {
            "ok": True,
            "changed": True,
            "duplicate_repaired": repaired_duplicate,
            "inbound": _compact_inbound_for_client(_normalize_inbound(updated_raw), new_client),
            "client": new_client,
        }


def cmd_remove_client(ns: argparse.Namespace) -> dict[str, Any]:
    path = Path(ns.managed_file)
    with _FileLock(_lock_path(ns)):
        original_payload = _load_payload(path)
        payload = json.loads(json.dumps(original_payload, ensure_ascii=False))
        raw = _find_raw_inbound(payload, int(ns.inbound_id))
        if raw is None:
            raise XrayCtlError(f"inbound {ns.inbound_id} not found")
        inbound = _normalize_inbound(raw)
        tag = str(inbound.get("tag") or "").strip()
        api_email = _client_email(int(ns.user_id), inbound)
        settings = raw.setdefault("settings", {})
        target = _find_client(int(ns.user_id), inbound)

        if not target:
            if tag and api_email:
                code, out, err = _api_remove_user(ns, tag, api_email)
                if code != 0:
                    raise XrayCtlError(
                        f"xray api runtime-only remove failed: exit={code} stdout={out[-500:]} stderr={err[-500:]}"
                    )
                runtime_removed = not _api_removed_no_users(out)
                return {"ok": True, "removed": runtime_removed, "runtime_only": runtime_removed}
            return {"ok": True, "removed": False, "runtime_only": False}

        if not isinstance(settings, dict):
            return {"ok": True, "removed": False, "runtime_only": False}
        clients = settings.get("clients", [])
        if not isinstance(clients, list):
            return {"ok": True, "removed": False, "runtime_only": False}

        target_email = str(target.get("email") or "")
        target_id = _extract_client_identifier(target, inbound.get("protocol"))
        kept = []
        removed = False
        for client in clients:
            if not isinstance(client, dict):
                kept.append(client)
                continue
            email = str(client.get("email") or "")
            identifier = _extract_client_identifier(client, inbound.get("protocol"))
            if email == target_email or (target_id and identifier == target_id):
                removed = True
                continue
            kept.append(client)
        settings["clients"] = kept
        if not removed:
            return {"ok": True, "removed": False, "runtime_only": False}

        _atomic_write(path, payload)
        try:
            _validate_config(ns)
            code, out, err = _api_remove_user(ns, tag, target_email)
            if code != 0 and _api_reports_handler_missing(out, err):
                _maybe_restart_xray_service_for_handler_mismatch(ns)
                restarted_for_handler_mismatch = True
                code, out, err = _api_remove_user(ns, tag, target_email)
            else:
                restarted_for_handler_mismatch = False
            if code != 0:
                raise XrayCtlError(f"xray api remove user failed: exit={code} stdout={out[-500:]} stderr={err[-500:]}")
        except Exception:
            _atomic_write(path, original_payload)
            raise

        return {
            "ok": True,
            "removed": True,
            "runtime_only": False,
            "email": target_email,
            "handler_mismatch_restarted": restarted_for_handler_mismatch,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local VPnBot Xray-core control helper")
    parser.add_argument("--managed-file", default=DEFAULT_MANAGED_FILE)
    parser.add_argument("--xray-bin", default=DEFAULT_XRAY_BIN)
    parser.add_argument("--xray-confdir", default=DEFAULT_XRAY_CONFDIR)
    parser.add_argument("--xray-asset-dir", default=DEFAULT_XRAY_ASSET_DIR)
    parser.add_argument("--api-server", default=DEFAULT_API_SERVER)
    parser.add_argument("--xray-service-name", default=DEFAULT_XRAY_SERVICE_NAME)
    parser.add_argument("--handler-mismatch-restart-cooldown-seconds", type=int, default=DEFAULT_HANDLER_MISMATCH_RESTART_COOLDOWN_SECONDS)
    parser.add_argument("--restart-state-file", default=DEFAULT_RESTART_STATE_FILE)
    parser.add_argument("--lock-file", default="")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_inbounds = subparsers.add_parser("list-inbounds")
    list_inbounds.add_argument("--compact", action="store_true")

    ensure = subparsers.add_parser("ensure-client")
    ensure.add_argument("--inbound-id", required=True, type=int)
    ensure.add_argument("--user-id", required=True, type=int)

    remove = subparsers.add_parser("remove-client")
    remove.add_argument("--inbound-id", required=True, type=int)
    remove.add_argument("--user-id", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    try:
        if ns.command == "list-inbounds":
            return _json_response(cmd_list_inbounds(ns))
        if ns.command == "ensure-client":
            return _json_response(cmd_ensure_client(ns))
        if ns.command == "remove-client":
            return _json_response(cmd_remove_client(ns))
        raise XrayCtlError(f"unknown command: {ns.command}")
    except Exception as exc:
        return _json_response({"ok": False, "error": str(exc), "error_type": type(exc).__name__}, exit_code=1)


if __name__ == "__main__":
    raise SystemExit(main())
