# VPnBot Node Installer

Latest-based installer bundle for VPnBot VPN nodes.

## Public Repository Notice

This repository is intentionally **public**.

Fresh VPN nodes must be able to download the installer with plain `curl`
without GitHub tokens, SSH keys, or any private repository access. Because of
that, this repository must contain only installer code, helper scripts, static
templates, and public documentation.

Never commit runtime secrets here: no `.env` files, API tokens, SSH private
keys, real panel passwords, live server credentials, production runtime JSON, or
logs with sensitive data. If a value is generated during installation, it must
stay on the target server and must not be copied back into this repository.

The entrypoint is `install.sh`. It downloads the current `scripts/install_vray.sh`
from `main`, and that installer downloads helper assets from `assets/`.
The bootstrap uses `raw.githubusercontent.com/.../refs/heads/main` only for the first tiny `install.sh`. After that it downloads the current branch archive through `codeload.github.com`, so helper assets are installed from the same fresh extracted tree instead of stale branch-file CDN responses.

## Install

```bash
bash <(curl -fsSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/youtubediscord/vpnbot_node_installer/refs/heads/main/install.sh?ts=$(date +%s)")
```

## Why This Repo Exists

`install_vray.sh` used to be a fully monolithic shell script. That works, but it
gets hard to read once Python helpers and service scripts are embedded as large
heredocs.

This repository keeps the public bootstrap flow simple while allowing helper
files to stay readable and testable as normal files:

- `assets/vpnbot_xrayctl.py` - local Xray-core control helper used by the bot
  over SSH.
- `assets/vpnbot_xui_presets.py` - preset/catalog helper for legacy 3x-ui
  nodes.
- `assets/vpnbot_vless_presets.py` - shared VLESS/Trojan/VMess preset helper
  that delegates to 3x-ui or manages standalone Xray-core directly.
- `assets/reality_sni_pool.json` - shared REALITY SNI pool used by both preset
  helpers.
- `assets/vpnbot_xray_online_tracker.py` - local Xray-core online/recent
  activity and abuse-audit HTTP service.
- `assets/vpnbot_xray_sync_routes.py` - nginx route sync helper for standalone
  Xray-core managed inbounds.
- `assets/vpnbot_xui_sync_routes.py` - nginx route sync helper for legacy
  3x-ui inbounds.

## Latest Policy

This repository intentionally uses `main` as latest. New installs always fetch
the current installer and current assets.

If a bad installer is pushed, rollback is done by fixing or reverting `main`,
not by selecting older release tags.

Do not publish a parallel gist copy of this installer. The old VLESS/Xray gist
was intentionally retired so there is one source of truth: this repository.
