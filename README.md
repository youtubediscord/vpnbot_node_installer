# VPnBot Node Installer

Latest-based installer bundle for VPnBot VPN nodes.

The entrypoint is `install.sh`. It downloads the current `scripts/install_vray.sh`
from `main`, and that installer downloads helper assets from `assets/`.

## Install

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/youtubediscord/vpnbot_node_installer/main/install.sh?ts=$(date +%s)")
```

## Why This Repo Exists

`install_vray.sh` used to be a fully monolithic shell script. That works, but it
gets hard to read once Python helpers and service scripts are embedded as large
heredocs.

This repository keeps the public bootstrap flow simple while allowing helper
files such as `assets/vpnbot_xrayctl.py` to stay readable and testable as normal
files.

## Latest Policy

This repository intentionally uses `main` as latest. New installs always fetch
the current installer and current assets.

If a bad installer is pushed, rollback is done by fixing or reverting `main`,
not by selecting older release tags.
