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
  activity, abuse-audit and multi-IP scoring HTTP service. Multi-IP scoring is
  based on short activity windows, per-user Xray traffic counters, short
  traffic-delta windows, and a local runtime history file; it does not disable
  clients by itself.
- `assets/vpnbot_xray_sync_routes.py` - nginx route sync helper for standalone
  Xray-core managed inbounds.
- `assets/vpnbot_xui_sync_routes.py` - nginx route sync helper for legacy
  3x-ui inbounds.

Standalone Xray-core installs block proxied user egress to Russian destination
domains/IPs by default through Xray `routing` and the `blackhole` outbound. The
installer downloads `roscomvpn-geosite.dat` from
`hydraponique/roscomvpn-geosite` and uses `ext:roscomvpn-geosite.dat:category-ru`
plus conservative fallback rules for `.ru`, `.su`, `.рф`, Yandex/VK domains and
`geoip:ru`. `domain:pally.info` and `domain:pal24.pro` are allowed before the RU
block because they are payment gateways. This does not add a server firewall
rule, so REALITY `dest` camouflage targets such as Yandex remain reachable by
the node itself. Set `VPNBOT_XRAY_BLOCK_RU_EGRESS=0` before running the
installer to disable that routing block for a special node. Rerun
`/usr/local/bin/vpnbot-xray-heal-routes` on an installed standalone node to
refresh `roscomvpn-geosite.dat`, reapply the managed routing rules, validate
Xray, and trigger nginx route-sync without editing JSON by hand.

For a side-by-side smoke test on a legacy node where another service already
owns public HTTP/TCP ports, set `VPNBOT_NGINX_AUTOSTART=0`. Route sync will
still validate and write generated files, but it will not try to start nginx.
Leave the default `VPNBOT_NGINX_AUTOSTART=1` for normal fresh installs.

## Latest Policy

This repository intentionally uses `main` as latest. New installs always fetch
the current installer and current assets.

If a bad installer is pushed, rollback is done by fixing or reverting `main`,
not by selecting older release tags.

Do not publish a parallel gist copy of this installer. The old VLESS/Xray gist
was intentionally retired so there is one source of truth: this repository.
