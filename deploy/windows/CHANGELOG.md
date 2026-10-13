# HumID Server for Windows

## 1.0.0

- The five HumID services and a local edge in one background task (scheduled task at startup, LOCAL SERVICE account, restarted if it stops), bound to 127.0.0.1.
- Double-click installer; official Node.js 22 downloaded from nodejs.org and checksum verified.
- `humid` command: install / update, start, stop, restart, status, logs, set, show, backup, restore, expose (Tailscale Funnel or Cloudflare Tunnel), uninstall.
- Offers to keep a laptop awake while plugged in.
