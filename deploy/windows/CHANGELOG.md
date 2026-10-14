# HumID Server for Windows

## 1.1.0

- Two-proof recovery: witnesses, ID chip anchor and seal card; any two, with waits set by the evidence (24 h with a station, 72 h with witnesses, 7 days for card + chip; doubled after a duress signal).
- ID chip checks (ICAO 9303 passive and active authentication). Put country signing certificates in `C:\ProgramData\HumID\csca`.
- Verification stations (`HUMID_STATION_ACCOUNTS`), duress lockdown (`HUMID_DURESS_COOLOFF_MS`), and the public transparency log at `/tlog/v1/*` with optional cosigners (`HUMID_TLOG_COSIGNERS`).

## 1.0.0

- The five HumID services and a local edge in one background task (scheduled task at startup, LOCAL SERVICE account, restarted if it stops), bound to 127.0.0.1.
- Double-click installer; official Node.js 22 downloaded from nodejs.org and checksum verified.
- `humid` command: install / update, start, stop, restart, status, logs, set, show, backup, restore, expose (Tailscale Funnel or Cloudflare Tunnel), uninstall.
- Offers to keep a laptop awake while plugged in.
