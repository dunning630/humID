---
"@humid/gateway-service": minor
"@humid/htp": minor
"@humid/api": minor
---

A visitor can't lock every holder out when the proxy can't name visitors (V76-03, Windows behind Tailscale Funnel with `HUMID_TRUST_FORWARDED=off`). When the forwarded address is the proxy's own loopback address, handshakes share a server-wide ceiling (`sharedHelloPerMin` / `HUMID_SHARED_HELLO_PER_MIN`, 600 a minute) instead of 30 per address, failed sign-ins count per identity and server-wide only, and in-flight bodies only against the server-wide cap. Every sign-in returns a one-use `helloPass` (`sessionView`); `HtpClient` sends it with its next handshake (`x-humid-hello-pass`), which skips every handshake limit, and `HumidApi` keeps it (in memory, and in `localStorage` where there is one, per server), so unlocking and checking in always get through.
