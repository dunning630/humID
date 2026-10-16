---
"@humid/mobile": patch
---

Reconnecting costs nothing while the connection is fine: the 30-second heartbeat is
gone, so a healthy, idle HumID sends no requests at all. A drop is still noticed the
moment any request fails, when the phone goes offline or back online, or when HumID
comes back to the screen; retries run only while it's disconnected. The bar's button
is now "Reconnect now".
