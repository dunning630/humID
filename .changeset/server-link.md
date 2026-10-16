---
"@humid/mobile": patch
---

The app notices when the vault server can't be reached, and reconnects by itself.

- Every request reports whether the server answered; the phone's online/offline
  events, HumID coming back to the screen, and a light 30-second heartbeat while
  the server is in use do too, so a drop is noticed even when nothing is tapped.
- After a drop it retries with backoff (1, 2, 4, 8, 15, then every 30 s, with
  jitter) for as long as it takes, pausing only while HumID is off the screen;
  coming back online or back to the screen tries at once.
- A bar at the top says what's happening ("Can't reach your vault · Trying again
  in 8 s", with Try now; or "No internet connection"). It waits 1.5 s, so blips
  don't flash it, and replaces the stack of "can't reach" error toasts.
- On recovery the screen reloads in the same session. If the server restarted and
  forgot the session, the app locks once with "Your session ended" (one live check
  signs back in), instead of three raw "Unknown session" errors.
- An unreachable server is no longer reported as "Public log check failed … your
  history may have been altered": the public-log check waits until it's back.
