# @humid/svc

## 1.1.0

- `isMain(import.meta.url)`: a service starts itself only when it is the program being run, so several services can be hosted in one process (HumID Server for Windows).
- `HUMID_BIND_HOST` binds a service to one address, e.g. 127.0.0.1.
- `start()` rejects when the port can't be bound instead of crashing.

## 1.0.0

- HTTP service kit, Ed25519 internal assertions, SQLite with numbered migrations.
