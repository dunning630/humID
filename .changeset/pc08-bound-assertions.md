---
"@humid/svc": minor
"@humid/gateway-service": patch
---

Internal assertions are bound to one request (audit PC-08): `signRequestAssertion(sk, claims, { method, path, body })` signs the method, target and body hash in, and `createService` refuses an assertion on any other request or a second time (by `rid`). A captured assertion can no longer be replayed or turned from a read into a delete. Services and gateway must be upgraded together.
