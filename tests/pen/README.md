# Penetration regression pack

What the October 2026 dynamic test pass tried against the stack, kept as tests so
it stays true. Every file boots the seven services in-process (`tests/e2e/stack.js`,
random ports, throwaway data, production limiter values) and drives them with the
repo's own `@humid/htp` client and the simulated phones in `tests/e2e/holder.js`.
Each refusal is asserted by the exact code in [docs/PROTOCOL.md](../../docs/PROTOCOL.md),
and every refusal body is checked for leaked internals (paths, stack frames, hosts).

Run it:

```
npm run test:pen            # all files, about 20 s
node --test tests/pen/frames.test.js
```

| File | What it asserts |
|---|---|
| `frames.test.js` | Hand-built HTP frames against `/htp/v1/call`: verbatim replay, seq 0 and an old seq after a jump are `409 replay`; ±3 min timestamps are `stale_frame`; a flipped sid byte is `session_unknown`; flipped ciphertext or tag is `bad_frame` (and the genuine frame still works after a tampered copy); empty, garbage and response-direction bodies are `bad_frame`; the content-type header is not trusted; GET on hello/call is `not_found`. |
| `stepup.test.js` | Step-up proofs on a download: none → `step_up_required`; wrong body hash or another device's key → `bad_proof`; a 2-minute-old `at` → `step_up_stale`; a reused ticket → `409 replay`; a nonce for a different action → `step_up_mismatch`; a never-issued nonce → `step_up_unknown`; rejected proofs reach the ledger as `access.denied`. |
| `sessions.test.js` | Session mixing: A's sid under B's keys → `bad_frame`; a sid after logout or one never issued → `session_unknown`; an anonymous session on an account route → `sign_in_required` inside the channel; a second handshake is a new, signed-out session. |
| `bruteforce.test.js` | Sign-in brute force: 10 × `bad_proof` then `rate_limited`, the correct key still signs in (SRV-02: failures only are counted), another identity is unaffected, the ten refusals and one throttle note are in the ledger. Own stack, because each attempt spends a handshake. |
| `limits.test.js` | Demo and desktop gates under the `attested` policy → `device_not_proven`; malformed hello bodies → `bad_json` / `handshake_rejected` with no stack; oversize hello and call bodies → `413 too_large` (the call cap via a second gateway with a 4 KB `maxCallBytes`, the existing option); the handshake flood: ≤ 30 per minute per IP, the rest `rate_limited`. SRV-24: an unknown account, an unknown device and a wrong key all get `401 bad_proof` with the same message, in similar time (no account-existence oracle). |
| `hardening.test.js` | Pre-auth limits: a frame for an unknown session is `session_unknown` from its header whatever its size; a signed-out session is capped at 512 KiB (`413`); a huge declared Content-Length is refused before the body is sent; recovery routes answer JSON `null` / array / scalar bodies with 400. |
| `load.test.js` | Load sanity, not a benchmark: 20 concurrent sessions × 20 calls (list, me, step-up download, ledger) complete with zero errors and no `audit_unavailable`. |
| `_lib.js` | Shared helpers: raw sessions, frame sealing, byte flipping, the leak regex. |

Not carried over from the dynamic pass: the raw-socket probes (request smuggling,
Host injection, 64 KB URLs, slowloris). Those hit Node's HTTP parser and the TLS edge,
which the in-process stack doesn't exercise; rerun them against a deployed stack.
