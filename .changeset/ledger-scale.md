---
"@humid/ledger-service": minor
---

The ledger scales with its log (crypto review, efficiency). The tree size is one indexed lookup instead of `COUNT(*)` over every leaf on every write; reading the history re-uses the account's signed head until it moves or is an hour old, instead of an ML-DSA-87 signature per read; and the public log signs at most one checkpoint per `HUMID_TLOG_CHECKPOINT_MS` (default 5 s), not one per entry, pruning superseded uncosigned ones after an hour. An inclusion proof for an entry newer than the latest checkpoint waits for the next one.
