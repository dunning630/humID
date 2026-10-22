---
"@humid/mobile": patch
---

3.2.1 is a security release: it carries the fixes 3.2.0 was built without. A duress unlock is now signed into the sign-in itself, so a stolen session can't erase or lock down a vault (PC-01). A new phone can join only with a link one of your devices approved, or a released recovery (PC-02). A document opens only if your own key signed it, so a server can't plant one (PC-03). Activity pins the ledger's key on first check and counts only cosigners built into the app (PC-04). Builds are released only from reviewed code on main, with every build action pinned (PC-05, PC-06, PC-11). It also includes 4.0 credentials and the "Proving it's you" messaging core, which have no app screens yet.
