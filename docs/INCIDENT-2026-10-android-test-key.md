# Incident 2026-10: Android test signing key committed to the repository

Status: **fixed in code; the maintainer's cleanup below is still open.**
Finding: PC-05 (High), pre-certification security audit, October 2026.

## What happened

An Android signing key store, `tools/android-test.keystore` (store and key
password `android`), was committed so CI could sign test builds. Its
certificate has SHA-256

```
b066cd4564ac8446b02567e276992aacf64783004de81da3d3f1e51f3411928c
```

The file was later deleted from `main`, but:

- it is still in the repository's history, and in the tip of 22 other branches;
- nine pre-releases, **app-v1.5.0, 1.6.0, 1.7.0, 1.7.1, 1.7.2, 1.7.3, 1.7.4,
  1.7.5 and 1.7.6** (published 2026-10-15 to 2026-10-16), still offer
  `app-universal-debug.apk`: a **debuggable** build of `app.humid.vault`
  signed with that key.

## Impact

- Anyone who can read the repository, or any copy of it (clones, forks, CI
  caches, backups), has the private key. They can sign an APK as
  `app.humid.vault` with the same certificate. Android accepts it **as an
  update** to an installed 1.5.0 to 1.7.6 debug build, and the update can read
  that app's data.
- The debug builds themselves are debuggable (`adb run-as` reads the app's
  files), have WebView remote debugging on, allow cleartext HTTP and log to
  logcat.
- A server that trusted this certificate (by `HUMID_ANDROID_CERT_DIGESTS` or
  `HUMID_ANDROID_ALLOW_ANY_SIGNER=1`) would accept liveness keys from any app
  signed with it, so an attacker's re-signed copy could join.
- The release key (certificate `bfd3dc42…578e`, made 2026-10-16) is a
  different key and is not affected. The repository is private, which limits
  who could have read the key, but doesn't make it secret again.

## Fixed in code (branch `security/release-chain`)

| Change | Where |
|---|---|
| A hard deny-list: servers refuse any app signed with this certificate (`revoked_signer`), even if an operator lists it in `HUMID_ANDROID_CERT_DIGESTS` or sets `HUMID_ANDROID_ALLOW_ANY_SIGNER=1`. Tested. | `packages/attest/src/roots.js` (`REVOKED_ANDROID_CERTS`), `packages/attest/src/android.js`, `tests/attest.test.js` |
| The release workflow checks **every** APK and AAB it publishes (apksigner for APKs; jarsigner and keytool for the AAB): each must be signed only with the release certificate and with no revoked certificate. Only those files are published, so Gradle's `intermediary-bundle.aab` no longer ships. Debug builds were already refused. | `.github/workflows/release.yml` |
| Key stores and secrets files can't be committed by accident: `*.keystore`, `*.jks`, `*.p12`, `*.pfx`, `*.p8`, `keystore.properties`, `**/.env` and the transparency-log cosigner files are ignored by git and Docker. | `.gitignore`, `.dockerignore` |
| Every pull request and every branch push is scanned for secrets (gitleaks, pinned and checksum-verified), and any key store file in a new commit fails the check. | `.github/workflows/secret-scan.yml`, `.gitleaks.toml` |
| Regression tests for the workflow guard rails. | `tests/release-chain.test.js` |

## Still to do: maintainer actions

These change or delete things on GitHub and rewrite history, so they are for
the maintainer to run, in this order. **The commands below have not been run.**
Use a machine with an authenticated `gh` (owner rights) and `git filter-repo`
(`pip install git-filter-repo`).

- [ ] **1. Delete the nine debug APKs** from the pre-releases (asset ids as of
  2026-10-21; re-list first to confirm):

  ```bash
  # to be run by the maintainer
  gh api "repos/dunning630/humID/releases?per_page=100" --paginate \
    --jq '.[] | .tag_name as $t | .assets[] | select(.name == "app-universal-debug.apk") | "\(.id)\t\($t)"'
  for id in 644272408 644469902 645724733 645945676 647703467 647997795 648153103 648768661 648910799; do
    gh api -X DELETE "repos/dunning630/humID/releases/assets/$id"
  done
  ```

  Optionally mark those releases as withdrawn
  (`gh release edit app-v1.7.6 --notes "Withdrawn: debug build signed with a leaked key. Uninstall it and install the current HumID."`, and the same for the other eight).

- [ ] **2. Tell everyone on 1.5.0 to 1.7.6 to uninstall, not update.** The
  current app is signed with the release key, so Android refuses it as an
  update over the debug build anyway; more importantly, while a debug build
  stays installed, anyone holding the leaked key can push an "update" that
  reads its data. Uninstall, install the current release, enrol again (servers
  now refuse the old installs' liveness keys).

- [ ] **3. Delete stale branches.** List every branch whose tip still has the
  key, then delete the ones that are no longer needed (merge anything worth
  keeping first):

  ```bash
  # to be run by the maintainer
  git clone --mirror https://github.com/dunning630/humID.git humID-audit.git && cd humID-audit.git
  for b in $(git for-each-ref --format='%(refname:short)' refs/heads); do
    git cat-file -e "$b:tools/android-test.keystore" 2>/dev/null && echo "$b"
  done
  git push origin --delete <branch> [<branch> ...]
  ```

- [ ] **4. Purge the key from history** with `git filter-repo`, on a fresh
  mirror clone. First list every key-like file that was ever committed, and
  add any others to the command:

  ```bash
  # to be run by the maintainer
  git clone --mirror https://github.com/dunning630/humID.git humID-clean.git && cd humID-clean.git
  git log --all --format= --name-only | grep -iE '\.(keystore|jks|p12|pfx|p8)$|keystore\.properties$' | sort -u
  git filter-repo --invert-paths --path tools/android-test.keystore
  git remote add origin https://github.com/dunning630/humID.git   # filter-repo removes the remote
  git push --force --all origin
  git push --force --tags origin
  ```

  Then: every collaborator re-clones (an old clone pushed back reintroduces
  the key); ask GitHub Support to purge cached views and pull-request refs of
  the old commits (see GitHub's "Removing sensitive data from a repository"
  guide); delete forks you control. Release tags are rewritten too, so
  re-check that each published release still points at the intended commit.

- [ ] **5. Rotate every credential that could read the repository**: personal
  access tokens (classic and fine-grained), deploy keys, GitHub App and OAuth
  app installations, CI or hosting integrations, and any machine with a clone.
  Review who has read access (collaborators, outside collaborators). The
  leaked key itself can't be rotated; it is refused by the deny-list
  permanently instead.

- [ ] **6. Close the path that let it ship**: set up the `release` environment
  and move the signing secrets there (RELEASING.md, "Release environment"),
  and enable branch and tag rulesets once the plan allows (PC-06).

## Lessons

- Signing keys never go in the repository, test keys included: a test key
  that signs the production package name is a production key.
- A release must be built from reviewed code on `main`, and the workflow must
  check every file it publishes, not the first one it finds.
