// The HumID release keys this admin console trusts to sign HumID Server for Windows
// updates (release.mjs, docs/ADMIN.md, RELEASING.md). One or two base64url ML-DSA-87
// public keys: two only while moving from an old key to a new one.
//
// ┌──────────────────────────────────────────────────────────────────────────────────┐
// │ EMPTY ON PURPOSE. While this list is empty the console refuses EVERY update, and  │
// │ the release workflow refuses to build a release.                                  │
// │                                                                                   │
// │ Before the next release, the maintainer, on a computer that's offline:            │
// │   node tools/release-key.mjs keygen --out <USB drive>\humid-release.key           │
// │ then pastes the public key it prints below (as a string, with a comment naming    │
// │ the key's fingerprint and date) and commits it. The secret key file never goes    │
// │ near GitHub, CI or a server. Nobody else can make this key for you: a key made by │
// │ someone else (or by a tool, in a pull request) is a key someone else holds.       │
// └──────────────────────────────────────────────────────────────────────────────────┘
//
// A server only learns a new key by installing an update signed by a key it already
// trusts (or by a person installing a release by hand). So to rotate: add the new key
// here beside the old one, release (signed with the old key), then sign later releases
// with the new key and remove the old one in a later release.
export const RELEASE_KEYS = [
];
