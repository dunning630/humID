//! Messages between units, and the bodies a holder signs. Shared so that no unit's module
//! imports another's: core and keys agree on these types, nothing else.

use serde::{Deserialize, Serialize};

use crate::proofs::{DeviceCert, DuressProof, Signed};
use crate::wire::{B64, Id};

/// Bodies the holder's device key signs (inside `Signed.body`), by app route.
pub mod app {
    use super::{B64, Deserialize, Id, Serialize};

    /// `POST /v1/objects`: what is being sealed. The envelope and the sealed share travel
    /// beside the signed body; their hashes are in it.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Upload {
        /// The object id (the app picks it: its index entry is sealed to it).
        pub object: Id,
        /// SHA3-512 of the envelope.
        pub envelope_hash: B64,
        /// The document's manifest hash (CORE.md §6.2): the upload share is bound to it.
        pub manifest_hash: B64,
        /// SHA3-512 of the share sealed to the keys unit.
        pub sealed_share_hash: B64,
        /// The encrypted index entry.
        pub index: B64,
    }

    /// `POST /v1/objects/:id/open`: humid-core's share request (CORE.md §6.3, type `0x0012`:
    /// account, document, manifest hash, one-time KEM key). The share is released sealed to
    /// that key under `H("HUMID-PQ2 share-request", [request])`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Open {
        /// The object.
        pub object: Id,
        /// The share request encoding.
        pub share_request: B64,
    }

    /// `DELETE /v1/objects/:id` and `PATCH /v1/objects/:id`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ObjectChange {
        /// The object.
        pub object: Id,
        /// The new index entry (PATCH only).
        #[serde(default)]
        pub index: Option<B64>,
    }

    /// `POST /v1/checkin/arm`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CheckinArm {
        /// Check in every … hours.
        pub window_h: u32,
        /// Longest single window the holder may pick at a check-in.
        pub max_window_h: u32,
        /// Grace after a missed deadline (minutes).
        pub grace_min: u32,
        /// Documents kept out of the erase (decoys).
        #[serde(default)]
        pub keep: Vec<Id>,
    }

    /// `POST /v1/checkin/check`.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CheckinCheck {
        /// A longer next window (hours), up to the armed maximum.
        #[serde(default)]
        pub next_window_h: Option<u32>,
    }

    /// Bodies that only name the action (device removal, close, disarm, cancel…).
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Empty {}
}

/// core → keys.
pub mod keys {
    use super::{B64, Deserialize, DeviceCert, DuressProof, Id, Serialize, Signed};

    /// Facts in core's `upload` statement.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct UploadFacts {
        /// Account.
        pub account: Id,
        /// Object.
        pub object: Id,
        /// SHA3-512 of the envelope core stored.
        pub envelope_hash: B64,
        /// The manifest hash the share is bound to.
        pub manifest_hash: B64,
        /// The holder proof core checked.
        pub proof_hash: B64,
        /// The `object.sealed` ledger entry.
        pub ledger_seq: i64,
    }

    /// `POST /v1/shares`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Store {
        /// Core's `upload` statement.
        pub statement: B64,
        /// The device's account-signed certificate.
        pub cert: DeviceCert,
        /// The holder's signed upload request.
        pub signed: Signed,
        /// The share the phone sealed to this unit.
        pub sealed_share: B64,
    }

    /// Facts in core's `release` statement: the open is in the ledger.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ReleaseFacts {
        /// Account.
        pub account: Id,
        /// Object.
        pub object: Id,
        /// The holder proof core checked.
        pub proof_hash: B64,
        /// The `object.opened` ledger entry, committed before this statement was signed.
        pub ledger_seq: i64,
        /// Its hash.
        pub ledger_hash: B64,
    }

    /// `POST /v1/shares/:id/release`, `POST /v1/shares/:id/delete`, `POST /v1/accounts/:id/close`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HolderAction {
        /// Core's statement for this action.
        pub statement: B64,
        /// The device's certificate.
        pub cert: DeviceCert,
        /// The holder's signed request.
        pub signed: Signed,
    }

    /// Answer to a release.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Released {
        /// The share, sealed to the phone's one-time key.
        pub sealed: B64,
    }

    /// Facts in core's `delete` / `close` statements.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ActionFacts {
        /// Account.
        pub account: Id,
        /// Object (delete only).
        #[serde(default)]
        pub object: Option<Id>,
        /// The holder proof core checked.
        pub proof_hash: B64,
    }

    /// Facts in core's `checkin` statement.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CheckinFacts {
        /// Account.
        pub account: Id,
        /// `status`, `arm`, `check` or `disarm`.
        pub action: String,
        /// The holder proof core checked (not for `status`).
        #[serde(default)]
        pub proof_hash: Option<B64>,
        /// Arm: every document the vault holds for the account (each must have its share here).
        #[serde(default)]
        pub objects: Vec<Id>,
    }

    /// `POST /v1/checkin`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Checkin {
        /// Core's statement.
        pub statement: B64,
        /// The device certificate (not for `status`).
        #[serde(default)]
        pub cert: Option<DeviceCert>,
        /// The holder's signed request (not for `status`).
        #[serde(default)]
        pub signed: Option<Signed>,
    }

    /// Where Check-in stands.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CheckinStatus {
        /// `off`, `armed`, `locked`, `erased`.
        pub state: String,
        /// Next deadline (ms).
        #[serde(default)]
        pub deadline: Option<i64>,
        /// When it erases (ms).
        #[serde(default)]
        pub erases_at: Option<i64>,
        /// When it erased (ms).
        #[serde(default)]
        pub erased_at: Option<i64>,
    }

    /// Facts in core's `duress` statement.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DuressFacts {
        /// Account.
        pub account: Id,
    }

    /// `POST /v1/duress`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Duress {
        /// Core's statement.
        pub statement: B64,
        /// The duress sign-in itself.
        pub proof: DuressProof,
    }

    /// Facts in core's `account` statement (status, erased list).
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AccountFacts {
        /// Account (absent for the erased list).
        #[serde(default)]
        pub account: Option<Id>,
    }

    /// One erased vault, as keys signs it.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ErasedFacts {
        /// Account.
        pub account: Id,
        /// When the fuse key was destroyed.
        pub erased_at: i64,
        /// Documents whose shares are still here (decoys, and anything sealed since).
        pub keep: Vec<Id>,
        /// How many shares went.
        pub count: i64,
    }

    /// `POST /v1/checkin/erased`: keys' statements, one per erased vault core hasn't cleaned.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ErasedList {
        /// `erased` statements from keys.
        pub erased: Vec<B64>,
    }

    /// `POST /v1/checkin/cleaned`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Cleaned {
        /// Core's `account` statement naming the account.
        pub statement: B64,
        /// The erase this cleans up.
        pub erased_at: i64,
    }

    /// The keys unit's public KEM key (phones seal uploads to it).
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct KemKey {
        /// Hybrid KEM public key.
        pub kem_pk: B64,
        /// The keys unit's statement over it.
        pub statement: B64,
    }
}

/// core ↔ anon (carried by front; anon never sees an account).
pub mod anon {
    use super::{B64, Deserialize, Serialize};

    /// Core's account-free statement that a live check approved exactly these values.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct LiveCheckFacts {
        /// What it approves (`post-tokens`).
        pub action: String,
        /// SHA3-512 of what was approved (the blinded values).
        pub body_hash: B64,
        /// The proof's short hash (single use at anon).
        pub proof_hash: B64,
    }

    /// Anon's statement that an access pass was spent (core needs it to register).
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SpentFacts {
        /// The spent id.
        pub spent: B64,
        /// The day.
        pub day: String,
    }

    /// A finalized blind token (pass or post token).
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Token {
        /// The signing key's id.
        pub kid: B64,
        /// The token message (32 random bytes the phone chose).
        pub msg: B64,
        /// RFC 9474 message randomizer.
        pub randomizer: B64,
        /// The signature.
        pub sig: B64,
    }
}

/// Header names.
pub mod headers {
    /// `Session <base64url token>`.
    pub const AUTHORIZATION: &str = "authorization";
    /// The HTP session transcript hash (front tells core which session a call came in).
    pub const TH: &str = "x-humid-th";
    /// A download ticket.
    pub const TICKET: &str = "x-humid-ticket";
}
