//! Documents, `/sync`, and the ledger / public-log reads.
//!
//! * **Upload (H2)**: the phone seals the document key to the keys unit. Core stores the
//!   envelope, logs `object.sealed`, and has keys store the sealed share; it commits only if
//!   keys stored it. Core never sees the share in the clear, and neither does front.
//! * **Open (log before release)**: core checks the live proof, appends `object.opened` and
//!   **commits** (with synchronous replication in production) before it asks keys for the
//!   share. If keys then refuses, an `access.denied` entry follows the open.
//! * Envelopes are served in 1 MiB chunks under a 60 s download ticket that each chunk
//!   renews, so a dropped connection resumes without a new live check.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use super::auth::{Approved, devices_of};
use super::ledger::{self, Vouch};
use super::{Core, Reply, SMALL, ok, path_id, read};
use crate::api::{app, headers as h, keys as keys_api};
use crate::crypto;
use crate::error::{Error, Result};
use crate::proofs::Signed;
use crate::unit::ms;
use crate::wire::{self, B64, Id};

/// Bytes per chunk.
pub const CHUNK: i64 = 1 << 20;
/// A download ticket lasts this long after its last use.
pub const TICKET_MS: i64 = 60 * ms::SECOND;

/// `POST /v1/objects`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadReq {
    /// The holder's signed upload (`app::Upload`).
    pub signed: Signed,
    /// The envelope (ciphertext).
    pub envelope: B64,
    /// The document key, sealed by the phone to the keys unit.
    pub sealed_share: B64,
}

/// Upload a document.
pub async fn upload(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    if s.duress {
        return Err(Error::busy()); // a duress session writes nothing real
    }
    let max = usize::try_from(core.policy.policy.limits.max_object_bytes).unwrap_or(usize::MAX);
    let r: UploadReq = read(body, max / 3 * 4 + (64 << 10)).await?;
    let u: app::Upload = wire::parse(&r.signed.body)?;
    if r.envelope.is_empty() || r.envelope.len() > max {
        return Err(Error::TooLarge(
            "too_large",
            "That document is too large.".into(),
        ));
    }
    let env_hash = crypto::sha3_512(&r.envelope);
    if !crypto::ct_eq(&env_hash, &u.envelope_hash)
        || !crypto::ct_eq(&crypto::sha3_512(&r.sealed_share), &u.sealed_share_hash)
    {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "The live check approved a different document.",
        ));
    }
    if r.sealed_share.len() != crypto::SEALED_SHARE_LEN {
        return Err(Error::bad(
            "bad_share",
            "A sealed document key has the wrong size.",
        ));
    }
    if u.index.len() < 28 || u.index.len() > 4096 {
        return Err(Error::bad(
            "bad_index",
            "The index entry has an invalid size.",
        ));
    }
    if u.manifest_hash.len() != 64 {
        return Err(Error::bad("bad_manifest", "A manifest hash is 64 bytes."));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, cert) = core
        .step_up(&tx, &s, &r.signed, "POST", "/v1/objects")
        .await?;
    let a = s.account.as_bytes();
    let used: i64 = tx
        .query_one(
            "SELECT COALESCE(sum(size), 0)::bigint FROM objects WHERE account = $1",
            &[&a],
        )
        .await?
        .get(0);
    let size = i64::try_from(r.envelope.len()).unwrap_or(i64::MAX);
    if u64::try_from(used + size).unwrap_or(u64::MAX) > core.policy.policy.limits.vault_quota_bytes
    {
        return Err(Error::TooLarge(
            "quota_exceeded",
            "Your vault is full.".into(),
        ));
    }
    let rev: i64 = tx
        .query_one(
            "UPDATE accounts SET object_rev = object_rev + 1 WHERE id = $1 RETURNING object_rev",
            &[&a],
        )
        .await?
        .get(0);
    let now = core.now();
    let n = tx
        .execute(
            "INSERT INTO objects (id, account, envelope, envelope_hash, manifest_hash, size, idx, rev, sealed_by, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) ON CONFLICT DO NOTHING",
            &[&u.object.as_bytes(), &a, &r.envelope.0, &env_hash.as_slice(), &u.manifest_hash.0, &size, &u.index.0, &rev, &s.device.as_bytes(), &now],
        )
        .await?;
    if n != 1 {
        return Err(Error::conflict(
            "id_taken",
            "That document id is already in use.",
        ));
    }
    let e = ledger::append(
        &tx,
        now,
        &s.account,
        "object.sealed",
        &serde_json::json!({ "object": u.object, "size": size }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    let facts = keys_api::UploadFacts {
        account: s.account,
        object: u.object,
        envelope_hash: B64(env_hash.to_vec()),
        manifest_hash: u.manifest_hash.clone(),
        proof_hash: B64(checked.proof_hash.to_vec()),
        ledger_seq: e.seq,
    };
    let store = keys_api::Store {
        statement: core.statement("upload", &facts)?,
        cert,
        signed: r.signed,
        sealed_share: r.sealed_share,
    };
    // keys checks the holder's proof itself; if it refuses, this transaction rolls back
    let _: serde_json::Value = core.keys.post("/v1/shares", &[], &store).await?;
    tx.commit().await?;
    super::created(&serde_json::json!({ "object": u.object, "rev": rev, "ledger": e }))
}

/// What an open returns.
#[derive(Serialize, Deserialize, Debug)]
pub struct Opened {
    /// The share, sealed to the phone's one-time key.
    pub sealed_share: B64,
    /// The download ticket.
    pub ticket: B64,
    /// Envelope size.
    pub size: i64,
    /// Chunks.
    pub chunks: i64,
    /// The ledger entry for this open.
    pub ledger: ledger::Appended,
}

/// `POST /v1/objects/:id/open`.
pub async fn open(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    let object = path_id(&id)?;
    let r: Approved = read(body, SMALL).await?;
    let o: app::Open = wire::parse(&r.signed.body)?;
    if o.object != object {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different document.",
        ));
    }
    // humid-core's share request names the account, document, manifest and one-time key
    let req = crypto::ShareRequest::parse(&o.share_request)?;
    if req.account != s.account.0 || req.doc != object.0 {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That share request is for a different document.",
        ));
    }
    let path = format!("/v1/objects/{object}/open");
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, cert) = core.step_up(&tx, &s, &r.signed, "POST", &path).await?;
    let row = tx
        .query_opt(
            "SELECT size, manifest_hash FROM objects WHERE id = $1 AND account = $2",
            &[&object.as_bytes(), &s.account.as_bytes()],
        )
        .await?
        .ok_or_else(|| Error::not_found("not_found", "No such item in your vault."))?;
    let size: i64 = row.get(0);
    if !crypto::ct_eq(&row.get::<_, Vec<u8>>(1), &req.manifest_hash) {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That share request is for another version of this document.",
        ));
    }
    let now = core.now();
    let entry = ledger::append(
        &tx,
        now,
        &s.account,
        "object.opened",
        &serde_json::json!({ "object": object }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    let ticket = crypto::random::<32>()?;
    tx.execute(
        "INSERT INTO download_tickets (ticket, session, object, expires_at) VALUES ($1, $2, $3, $4)",
        &[&ticket.as_slice(), &s.token_hash, &object.as_bytes(), &(now + TICKET_MS)],
    )
    .await?;
    // logged before release: the entry is committed before keys is asked for anything
    tx.commit().await?;
    let facts = keys_api::ReleaseFacts {
        account: s.account,
        object,
        proof_hash: B64(checked.proof_hash.to_vec()),
        ledger_seq: entry.seq,
        ledger_hash: entry.hash.clone(),
    };
    let req = keys_api::HolderAction {
        statement: core.statement("release", &facts)?,
        cert,
        signed: r.signed,
    };
    match core
        .keys
        .post::<_, keys_api::Released>(&format!("/v1/shares/{object}/release"), &[], &req)
        .await
    {
        Ok(rel) => ok(&Opened {
            sealed_share: rel.sealed,
            ticket: B64(ticket.to_vec()),
            size,
            chunks: (size + CHUNK - 1) / CHUNK,
            ledger: entry,
        }),
        Err(e) => {
            let mut c = core.db.conn().await?;
            let tx = c.transaction().await?;
            tx.execute(
                "DELETE FROM download_tickets WHERE ticket = $1",
                &[&ticket.as_slice()],
            )
            .await?;
            ledger::append(
                &tx,
                core.now(),
                &s.account,
                "access.denied",
                &serde_json::json!({ "object": object, "reason": e.code_str() }),
                Vouch::Holder(&checked.proof_hash),
            )
            .await?;
            tx.commit().await?;
            Err(e)
        }
    }
}

/// `GET /v1/objects/:id/chunks/:n` with `x-humid-ticket`.
pub async fn chunk(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path((id, n)): Path<(String, i64)>,
) -> Reply {
    let s = core.session(&headers).await?;
    let object = path_id(&id)?;
    let ticket = headers
        .get(h::TICKET)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::forbidden("no_ticket", "Open the document first."))?;
    let ticket = B64::decode(ticket)?;
    let now = core.now();
    let c = core.db.conn().await?;
    let t = c
        .execute(
            "UPDATE download_tickets SET expires_at = $4 WHERE ticket = $1 AND session = $2 AND object = $3 AND expires_at >= $5",
            &[&ticket, &s.token_hash, &object.as_bytes(), &(now + TICKET_MS), &now],
        )
        .await?;
    if t != 1 {
        return Err(Error::forbidden(
            "ticket_expired",
            "This download needs a new live check.",
        ));
    }
    if n < 0 {
        return Err(Error::bad("bad_chunk", "No such chunk."));
    }
    let row = c
        .query_one(
            "SELECT substring(envelope FROM $3::int FOR $4::int), size FROM objects WHERE id = $1 AND account = $2",
            &[&object.as_bytes(), &s.account.as_bytes(), &i32::try_from(n * CHUNK + 1).map_err(|_| Error::bad("bad_chunk", "No such chunk."))?, &i32::try_from(CHUNK).unwrap_or(i32::MAX)],
        )
        .await?;
    let bytes: Vec<u8> = row.get(0);
    if bytes.is_empty() {
        return Err(Error::bad("bad_chunk", "No such chunk."));
    }
    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        bytes,
    )
        .into_response())
}

/// `PATCH /v1/objects/:id`: replace the index entry (a live check, L3).
pub async fn update(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    let object = path_id(&id)?;
    let r: Approved = read(body, SMALL).await?;
    let u: app::ObjectChange = wire::parse(&r.signed.body)?;
    let idx = u
        .index
        .ok_or_else(|| Error::bad("missing_index", "Send the new index entry."))?;
    if u.object != object || idx.len() < 28 || idx.len() > 4096 {
        return Err(Error::bad("bad_index", "Bad index entry."));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(
            &tx,
            &s,
            &r.signed,
            "PATCH",
            &format!("/v1/objects/{object}"),
        )
        .await?;
    let rev: i64 = tx
        .query_one(
            "UPDATE accounts SET object_rev = object_rev + 1 WHERE id = $1 RETURNING object_rev",
            &[&s.account.as_bytes()],
        )
        .await?
        .get(0);
    let n = tx
        .execute(
            "UPDATE objects SET idx = $3, rev = $4, updated_at = $5 WHERE id = $1 AND account = $2",
            &[
                &object.as_bytes(),
                &s.account.as_bytes(),
                &idx.0,
                &rev,
                &core.now(),
            ],
        )
        .await?;
    if n != 1 {
        return Err(Error::not_found("not_found", "No such item in your vault."));
    }
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "object.updated",
        &serde_json::json!({ "object": object }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "object": object, "rev": rev }))
}

/// `DELETE /v1/objects/:id`: keys destroys the share before core commits.
pub async fn remove(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    // a duress session changes nothing real (whoever forced the unlock can't destroy documents)
    Core::not_locked(&s)?;
    let object = path_id(&id)?;
    let r: Approved = read(body, SMALL).await?;
    let u: app::ObjectChange = wire::parse(&r.signed.body)?;
    if u.object != object {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different document.",
        ));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, cert) = core
        .step_up(
            &tx,
            &s,
            &r.signed,
            "DELETE",
            &format!("/v1/objects/{object}"),
        )
        .await?;
    let a = s.account.as_bytes();
    let n = tx
        .execute(
            "DELETE FROM objects WHERE id = $1 AND account = $2",
            &[&object.as_bytes(), &a],
        )
        .await?;
    if n != 1 {
        return Err(Error::not_found("not_found", "No such item in your vault."));
    }
    let rev: i64 = tx
        .query_one(
            "UPDATE accounts SET object_rev = object_rev + 1 WHERE id = $1 RETURNING object_rev",
            &[&a],
        )
        .await?
        .get(0);
    tx.execute("INSERT INTO object_tombstones (id, account, rev, deleted_at) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET rev = $3", &[&object.as_bytes(), &a, &rev, &core.now()])
        .await?;
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "object.deleted",
        &serde_json::json!({ "object": object }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    let st = core.statement(
        "delete",
        &keys_api::ActionFacts {
            account: s.account,
            object: Some(object),
            proof_hash: B64(checked.proof_hash.to_vec()),
        },
    )?;
    // keys destroys the share before core commits: no envelope without its share, ever
    let _: serde_json::Value = core
        .keys
        .post(
            &format!("/v1/shares/{object}/delete"),
            &[],
            &keys_api::HolderAction {
                statement: st,
                cert,
                signed: r.signed,
            },
        )
        .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "deleted": object, "rev": rev }))
}

/// `POST /v1/sync`: what changed since the phone's versions, in one round trip.
#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SyncReq {
    /// The phone's object revision.
    #[serde(default)]
    pub object_rev: i64,
    /// The last ledger entry it has.
    #[serde(default)]
    pub ledger_seq: i64,
    /// Its devices revision.
    #[serde(default)]
    pub devices_rev: i64,
}

/// One changed item (index only; the envelope comes with an open).
#[derive(Serialize, Deserialize, Debug)]
pub struct Item {
    /// Id.
    pub id: Id,
    /// Encrypted index entry.
    pub index: B64,
    /// Envelope size.
    pub size: i64,
    /// Its revision.
    pub rev: i64,
}

/// The `/sync` answer.
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncReply {
    /// The current object revision.
    pub object_rev: i64,
    /// Items changed since.
    pub changed: Vec<Item>,
    /// Items deleted since.
    pub deleted: Vec<Id>,
    /// The phone's revision is older than the tombstones kept: list everything again.
    pub resync: bool,
    /// Ledger entries since.
    pub ledger: Vec<Entry>,
    /// The current devices revision.
    pub devices_rev: i64,
    /// Devices, when they changed.
    pub devices: Option<Vec<super::auth::DeviceView>>,
    /// The step-up nonce pool.
    pub nonces: Vec<B64>,
}

/// A ledger entry as served.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    /// Number.
    pub seq: i64,
    /// The exact body bytes hashed (absent once redacted).
    pub body: Option<B64>,
    /// Previous hash.
    pub prev: B64,
    /// This hash.
    pub hash: B64,
    /// Public-log leaf.
    pub leaf: i64,
}

async fn entries_since(
    c: &impl deadpool_postgres::GenericClient,
    account: &Id,
    since: i64,
    limit: i64,
) -> Result<Vec<Entry>> {
    let rows = c
        .query(
            "SELECT seq, body, prev, hash, leaf_index FROM ledger_entries WHERE account = $1 AND seq > $2 ORDER BY seq LIMIT $3",
            &[&account.as_bytes(), &since, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Entry {
            seq: r.get(0),
            body: r.get::<_, Option<Vec<u8>>>(1).map(B64),
            prev: B64(r.get(2)),
            hash: B64(r.get(3)),
            leaf: r.get(4),
        })
        .collect())
}

/// Sync.
pub async fn sync(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    let r: SyncReq = read(body, SMALL).await?;
    let c = core.db.conn().await?;
    let a = s.account.as_bytes();
    let acct = c
        .query_one(
            "SELECT object_rev, devices_rev FROM accounts WHERE id = $1",
            &[&a],
        )
        .await?;
    let (object_rev, devices_rev): (i64, i64) = (acct.get(0), acct.get(1));
    let oldest_tomb: Option<i64> = c
        .query_one(
            "SELECT min(rev) FROM object_tombstones WHERE account = $1",
            &[&a],
        )
        .await?
        .get(0);
    let resync = r.object_rev > 0
        && oldest_tomb.is_some_and(|t| r.object_rev < t - 1)
        && r.object_rev < object_rev;
    let since = if resync { 0 } else { r.object_rev };
    let changed = c
        .query("SELECT id, idx, size, rev FROM objects WHERE account = $1 AND rev > $2 ORDER BY rev LIMIT 5000", &[&a, &since])
        .await?
        .iter()
        .map(|row| Ok(Item { id: Id::from_slice(&row.get::<_, Vec<u8>>(0))?, index: B64(row.get(1)), size: row.get(2), rev: row.get(3) }))
        .collect::<Result<Vec<_>>>()?;
    let deleted = c
        .query(
            "SELECT id FROM object_tombstones WHERE account = $1 AND rev > $2",
            &[&a, &since],
        )
        .await?
        .iter()
        .map(|row| Id::from_slice(&row.get::<_, Vec<u8>>(0)))
        .collect::<Result<Vec<_>>>()?;
    let devices = if r.devices_rev == devices_rev {
        None
    } else {
        Some(devices_of(&c, &s.account).await?)
    };
    ok(&SyncReply {
        object_rev,
        changed,
        deleted,
        resync,
        ledger: entries_since(&c, &s.account, r.ledger_seq, 500).await?,
        devices_rev,
        devices,
        nonces: core.nonces(&c, &s.token_hash, &s.device).await?,
    })
}

/// `GET /v1/keys-kem`: the keys unit's KEM key with its statement (phones seal uploads to it).
pub async fn keys_kem(State(core): State<Arc<Core>>) -> Reply {
    let k: keys_api::KemKey = core.keys.get("/v1/kem-key", &[]).await?;
    ok(&k)
}

/// `?since=&limit=`.
#[derive(Deserialize)]
pub struct Since {
    /// After this seq.
    #[serde(default)]
    pub since: i64,
    /// At most.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /v1/ledger/events`.
pub async fn ledger_events(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Query(q): Query<Since>,
) -> Reply {
    let s = core.session(&headers).await?;
    let c = core.db.conn().await?;
    ok(
        &serde_json::json!({ "account": s.account, "entries": entries_since(&c, &s.account, q.since, q.limit.unwrap_or(300).clamp(1, 1000)).await? }),
    )
}

/// `?seq=`.
#[derive(Deserialize)]
pub struct Seq {
    /// Entry number (default: latest).
    #[serde(default)]
    pub seq: Option<i64>,
}

/// `GET /v1/ledger/inclusion`: where an entry sits in the latest checkpoint.
pub async fn ledger_inclusion(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Query(q): Query<Seq>,
) -> Reply {
    let s = core.session(&headers).await?;
    let c = core.db.conn().await?;
    let row = match q.seq {
        Some(seq) => c.query_opt("SELECT seq, hash, leaf_index FROM ledger_entries WHERE account = $1 AND seq = $2", &[&s.account.as_bytes(), &seq]).await?,
        None => c.query_opt("SELECT seq, hash, leaf_index FROM ledger_entries WHERE account = $1 ORDER BY seq DESC LIMIT 1", &[&s.account.as_bytes()]).await?,
    }
    .ok_or_else(|| Error::not_found("not_in_log", "No such entry."))?;
    let leaf: i64 = row.get(2);
    let cp = ledger::latest(&c)
        .await?
        .filter(|cp| cp.size > leaf)
        .ok_or_else(|| {
            Error::unavailable(
                "not_in_checkpoint_yet",
                "That entry isn't in a signed checkpoint yet. Try again in a minute.",
            )
        })?;
    let (l, size) = (
        u64::try_from(leaf).unwrap_or(0),
        u64::try_from(cp.size).unwrap_or(0),
    );
    let proof = ledger::with_nodes(&c, |n| ledger::inclusion_proof(n, l, 0, size)).await?;
    ok(&serde_json::json!({
        "seq": row.get::<_, i64>(0), "hash": B64(row.get(1)), "leaf": leaf,
        "checkpoint": cp, "proof": proof.iter().map(|p| B64(p.to_vec())).collect::<Vec<_>>(),
    }))
}

/// `GET /tlog/checkpoint` (public).
pub async fn tlog_checkpoint(State(core): State<Arc<Core>>) -> Reply {
    let c = core.db.conn().await?;
    ok(
        &serde_json::json!({ "checkpoint": ledger::latest(&c).await?, "ledger_key": core.policy.policy.unit_keys.ledger }),
    )
}

/// `?from=&to=`.
#[derive(Deserialize)]
pub struct Range {
    /// Old size.
    pub from: i64,
    /// New size.
    pub to: i64,
}

/// `GET /tlog/consistency` (public).
pub async fn tlog_consistency(State(core): State<Arc<Core>>, Query(q): Query<Range>) -> Reply {
    let c = core.db.conn().await?;
    let size: i64 = c
        .query_one("SELECT size FROM tlog_state", &[])
        .await?
        .get(0);
    if q.from < 0 || q.to < q.from || q.to > size {
        return Err(Error::bad("bad_size", "Tree size out of range."));
    }
    let (m, n) = (
        u64::try_from(q.from).unwrap_or(0),
        u64::try_from(q.to).unwrap_or(0),
    );
    let proof = ledger::with_nodes(&c, |t| ledger::consistency_proof(t, m, n)).await?;
    ok(
        &serde_json::json!({ "from": q.from, "to": q.to, "proof": proof.iter().map(|p| B64(p.to_vec())).collect::<Vec<_>>() }),
    )
}

/// `POST /tlog/cosign`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CosignReq {
    /// Cosigner name (must be in the policy).
    pub name: String,
    /// Checkpoint size.
    pub size: i64,
    /// ML-DSA-87 signature over `cosign_message`.
    pub sig: B64,
}

/// A cosigner's signature over a checkpoint, checked against the policy's key for that name.
pub async fn tlog_cosign(State(core): State<Arc<Core>>, body: Body) -> Reply {
    let r: CosignReq = read(body, SMALL).await?;
    let cs = core
        .policy
        .policy
        .cosigners
        .iter()
        .find(|c| c.name == r.name)
        .ok_or_else(|| {
            Error::forbidden(
                "unknown_cosigner",
                "That cosigner isn't in this server's policy.",
            )
        })?;
    let pk = crypto::MlDsaPublic::from_bytes(&cs.key)?;
    let c = core.db.conn().await?;
    let cp = c
        .query_opt(
            "SELECT root, at FROM tlog_checkpoints WHERE size = $1",
            &[&r.size],
        )
        .await?
        .ok_or_else(|| Error::not_found("unknown_checkpoint", "No such checkpoint."))?;
    let root: Vec<u8> = cp.get(0);
    if !pk.verifies(
        crypto::label::TLOG_COSIGN,
        &ledger::cosign_message(&r.name, r.size, &root, cp.get(1))?,
        &r.sig,
    ) {
        return Err(Error::unauth(
            "bad_cosignature",
            "That cosignature doesn't verify.",
        ));
    }
    c.execute("INSERT INTO tlog_cosigs (size, name, sig, at) VALUES ($1, $2, $3, $4) ON CONFLICT (size, name) DO UPDATE SET sig = $3, at = $4", &[&r.size, &r.name, &r.sig.0, &core.now()])
        .await?;
    ok(&serde_json::json!({ "accepted": true }))
}
