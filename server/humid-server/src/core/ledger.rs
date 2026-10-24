//! The ledger and the public log (SERVER.md §2.5, M3).
//!
//! * Each account's events form a hash chain: `hash_n = H(ledger-entry, [account, u64 n,
//!   hash_{n-1}, body])`, where `body` is the exact JSON bytes stored.
//! * Every entry is also a leaf of one public, append-only Merkle tree (RFC 6962 shape,
//!   SHA3-512 via the PQ2 labelled hash). Complete aligned subtrees are stored, so roots and
//!   proofs take O(log n) reads.
//! * Checkpoints `{size, root, at}` are dual-signed (ML-DSA-87 + SLH-DSA-SHA2-256s) by the HSM
//!   ledger key at a fixed cadence, never per request; cosigners add their signatures.
//!
//! Entries are written **only inside core's own transactions**, by the code that just did
//! the action and checked the holder's proof. No route accepts an event from outside (M3).
//! An entry that a live check vouches for carries that proof's hash; one that doesn't (a
//! Check-in timer, an erase reported by keys) says `"asserted": "server"`.

use deadpool_postgres::Transaction;
use serde::Serialize;

use crate::crypto::{self, label};
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef};
use crate::wire::{B64, Id};

/// The chain's start.
pub const GENESIS: [u8; 64] = [0u8; 64];

/// Every event type there is.
pub const EVENT_TYPES: &[&str] = &[
    "account.created",
    "account.closed",
    "device.added",
    "device.removed",
    "device.link_approved",
    "session.duress",
    "duress.cleared",
    "object.sealed",
    "object.opened",
    "object.updated",
    "object.deleted",
    "access.denied",
    "recovery.mode_set",
    "recovery.card_set",
    "recovery.card_removed",
    "recovery.witnesses_set",
    "recovery.witnesses_removed",
    "recovery.evidence",
    "recovery.requested",
    "recovery.helped",
    "recovery.cancelled",
    "recovery.completed",
    "checkin.armed",
    "checkin.disarmed",
    "checkin.erased",
];

/// Who vouches for an entry.
#[derive(Clone, Copy, Debug)]
pub enum Vouch<'a> {
    /// The holder's live check (its proof hash).
    Holder(&'a [u8; 32]),
    /// The server, on its own (timers, another unit's signed report).
    Server,
}

#[derive(Serialize)]
struct Body<'a, D: Serialize> {
    at: i64,
    #[serde(rename = "type")]
    kind: &'a str,
    detail: &'a D,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asserted: Option<&'static str>,
}

/// A written entry.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct Appended {
    /// Its number in the account's chain.
    pub seq: i64,
    /// Its hash.
    pub hash: B64,
    /// Its leaf index in the public log.
    pub leaf: i64,
}

/// `hash_n`.
///
/// # Errors
/// Never in practice.
pub fn entry_hash(account: &Id, seq: i64, prev: &[u8], body: &[u8]) -> Result<[u8; 64]> {
    crypto::hash(
        label::LEDGER_ENTRY,
        &[account.as_bytes(), &seq.to_be_bytes(), prev, body],
    )
}

/// A public-log leaf for an entry.
///
/// # Errors
/// Never in practice.
pub fn leaf_hash(account: &Id, seq: i64, hash: &[u8]) -> Result<[u8; 64]> {
    crypto::hash(
        label::TLOG_LEAF,
        &[account.as_bytes(), &seq.to_be_bytes(), hash],
    )
}

/// An interior node.
///
/// # Errors
/// Never in practice.
pub fn node_hash(l: &[u8], r: &[u8]) -> Result<[u8; 64]> {
    crypto::hash(label::TLOG_NODE, &[l, r])
}

/// The empty tree's root.
///
/// # Errors
/// Never in practice.
pub fn empty_root() -> Result<[u8; 64]> {
    crypto::hash(label::TLOG_NODE, &[])
}

/// Append an event to `account`'s chain and the public log, inside `tx`.
///
/// # Errors
/// An unknown type; database failure.
pub async fn append<D: Serialize>(
    tx: &Transaction<'_>,
    now: i64,
    account: &Id,
    kind: &str,
    detail: &D,
    vouch: Vouch<'_>,
) -> Result<Appended> {
    if !EVENT_TYPES.contains(&kind) {
        return Err(Error::internal(format!("unknown ledger event {kind}")));
    }
    let (proof, asserted) = match vouch {
        Vouch::Holder(h) => (Some(hex::encode(h)), None),
        Vouch::Server => (None, Some("server")),
    };
    let body = serde_json::to_vec(&Body {
        at: now,
        kind,
        detail,
        proof,
        asserted,
    })
    .map_err(|e| Error::internal(e.to_string()))?;
    // serialise appends on the log's one state row: leaf indices have no gaps
    let size: i64 = tx
        .query_one("SELECT size FROM tlog_state WHERE one FOR UPDATE", &[])
        .await?
        .get(0);
    let last = tx
        .query_opt(
            "SELECT seq, hash FROM ledger_entries WHERE account = $1 ORDER BY seq DESC LIMIT 1",
            &[&account.as_bytes()],
        )
        .await?;
    let (seq, prev) = match last {
        Some(r) => (r.get::<_, i64>(0) + 1, r.get::<_, Vec<u8>>(1)),
        None => (1, GENESIS.to_vec()),
    };
    let hash = entry_hash(account, seq, &prev, &body)?;
    tx.execute(
        "INSERT INTO ledger_entries (account, seq, at, type, body, prev, hash, leaf_index) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[&account.as_bytes(), &seq, &now, &kind, &body, &prev, &hash.as_slice(), &size],
    )
    .await?;
    add_leaf(tx, size, &leaf_hash(account, seq, &hash)?).await?;
    tx.execute("UPDATE tlog_state SET size = size + 1 WHERE one", &[])
        .await?;
    Ok(Appended {
        seq,
        hash: B64(hash.to_vec()),
        leaf: size,
    })
}

async fn add_leaf(tx: &Transaction<'_>, idx: i64, leaf: &[u8; 64]) -> Result<()> {
    let put = "INSERT INTO tlog_nodes (level, idx, hash) VALUES ($1, $2, $3)";
    tx.execute(put, &[&0i32, &idx, &leaf.as_slice()]).await?;
    let (mut level, mut i, mut h) = (0i32, idx, *leaf);
    while i % 2 == 1 {
        let left: Vec<u8> = tx
            .query_one(
                "SELECT hash FROM tlog_nodes WHERE level = $1 AND idx = $2",
                &[&level, &(i - 1)],
            )
            .await?
            .get(0);
        h = node_hash(&left, &h)?;
        level += 1;
        i /= 2;
        tx.execute(put, &[&level, &i, &h.as_slice()]).await?;
    }
    Ok(())
}

/* ------------------------------- proofs ------------------------------- */

/// A source of stored complete subtrees: `(level, idx)` → hash.
pub trait Nodes {
    /// The node.
    fn node(&mut self, level: u32, idx: u64) -> [u8; 64];
}

fn largest_pow2_below(n: u64) -> u64 {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle tree hash of leaves `[lo, hi)`, where `lo` is aligned so that every left split is a
/// stored complete subtree (true for every range RFC 6962 proofs ask for).
///
/// # Errors
/// Never in practice.
pub fn tree_hash(n: &mut dyn Nodes, lo: u64, hi: u64) -> Result<[u8; 64]> {
    let len = hi - lo;
    if len == 0 {
        return empty_root();
    }
    if len.is_power_of_two() && lo % len == 0 {
        return Ok(n.node(len.trailing_zeros(), lo / len));
    }
    let k = largest_pow2_below(len);
    let l = tree_hash(n, lo, lo + k)?;
    let r = tree_hash(n, lo + k, hi)?;
    node_hash(&l, &r)
}

/// RFC 6962 PATH(m, D[lo:hi]).
///
/// # Errors
/// Never in practice.
pub fn inclusion_proof(n: &mut dyn Nodes, m: u64, lo: u64, hi: u64) -> Result<Vec<[u8; 64]>> {
    let len = hi - lo;
    if len <= 1 {
        return Ok(vec![]);
    }
    let k = largest_pow2_below(len);
    if m < k {
        let mut p = inclusion_proof(n, m, lo, lo + k)?;
        p.push(tree_hash(n, lo + k, hi)?);
        Ok(p)
    } else {
        let mut p = inclusion_proof(n, m - k, lo + k, hi)?;
        p.push(tree_hash(n, lo, lo + k)?);
        Ok(p)
    }
}

/// RFC 6962 PROOF(m, D[0:size]).
///
/// # Errors
/// Never in practice.
pub fn consistency_proof(n: &mut dyn Nodes, m: u64, size: u64) -> Result<Vec<[u8; 64]>> {
    fn sub(n: &mut dyn Nodes, m: u64, lo: u64, hi: u64, complete: bool) -> Result<Vec<[u8; 64]>> {
        let len = hi - lo;
        if m == len {
            return if complete {
                Ok(vec![])
            } else {
                Ok(vec![tree_hash(n, lo, hi)?])
            };
        }
        let k = largest_pow2_below(len);
        if m <= k {
            let mut p = sub(n, m, lo, lo + k, complete)?;
            p.push(tree_hash(n, lo + k, hi)?);
            Ok(p)
        } else {
            let mut p = sub(n, m - k, lo + k, hi, false)?;
            p.push(tree_hash(n, lo, lo + k)?);
            Ok(p)
        }
    }
    if m == 0 || m == size {
        return Ok(vec![]);
    }
    sub(n, m, 0, size, true)
}

/// Verify an inclusion proof (what the phone does).
///
/// # Errors
/// Never in practice.
pub fn verify_inclusion(
    leaf: &[u8; 64],
    index: u64,
    size: u64,
    proof: &[[u8; 64]],
    root: &[u8; 64],
) -> Result<bool> {
    if index >= size {
        return Ok(false);
    }
    let (mut fn_, mut sn, mut r) = (index, size - 1, *leaf);
    for p in proof {
        if sn == 0 {
            return Ok(false);
        }
        if fn_ % 2 == 1 || fn_ == sn {
            r = node_hash(p, &r)?;
            if fn_ % 2 == 0 {
                while fn_ % 2 == 0 && fn_ != 0 {
                    fn_ /= 2;
                    sn /= 2;
                }
            }
        } else {
            r = node_hash(&r, p)?;
        }
        fn_ /= 2;
        sn /= 2;
    }
    Ok(sn == 0 && crypto::ct_eq(&r, root))
}

/// Records which nodes a computation asks for (pass 1), then serves them (pass 2). The
/// request pattern depends only on sizes and indices, never on hashes, so two passes work
/// and each proof costs one batched query.
struct Recorder {
    want: Vec<(u32, u64)>,
}
impl Nodes for Recorder {
    fn node(&mut self, level: u32, idx: u64) -> [u8; 64] {
        self.want.push((level, idx));
        [0u8; 64]
    }
}
struct Served(std::collections::HashMap<(u32, u64), [u8; 64]>);
impl Nodes for Served {
    fn node(&mut self, level: u32, idx: u64) -> [u8; 64] {
        self.0.get(&(level, idx)).copied().unwrap_or([0u8; 64])
    }
}

/// Run `f` over the stored tree.
///
/// # Errors
/// Database failure.
pub async fn with_nodes<T>(
    c: &impl deadpool_postgres::GenericClient,
    f: impl Fn(&mut dyn Nodes) -> Result<T>,
) -> Result<T> {
    let mut rec = Recorder { want: vec![] };
    f(&mut rec)?;
    let levels: Vec<i32> = rec
        .want
        .iter()
        .map(|(l, _)| i32::try_from(*l).unwrap_or(0))
        .collect();
    let idxs: Vec<i64> = rec
        .want
        .iter()
        .map(|(_, i)| i64::try_from(*i).unwrap_or(0))
        .collect();
    let rows = c
        .query(
            "SELECT n.level, n.idx, n.hash FROM tlog_nodes n JOIN unnest($1::int[], $2::bigint[]) AS w(level, idx) ON n.level = w.level AND n.idx = w.idx",
            &[&levels, &idxs],
        )
        .await?;
    let mut m = std::collections::HashMap::new();
    for r in rows {
        let h: Vec<u8> = r.get(2);
        let mut a = [0u8; 64];
        if h.len() == 64 {
            a.copy_from_slice(&h);
        }
        m.insert(
            (
                u32::try_from(r.get::<_, i32>(0)).unwrap_or(0),
                u64::try_from(r.get::<_, i64>(1)).unwrap_or(0),
            ),
            a,
        );
    }
    if m.len()
        != rec
            .want
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    {
        return Err(Error::internal("public log is missing a node"));
    }
    f(&mut Served(m))
}

/* ----------------------------- checkpoints ----------------------------- */

/// What the ledger key signs.
///
/// # Errors
/// Never in practice.
pub fn checkpoint_message(size: i64, root: &[u8], at: i64) -> Result<Vec<u8>> {
    crypto::lp(&[&size.to_be_bytes(), root, &at.to_be_bytes()])
}

/// What a cosigner signs.
///
/// # Errors
/// Never in practice.
pub fn cosign_message(name: &str, size: i64, root: &[u8], at: i64) -> Result<Vec<u8>> {
    crypto::lp(&[
        name.as_bytes(),
        &size.to_be_bytes(),
        root,
        &at.to_be_bytes(),
    ])
}

/// A signed checkpoint.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Leaves.
    pub size: i64,
    /// Root.
    pub root: B64,
    /// When signed.
    pub at: i64,
    /// Dual signature.
    pub sig: B64,
    /// Cosignatures `{name, sig}`.
    pub cosigs: Vec<Cosig>,
}

/// A cosignature.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct Cosig {
    /// Cosigner.
    pub name: String,
    /// Signature.
    pub sig: B64,
}

/// Sign a checkpoint for the tree as it is, unless the latest already covers it. Called by
/// the checkpoint job (fixed cadence) and by tests; SLH-DSA makes it take about half a second.
///
/// # Errors
/// Database or HSM failure.
pub async fn cut(db: &crate::db::Db, hsm: &dyn Hsm, now: i64) -> Result<Option<Checkpoint>> {
    let c = db.conn().await?;
    let size: i64 = c
        .query_one("SELECT size FROM tlog_state", &[])
        .await?
        .get(0);
    if c.query_opt("SELECT 1 FROM tlog_checkpoints WHERE size = $1", &[&size])
        .await?
        .is_some()
    {
        return latest(&c).await;
    }
    let s = u64::try_from(size).unwrap_or(0);
    let root = with_nodes(&c, |n| tree_hash(n, 0, s)).await?;
    let sig = hsm.dual_sign(
        KeyRef::Ledger,
        label::TLOG_CHECKPOINT,
        &checkpoint_message(size, &root, now)?,
    )?;
    c.execute("INSERT INTO tlog_checkpoints (size, root, at, sig) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", &[&size, &root.as_slice(), &now, &sig])
        .await?;
    latest(&c).await
}

/// The latest checkpoint and its cosignatures.
///
/// # Errors
/// Database failure.
pub async fn latest(c: &impl deadpool_postgres::GenericClient) -> Result<Option<Checkpoint>> {
    let Some(r) = c
        .query_opt(
            "SELECT size, root, at, sig FROM tlog_checkpoints ORDER BY size DESC LIMIT 1",
            &[],
        )
        .await?
    else {
        return Ok(None);
    };
    let size: i64 = r.get(0);
    let cos = c
        .query(
            "SELECT name, sig FROM tlog_cosigs WHERE size = $1 ORDER BY name",
            &[&size],
        )
        .await?;
    Ok(Some(Checkpoint {
        size,
        root: B64(r.get(1)),
        at: r.get(2),
        sig: B64(r.get(3)),
        cosigs: cos
            .iter()
            .map(|c| Cosig {
                name: c.get(0),
                sig: B64(c.get(1)),
            })
            .collect(),
    }))
}

/// Run `cut` every `every_ms` (the fixed cadence; 60 s in production).
pub fn spawn_checkpoints(
    db: crate::db::Db,
    hsm: std::sync::Arc<dyn Hsm>,
    clock: crate::unit::Clock,
    every_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_millis(every_ms));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            if let Err(e) = cut(&db, hsm.as_ref(), clock.now()).await {
                tracing::warn!(error = %e, "checkpoint failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory tree built the same way `add_leaf` builds the stored one.
    struct Mem(std::collections::HashMap<(u32, u64), [u8; 64]>);
    impl Mem {
        fn build(leaves: &[[u8; 64]]) -> Self {
            let mut m = std::collections::HashMap::new();
            for (idx, leaf) in leaves.iter().enumerate() {
                let mut i = idx as u64;
                let mut level = 0u32;
                let mut h = *leaf;
                m.insert((0, i), h);
                while i % 2 == 1 {
                    h = node_hash(&m[&(level, i - 1)], &h).unwrap();
                    level += 1;
                    i /= 2;
                    m.insert((level, i), h);
                }
            }
            Self(m)
        }
    }
    impl Nodes for Mem {
        fn node(&mut self, level: u32, idx: u64) -> [u8; 64] {
            self.0[&(level, idx)]
        }
    }

    fn reference_root(leaves: &[[u8; 64]]) -> [u8; 64] {
        match leaves.len() {
            0 => empty_root().unwrap(),
            1 => leaves[0],
            n => {
                let k = largest_pow2_below(n as u64) as usize;
                node_hash(&reference_root(&leaves[..k]), &reference_root(&leaves[k..])).unwrap()
            }
        }
    }

    #[test]
    fn stored_subtrees_give_the_rfc6962_root_and_valid_proofs() {
        let leaves: Vec<[u8; 64]> = (0..37u8).map(|i| crypto::sha3_512(&[i])).collect();
        for size in 0..=leaves.len() {
            let mut t = Mem::build(&leaves[..size]);
            let root = tree_hash(&mut t, 0, size as u64).unwrap();
            assert_eq!(root, reference_root(&leaves[..size]), "size {size}");
            for m in 0..size {
                let p = inclusion_proof(&mut t, m as u64, 0, size as u64).unwrap();
                assert!(
                    verify_inclusion(&leaves[m], m as u64, size as u64, &p, &root).unwrap(),
                    "leaf {m} of {size}"
                );
                assert!(
                    !verify_inclusion(&leaves[(m + 1) % size], m as u64, size as u64, &p, &root)
                        .unwrap()
                        || size == 1
                );
            }
        }
    }

    #[test]
    fn consistency_proofs_have_the_rfc6962_shape() {
        let leaves: Vec<[u8; 64]> = (0..20u8).map(|i| crypto::sha3_512(&[i])).collect();
        let mut t = Mem::build(&leaves);
        assert!(consistency_proof(&mut t, 0, 20).unwrap().is_empty());
        assert!(consistency_proof(&mut t, 20, 20).unwrap().is_empty());
        assert!(!consistency_proof(&mut t, 7, 20).unwrap().is_empty());
        // m a power of two: the old root itself isn't in the proof
        let p4 = consistency_proof(&mut t, 4, 8).unwrap();
        assert_eq!(p4.len(), 1);
    }
}
