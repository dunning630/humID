//! The relay (H-3, M-5, M-10; SERVER.md §10).
//!
//! * `deposit`: one wire object of a fixed size class into a 128-bit mailbox, paid with one
//!   post token (no IP quotas). The sender stores `H(ack token)` beside it; only the recipient
//!   can derive the ack token (from the box key), and the sender may keep a retract token.
//! * `tick`: a fixed number of prefix slots, each with a cursor; the reply is always padded to
//!   the same size. It **never deletes**. A tick is also the cover traffic: a phone sends one
//!   per interval whether or not it expects anything.
//! * `ack`: the recipient shows ack tokens for what it has stored; only then is it deleted.
//!   Unacknowledged objects stay until their TTL, so a lost reply or a lock mid-fetch loses
//!   nothing.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use super::{Anon, Reply, ok, read};
use crate::api::anon as a;
use crate::crypto::{self, label};
use crate::error::{Error, Result};
use crate::unit::ms;
use crate::wire::B64;

/// Wire size classes (bytes), as 4.x's @humid/msg.
pub const BUCKETS: [usize; 11] = [
    4096, 8192, 16384, 32768, 65536, 131_072, 262_144, 524_288, 1_048_576, 2_097_152, 4_194_304,
];

/// The prefix of a 16-byte box id, `bits` long.
#[must_use]
pub fn prefix_of(boxid: &[u8], bits: u32) -> i32 {
    let v = u32::from_be_bytes([boxid[0], boxid[1], boxid[2], boxid[3]]);
    i32::try_from(v >> (32 - bits)).unwrap_or(i32::MAX)
}

/// `H(relay-token, token)`.
///
/// # Errors
/// Never in practice.
pub fn token_hash(kind: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    Ok(crypto::hash(label::RELAY_TOKEN, &[kind, token])?.to_vec())
}

/// `POST /v1/relay/deposit`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deposit {
    /// A post token (spent).
    pub token: a::Token,
    /// The 16-byte mailbox id.
    pub r#box: B64,
    /// H(ack token), 64 bytes.
    pub ack_hash: B64,
    /// H(retract token), optional.
    #[serde(default)]
    pub retract_hash: Option<B64>,
    /// The wire object.
    pub wire: B64,
}

/// Deposit one object.
pub async fn deposit(State(an): State<Arc<Anon>>, body: Body) -> Reply {
    let r: Deposit = read(body, BUCKETS[10] / 3 * 4 + (16 << 10)).await?;
    let m = &an.policy.policy.messaging;
    if !m.enabled {
        return Err(Error::forbidden(
            "messaging_off",
            "This server doesn't run a relay.",
        ));
    }
    if r.r#box.len() != 16
        || r.ack_hash.len() != 64
        || r.retract_hash.as_ref().is_some_and(|h| h.len() != 64)
    {
        return Err(Error::bad("bad_box", "Bad mailbox or token hash."));
    }
    if !BUCKETS.contains(&r.wire.len()) {
        return Err(Error::bad("bad_size", "Not a wire object."));
    }
    let size = i64::try_from(r.wire.len()).unwrap_or(i64::MAX);
    let mut c = an.db.conn().await?;
    let tx = c.transaction().await?;
    an.spend(&tx, "post", &r.token).await?;
    let use_ = tx
        .query_one(
            "SELECT count(*), COALESCE(sum(size), 0)::bigint FROM relay_objects WHERE box = $1",
            &[&r.r#box.0],
        )
        .await?;
    let (n, bytes): (i64, i64) = (use_.get(0), use_.get(1));
    if n >= i64::from(m.max_per_box)
        || u64::try_from(bytes + size).unwrap_or(u64::MAX) > m.max_box_bytes
    {
        return Err(Error::TooLarge("box_full", "That mailbox is full.".into()));
    }
    if u64::try_from(an.relay_bytes.load(Ordering::SeqCst) + size).unwrap_or(u64::MAX)
        > m.max_total_bytes
    {
        return Err(Error::TooLarge("relay_full", "The relay is full.".into()));
    }
    let minute = an.now() / ms::MINUTE * ms::MINUTE; // arrival to the minute: no finer timing kept
    tx.execute(
        "INSERT INTO relay_objects (box, prefix, at, size, ack_hash, retract_hash, wire) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[&r.r#box.0, &prefix_of(&r.r#box, m.prefix_bits), &minute, &i32::try_from(size).unwrap_or(i32::MAX), &r.ack_hash.0, &r.retract_hash.as_ref().map(|h| h.0.clone()), &r.wire.0],
    )
    .await?;
    an.count(&tx, "deposits", 1).await?;
    tx.commit().await?;
    an.relay_bytes.fetch_add(size, Ordering::SeqCst);
    ok(&serde_json::json!({ "ok": true }))
}

/// `POST /v1/relay/tick`: exactly `tick_slots` slots, each a prefix and a cursor (the
/// highest object id already seen there; 0 for none). Cover slots are random prefixes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tick {
    /// The slots.
    pub slots: Vec<Slot>,
}

/// One slot.
#[derive(Deserialize, Serialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    /// A mailbox prefix.
    pub prefix: i32,
    /// Objects after this id.
    pub after: i64,
}

/// One object in a tick reply.
#[derive(Serialize, Deserialize, Debug)]
pub struct Got {
    /// Its id (the cursor, and what an ack names).
    pub id: i64,
    /// Its box.
    pub r#box: B64,
    /// The wire object.
    pub wire: B64,
}

/// The tick reply, always `tick_reply_bytes` of JSON (padded).
#[derive(Serialize, Deserialize, Debug)]
pub struct TickReply {
    /// Objects, oldest first per slot.
    pub got: Vec<Got>,
    /// More are waiting beyond what fit.
    pub more: bool,
    /// Padding to the fixed size.
    pub pad: String,
}

/// Read (never delete) what's in the asked prefixes.
pub async fn tick(State(an): State<Arc<Anon>>, body: Body) -> Reply {
    let r: Tick = read(body, 16 << 10).await?;
    let m = &an.policy.policy.messaging;
    if r.slots.len() != m.tick_slots as usize {
        return Err(Error::bad(
            "bad_tick",
            "A tick names exactly the policy's number of slots.",
        ));
    }
    let max_prefix = 1i64 << m.prefix_bits;
    if r.slots
        .iter()
        .any(|s| i64::from(s.prefix) < 0 || i64::from(s.prefix) >= max_prefix || s.after < 0)
    {
        return Err(Error::bad("bad_tick", "Bad prefix."));
    }
    let budget = m.tick_reply_bytes as usize;
    let c = an.db.conn().await?;
    let mut got = vec![];
    let mut used = 64usize;
    let mut more = false;
    'slots: for s in &r.slots {
        let rows = c.query("SELECT id, box, wire FROM relay_objects WHERE prefix = $1 AND id > $2 ORDER BY id LIMIT 64", &[&s.prefix, &s.after]).await?;
        for row in rows {
            let wire: Vec<u8> = row.get(2);
            let cost = wire.len() / 3 * 4 + 64;
            if used + cost > budget {
                more = true;
                break 'slots;
            }
            used += cost;
            got.push(Got {
                id: row.get(0),
                r#box: B64(row.get(1)),
                wire: B64(wire),
            });
        }
    }
    let mut reply = TickReply {
        got,
        more,
        pad: String::new(),
    };
    let len = serde_json::to_vec(&reply)
        .map_err(|e| Error::internal(e.to_string()))?
        .len();
    reply.pad = "0".repeat(budget.saturating_sub(len));
    ok(&reply)
}

/// `POST /v1/relay/ack`: `{id, token}` pairs for what the phone has safely stored.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    /// The acks.
    pub acks: Vec<AckOne>,
}

/// One ack.
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AckOne {
    /// The object id from the tick.
    pub id: i64,
    /// The ack token (only the recipient can derive it).
    pub token: B64,
}

/// Delete what the recipient acknowledged (a wrong token deletes nothing).
pub async fn ack(State(an): State<Arc<Anon>>, body: Body) -> Reply {
    let r: Ack = read(body, 64 << 10).await?;
    if r.acks.is_empty() || r.acks.len() > 256 {
        return Err(Error::bad("bad_ack", "Acknowledge 1 to 256 objects."));
    }
    let c = an.db.conn().await?;
    let mut deleted = 0;
    for a in &r.acks {
        let h = token_hash(b"ack", &a.token)?;
        if let Some(row) = c
            .query_opt(
                "DELETE FROM relay_objects WHERE id = $1 AND ack_hash = $2 RETURNING size",
                &[&a.id, &h],
            )
            .await?
        {
            an.relay_bytes
                .fetch_sub(i64::from(row.get::<_, i32>(0)), Ordering::SeqCst);
            deleted += 1;
        }
    }
    ok(&serde_json::json!({ "deleted": deleted }))
}

/// `POST /v1/relay/retract`: the sender unsends an object not yet acknowledged.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Retract {
    /// Its box.
    pub r#box: B64,
    /// The retract token.
    pub token: B64,
}

/// Unsend. `removed: false` for gone, acknowledged and never-there alike.
pub async fn retract(State(an): State<Arc<Anon>>, body: Body) -> Reply {
    let r: Retract = read(body, 4 << 10).await?;
    let h = token_hash(b"retract", &r.token)?;
    let c = an.db.conn().await?;
    let row = c
        .query_opt(
            "DELETE FROM relay_objects WHERE box = $1 AND retract_hash = $2 RETURNING size",
            &[&r.r#box.0, &h],
        )
        .await?;
    if let Some(row) = &row {
        an.relay_bytes
            .fetch_sub(i64::from(row.get::<_, i32>(0)), Ordering::SeqCst);
    }
    ok(&serde_json::json!({ "removed": row.is_some() }))
}

/// Expire relay objects past their TTL (keeps the byte counter right).
///
/// # Errors
/// Database failure.
pub async fn expire(an: &Anon) -> Result<u64> {
    let ttl = i64::from(an.policy.policy.messaging.relay_ttl_days) * ms::DAY;
    let c = an.db.conn().await?;
    let rows = c
        .query(
            "DELETE FROM relay_objects WHERE at < $1 RETURNING size",
            &[&(an.now() - ttl)],
        )
        .await?;
    let gone: i64 = rows.iter().map(|r| i64::from(r.get::<_, i32>(0))).sum();
    an.relay_bytes.fetch_sub(gone, Ordering::SeqCst);
    Ok(rows.len() as u64)
}

/// `POST /v1/push/subscribe`: a push token against coarse prefix buckets, paid with a post
/// token. Stored; the sender (APNs/FCM) is stubbed.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushSub {
    /// A post token.
    pub token: a::Token,
    /// The platform push token.
    pub push_token: B64,
    /// Prefix buckets to be woken for.
    pub prefixes: Vec<i32>,
}

/// Subscribe.
pub async fn push_subscribe(State(an): State<Arc<Anon>>, body: Body) -> Reply {
    let r: PushSub = read(body, 16 << 10).await?;
    if r.push_token.is_empty()
        || r.push_token.len() > 512
        || r.prefixes.is_empty()
        || r.prefixes.len() > 64
    {
        return Err(Error::bad("bad_request", "Bad push subscription."));
    }
    let mut c = an.db.conn().await?;
    let tx = c.transaction().await?;
    an.spend(&tx, "post", &r.token).await?;
    let h = crypto::sha3_512(&r.push_token).to_vec();
    tx.execute(
        "INSERT INTO push_subs (token_hash, token, prefixes, refreshed_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (token_hash) DO UPDATE SET prefixes = $3, refreshed_at = $4",
        &[&h, &r.push_token.0, &r.prefixes, &an.now()],
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "subscribed": true, "sender": "not_implemented" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let b = [0xAB, 0xCD, 0xEF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(prefix_of(&b, 16), 0xABCD);
        assert_eq!(prefix_of(&b, 4), 0xA);
    }
}
