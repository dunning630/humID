//! Check-in (docs/CHECKIN.md): core checks the holder's step-up, writes the ledger, and hands
//! keys the signed request, which keys checks again before it touches a fuse. After an erase,
//! core drops the erased envelopes only on keys' own signed `erased` statement.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;

use super::auth::Approved;
use super::ledger::{self, Vouch};
use super::{Core, Reply, SMALL, ok, read};
use crate::api::{app, keys as keys_api};
use crate::error::{Error, Result};
use crate::wire::{self, B64, Id};

/// `GET /v1/checkin`. A duress session sees what an armed one would (docs/CHECKIN.md).
pub async fn status(State(core): State<Arc<Core>>, headers: HeaderMap) -> Reply {
    let s = core.session(&headers).await?;
    let facts = keys_api::CheckinFacts {
        account: s.account,
        action: "status".into(),
        proof_hash: None,
        objects: vec![],
    };
    let req = keys_api::Checkin {
        statement: core.statement("checkin", &facts)?,
        cert: None,
        signed: None,
    };
    let st: keys_api::CheckinStatus = core.keys.post("/v1/checkin", &[], &req).await?;
    ok(&st)
}

async fn act(core: Arc<Core>, headers: HeaderMap, body: Body, action: &str) -> Reply {
    if !core.policy.policy.checkin.enabled {
        return Err(Error::forbidden(
            "checkin_off",
            "This server doesn't offer Check-in.",
        ));
    }
    let s = core.session(&headers).await?;
    let r: Approved = read(body, SMALL).await?;
    match action {
        "arm" => {
            wire::parse::<app::CheckinArm>(&r.signed.body)?;
        }
        "check" => {
            wire::parse::<app::CheckinCheck>(&r.signed.body)?;
        }
        _ => {
            wire::parse::<app::Empty>(&r.signed.body)?;
        }
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, cert) = core
        .step_up(&tx, &s, &r.signed, "POST", &format!("/v1/checkin/{action}"))
        .await?;
    let objects = if action == "arm" {
        tx.query(
            "SELECT id FROM objects WHERE account = $1",
            &[&s.account.as_bytes()],
        )
        .await?
        .iter()
        .map(|r| Id::from_slice(&r.get::<_, Vec<u8>>(0)))
        .collect::<Result<Vec<_>>>()?
    } else {
        vec![]
    };
    let facts = keys_api::CheckinFacts {
        account: s.account,
        action: action.into(),
        proof_hash: Some(B64(checked.proof_hash.to_vec())),
        objects,
    };
    let req = keys_api::Checkin {
        statement: core.statement("checkin", &facts)?,
        cert: Some(cert),
        signed: Some(r.signed),
    };
    // never one ledger entry per check-in: an hourly heartbeat would tell a watcher it's armed
    match action {
        "arm" if !s.duress => {
            ledger::append(
                &tx,
                core.now(),
                &s.account,
                "checkin.armed",
                &serde_json::json!({}),
                Vouch::Holder(&checked.proof_hash),
            )
            .await?;
        }
        "disarm" if !s.duress => {
            ledger::append(
                &tx,
                core.now(),
                &s.account,
                "checkin.disarmed",
                &serde_json::json!({}),
                Vouch::Holder(&checked.proof_hash),
            )
            .await?;
        }
        _ => {}
    }
    let st: keys_api::CheckinStatus = core.keys.post("/v1/checkin", &[], &req).await?;
    tx.commit().await?;
    ok(&st)
}

/// `POST /v1/checkin/arm`.
pub async fn arm(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    act(core, headers, body, "arm").await
}

/// `POST /v1/checkin/check`.
pub async fn check(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    act(core, headers, body, "check").await
}

/// `POST /v1/checkin/disarm`.
pub async fn disarm(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    act(core, headers, body, "disarm").await
}

/// Drop the envelopes of vaults keys has erased, on keys' signed word only. Returns how
/// many accounts were cleaned. Run by a job (and by tests).
///
/// # Errors
/// Keys or the database is unavailable.
pub async fn sweep_erased(core: &Core) -> Result<usize> {
    let st = core.statement("account", &keys_api::AccountFacts { account: None })?;
    let list: keys_api::ErasedList = core
        .keys
        .post(
            "/v1/checkin/erased",
            &[],
            &serde_json::json!({ "statement": st }),
        )
        .await?;
    let kpk = core.policy.policy.keys_key()?;
    let mut cleaned = 0;
    for e in &list.erased {
        let f: keys_api::ErasedFacts = crate::statement::verify(&kpk, e, "erased", core.now())?;
        let mut c = core.db.conn().await?;
        let tx = c.transaction().await?;
        let a = f.account.as_bytes();
        let keep: Vec<Vec<u8>> = f.keep.iter().map(|k| k.as_bytes().to_vec()).collect();
        let gone = tx
            .query("DELETE FROM objects WHERE account = $1 AND NOT (id = ANY($2)) AND created_at <= $3 RETURNING id", &[&a, &keep, &f.erased_at])
            .await?;
        if !gone.is_empty() {
            let rev: i64 = tx.query_one("UPDATE accounts SET object_rev = object_rev + 1 WHERE id = $1 RETURNING object_rev", &[&a]).await?.get(0);
            for g in &gone {
                let id: Vec<u8> = g.get(0);
                tx.execute("INSERT INTO object_tombstones (id, account, rev, deleted_at) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET rev = $3", &[&id, &a, &rev, &core.now()])
                    .await?;
            }
        }
        // asserted by the server (keys' statement), not a live check: the app can tell
        ledger::append(
            &tx,
            core.now(),
            &f.account,
            "checkin.erased",
            &serde_json::json!({ "count": f.count }),
            Vouch::Server,
        )
        .await?;
        let ack = core.statement(
            "account",
            &keys_api::AccountFacts {
                account: Some(f.account),
            },
        )?;
        let _: serde_json::Value = core
            .keys
            .post(
                "/v1/checkin/cleaned",
                &[],
                &keys_api::Cleaned {
                    statement: ack,
                    erased_at: f.erased_at,
                },
            )
            .await?;
        tx.commit().await?;
        cleaned += 1;
    }
    Ok(cleaned)
}
