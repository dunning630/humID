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
use crate::unit::ms;
use crate::wire::{self, B64, Id};

/// `GET /v1/checkin`. A duress session is shown its own copy of Check-in, as it stood at the
/// duress sign-in and moved only by that session's own check-ins (H-1, CHECKIN.md: "the
/// duress session is shown a copy of Check-in as it was"). Keys is still asked, so the
/// answer takes the same time.
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
    let real = core
        .keys
        .post::<_, keys_api::CheckinStatus>("/v1/checkin", &[], &req)
        .await;
    if s.duress {
        return ok(&view_now(&core, &s));
    }
    ok(&real?)
}

/// The duress session's copy, settled to now the way keys settles a real one.
fn view_now(core: &Core, s: &super::Session) -> keys_api::CheckinStatus {
    let mut v = s
        .checkin_view
        .clone()
        .unwrap_or_else(keys_api::CheckinStatus::off);
    let now = core.now();
    if let (Some(d), Some(e)) = (v.deadline, v.erases_at)
        && (v.state == "armed" || v.state == "locked")
    {
        v.state = if now < d {
            "armed"
        } else if now < e {
            "locked"
        } else {
            // the copy runs out like the real thing would: what a missed deadline shows
            "erased"
        }
        .into();
        if v.state == "erased" {
            v = keys_api::CheckinStatus {
                state: "erased".into(),
                erased_at: Some(e),
                ..keys_api::CheckinStatus::off()
            };
        }
    }
    v
}

/// A duress session's arm / check / disarm: checked like the real thing (the step-up, the
/// policy's choices), applied only to the session's own copy. Keys is never told, so nothing
/// real changes and nothing is ever erased by it (H-2).
async fn simulate(
    core: &Core,
    tx: &deadpool_postgres::Transaction<'_>,
    s: &super::Session,
    action: &str,
    body: &[u8],
) -> Result<keys_api::CheckinStatus> {
    let p = &core.policy.policy.checkin;
    let pick = |v: u32, allowed: &[u32]| -> Result<i64> {
        if allowed.contains(&v) {
            Ok(i64::from(v))
        } else {
            Err(Error::bad(
                "bad_checkin",
                "Check-in can't use that setting.",
            ))
        }
    };
    let now = core.now();
    let mut v = view_now(core, s);
    match action {
        "arm" => {
            let a: app::CheckinArm = wire::parse(body)?;
            let window = pick(a.window_h, &p.windows_h)? * ms::HOUR;
            let max = pick(a.max_window_h, &p.windows_h)? * ms::HOUR;
            let grace = pick(a.grace_min, &p.grace_min)? * ms::MINUTE;
            if max < window {
                return Err(Error::bad(
                    "bad_checkin",
                    "The longest window can't be shorter than the usual one.",
                ));
            }
            if v.state == "erased" {
                return Err(Error::Gone(
                    "vault_erased",
                    "Your vault was erased by Check-in.".into(),
                ));
            }
            v = keys_api::CheckinStatus {
                state: "armed".into(),
                deadline: Some(now + window),
                erases_at: Some(now + window + grace),
                erased_at: None,
                window_ms: Some(window),
                max_window_ms: Some(max),
            };
        }
        "check" => {
            let c: app::CheckinCheck = wire::parse(body)?;
            match (
                v.state.as_str(),
                v.deadline,
                v.erases_at,
                v.window_ms,
                v.max_window_ms,
            ) {
                ("erased", ..) => {
                    return Err(Error::Gone(
                        "vault_erased",
                        "Your vault was erased by Check-in.".into(),
                    ));
                }
                ("armed" | "locked", Some(d), Some(e), Some(w), Some(max)) => {
                    let next = match c.next_window_h {
                        Some(h) => pick(h, &p.windows_h)? * ms::HOUR,
                        None => w,
                    };
                    if next > max {
                        return Err(Error::bad(
                            "bad_checkin",
                            "That's longer than the longest window you allowed.",
                        ));
                    }
                    v.state = "armed".into();
                    v.deadline = Some(now + next);
                    v.erases_at = Some(now + next + (e - d));
                }
                _ => return Err(Error::conflict("checkin_off", "Check-in isn't on.")),
            }
        }
        _ => {
            wire::parse::<app::Empty>(body)?;
            if v.state == "erased" {
                return Err(Error::Gone(
                    "vault_erased",
                    "Your vault was erased by Check-in.".into(),
                ));
            }
            v = keys_api::CheckinStatus::off();
        }
    }
    tx.execute(
        "UPDATE sessions SET checkin_view = $2 WHERE token_hash = $1",
        &[
            &s.token_hash,
            &serde_json::to_value(&v).map_err(|e| Error::internal(e.to_string()))?,
        ],
    )
    .await?;
    Ok(v)
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
    if s.duress {
        let v = simulate(&core, &tx, &s, action, &r.signed.body).await?;
        tx.commit().await?;
        return ok(&v);
    }
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
    // keys first (arming reseals every share), then the ledger entry in this transaction, so
    // the public log's lock is never held across the call (M-1)
    let st: keys_api::CheckinStatus = core.keys.post("/v1/checkin", &[], &req).await?;
    // never one ledger entry per check-in: an hourly heartbeat would tell a watcher it's armed
    let kind = match action {
        "arm" => Some("checkin.armed"),
        "disarm" => Some("checkin.disarmed"),
        _ => None,
    };
    if let Some(kind) = kind {
        ledger::append(
            &tx,
            core.now(),
            &s.account,
            kind,
            &serde_json::json!({}),
            Vouch::Holder(&checked.proof_hash),
        )
        .await?;
    }
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
        // one entry per erase, however many sweeps it takes; commit, then ack keys (L-8)
        let first = tx
            .execute(
                "INSERT INTO erase_sweeps (account, erased_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&a, &f.erased_at],
            )
            .await?;
        if first == 1 {
            // asserted by the server (keys' statement), not a live check: the app can tell.
            // Deferred while a duress session is live (it is shown Check-in as it was).
            ledger::append_or_defer(
                &tx,
                core.now(),
                &f.account,
                "checkin.erased",
                &serde_json::json!({ "count": f.count }),
                Vouch::Server,
            )
            .await?;
        }
        tx.commit().await?;
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
        cleaned += 1;
    }
    Ok(cleaned)
}
