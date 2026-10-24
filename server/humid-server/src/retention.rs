//! Retention (SERVER.md §5): one rule per table, run by one job per unit, in batches.
//!
//! Each rule is a `WHERE` clause over the table with `$1` = now (ms). Tables that are kept by
//! design (accounts, the ledger) still have an entry, with the reason, so the test
//! `every_table_has_a_rule` (per unit) fails when someone adds a table and forgets.

use crate::db::Db;
use crate::error::Result;

/// How a table's rows go.
pub enum Rule {
    /// Delete rows matching this `WHERE` clause (`$1` is now, ms).
    Delete(&'static str),
    /// Kept by design; the reason is the documentation.
    Kept(&'static str),
}

/// One table's rule.
pub struct TableRule {
    /// The table.
    pub table: &'static str,
    /// The rule.
    pub rule: Rule,
}

/// Rows deleted per batch (each batch is its own transaction).
pub const BATCH: i64 = 10_000;

/// Run every `Delete` rule once; returns rows deleted per table.
///
/// # Errors
/// Database failure.
pub async fn run(db: &Db, rules: &[TableRule], now: i64) -> Result<Vec<(&'static str, u64)>> {
    let mut out = vec![];
    for r in rules {
        let Rule::Delete(cond) = r.rule else { continue };
        let mut total = 0u64;
        loop {
            let c = db.conn().await?;
            // `$1` is now (ms): typed bigint, or Postgres infers int4 from `$1 - 86400000`
            let cond = cond.replace("$1", "($1::bigint)");
            let sql = format!(
                "DELETE FROM {t} WHERE ctid IN (SELECT ctid FROM {t} WHERE {cond} LIMIT {BATCH})",
                t = r.table
            );
            let n = c.execute(sql.as_str(), &[&now]).await?;
            total += n;
            if i64::try_from(n).unwrap_or(i64::MAX) < BATCH {
                break;
            }
        }
        if total > 0 {
            tracing::info!(table = r.table, rows = total, "retention");
        }
        out.push((r.table, total));
    }
    Ok(out)
}

/// Every table in the schema has a rule (and every rule names a table).
///
/// # Errors
/// Database failure.
pub async fn missing(db: &Db, rules: &[TableRule]) -> Result<(Vec<String>, Vec<&'static str>)> {
    let tables = db.tables().await?;
    let without: Vec<String> = tables
        .iter()
        .filter(|t| {
            t.as_str() != "schema_migrations" && !rules.iter().any(|r| r.table == t.as_str())
        })
        .cloned()
        .collect();
    let unknown: Vec<&'static str> = rules
        .iter()
        .map(|r| r.table)
        .filter(|r| !tables.iter().any(|t| t == r))
        .collect();
    Ok((without, unknown))
}

/// Run `rules` every `every_ms` until the task is dropped.
pub fn spawn(
    db: Db,
    rules: &'static [TableRule],
    clock: crate::unit::Clock,
    every_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_millis(every_ms));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            if let Err(e) = run(&db, rules, clock.now()).await {
                tracing::warn!(error = %e, "retention run failed");
            }
        }
    })
}
