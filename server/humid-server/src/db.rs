//! PostgreSQL (SERVER.md §4): a pool, migrations from empty, and always-rollback transactions.
//!
//! * A `Tx` rolls back when dropped unless `commit()` ran, so an early `?` never leaves half
//!   a change behind.
//! * Migrations are SQL files compiled into the binary, applied in order, each in its own
//!   transaction, recorded with their SHA3-512. A migration whose text changed after it was
//!   applied is refused: schemas move forward only.
//! * Connections are Unix-socket or loopback only in production (`config::database_is_local`),
//!   so the hop needs no TLS of its own.

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use crate::crypto;
use crate::error::{Error, Result};

/// A migration: version, name, SQL.
pub type Migration = (i32, &'static str, &'static str);

/// A database pool for one unit.
#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

/// A pooled connection.
pub type Conn = deadpool_postgres::Object;

impl Db {
    /// Connect with a libpq-style string or URL. `search_path` (tests) puts the unit in a schema.
    ///
    /// # Errors
    /// A malformed URL.
    pub fn connect(url: &str, size: usize, search_path: Option<&str>) -> Result<Self> {
        let mut cfg: tokio_postgres::Config = url
            .parse()
            .map_err(|e| Error::bad("bad_config", format!("database url: {e}")))?;
        if let Some(sp) = search_path {
            cfg.options(format!("-c search_path={sp}"));
        }
        cfg.application_name("humid-server");
        let mgr = Manager::from_config(
            cfg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(mgr)
            .max_size(size.max(2))
            .build()
            .map_err(|e| Error::internal(format!("pool: {e}")))?;
        Ok(Self { pool })
    }

    /// A connection.
    ///
    /// # Errors
    /// The database is unavailable.
    pub async fn conn(&self) -> Result<Conn> {
        Ok(self.pool.get().await?)
    }

    /// Apply `migrations` for `unit` from empty, in order.
    ///
    /// # Errors
    /// A changed migration, or SQL that fails.
    pub async fn migrate(&self, unit: &str, migrations: &[Migration]) -> Result<()> {
        let mut c = self.conn().await?;
        c.batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                unit text NOT NULL, version integer NOT NULL, name text NOT NULL,
                sha3 bytea NOT NULL, applied_at bigint NOT NULL, PRIMARY KEY (unit, version))",
        )
        .await?;
        let tx = c.transaction().await?;
        // one migrator at a time (two units of the same kind starting together)
        tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&unit])
            .await?;
        let mut last = 0;
        for &(version, name, sql) in migrations {
            if version <= last {
                return Err(Error::internal("migrations out of order"));
            }
            last = version;
            let h = crypto::sha3_512(sql.as_bytes()).to_vec();
            let row = tx
                .query_opt(
                    "SELECT sha3 FROM schema_migrations WHERE unit = $1 AND version = $2",
                    &[&unit, &version],
                )
                .await?;
            match row {
                Some(r) => {
                    let had: Vec<u8> = r.get(0);
                    if !crypto::ct_eq(&had, &h) {
                        return Err(Error::internal(format!(
                            "migration {unit}/{version} {name} changed after it was applied"
                        )));
                    }
                }
                None => {
                    tx.batch_execute(sql).await.map_err(|e| {
                        Error::internal(format!("migration {unit}/{version} {name}: {e}"))
                    })?;
                    tx.execute(
                        "INSERT INTO schema_migrations (unit, version, name, sha3, applied_at) VALUES ($1, $2, $3, $4, (extract(epoch from now()) * 1000)::bigint)",
                        &[&unit, &version, &name, &h],
                    )
                    .await?;
                    tracing::info!(unit, version, name, "migration applied");
                }
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Every table in the unit's schema (for the "every table has a retention rule" test).
    ///
    /// # Errors
    /// Database failure.
    pub async fn tables(&self) -> Result<Vec<String>> {
        let c = self.conn().await?;
        let rows = c
            .query("SELECT table_name::text FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY 1", &[])
            .await?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }
}

/// A test database: a fresh schema per unit per test, dropped by `TestDb::drop_all`.
#[cfg(any(test, feature = "testkit"))]
pub mod test {
    use super::{Db, Result};

    /// Where the tests find PostgreSQL (`HUMID_TEST_DATABASE_URL`).
    #[must_use]
    pub fn url() -> String {
        std::env::var("HUMID_TEST_DATABASE_URL").unwrap_or_else(|_| {
            "host=127.0.0.1 user=humid_test password=humid_test dbname=postgres".into()
        })
    }

    /// A fresh schema `t_<random>_<unit>` and a pool using it.
    ///
    /// # Errors
    /// The database isn't reachable.
    pub async fn fresh(unit: &str) -> Result<(Db, String)> {
        let schema = format!("t_{}_{unit}", hex::encode(crate::crypto::random::<6>()?));
        let admin = Db::connect(&url(), 2, None)?;
        admin
            .conn()
            .await?
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await?;
        Ok((Db::connect(&url(), 8, Some(&schema))?, schema))
    }

    /// Drop a test schema.
    ///
    /// # Errors
    /// The database isn't reachable.
    pub async fn drop_schema(schema: &str) -> Result<()> {
        let admin = Db::connect(&url(), 2, None)?;
        admin
            .conn()
            .await?
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_apply_once_and_refuse_edits() {
        let (db, schema) = test::fresh("mig").await.unwrap();
        let m1: &[Migration] = &[
            (1, "init", "CREATE TABLE a (x int)"),
            (2, "more", "CREATE TABLE b (y int)"),
        ];
        db.migrate("mig", m1).await.unwrap();
        db.migrate("mig", m1).await.unwrap(); // idempotent
        assert_eq!(
            db.tables().await.unwrap(),
            vec!["a", "b", "schema_migrations"]
        );
        let edited: &[Migration] = &[(1, "init", "CREATE TABLE a (x bigint)")];
        assert!(
            db.migrate("mig", edited).await.is_err(),
            "a migration can't change after it ran"
        );
        test::drop_schema(&schema).await.unwrap();
    }

    #[tokio::test]
    async fn a_transaction_rolls_back_unless_committed() {
        let (db, schema) = test::fresh("tx").await.unwrap();
        db.migrate("tx", &[(1, "t", "CREATE TABLE t (x int)")])
            .await
            .unwrap();
        {
            let mut c = db.conn().await.unwrap();
            let tx = c.transaction().await.unwrap();
            tx.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
            // dropped without commit: an early `?` in a handler looks like this
        }
        let c = db.conn().await.unwrap();
        let n: i64 = c
            .query_one("SELECT count(*) FROM t", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0);
        test::drop_schema(&schema).await.unwrap();
    }
}
