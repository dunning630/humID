//! Starting a unit: the same checks in the same order for all four binaries.
//!
//! 1. the HUMID-PQ2 self-test (refuse to run if it fails);
//! 2. `server.toml` for this role;
//! 3. the identity root, then the signed policy (signature, then forward-only);
//! 4. production mode: no stub in this unit's path, a loopback / socket database;
//! 5. the HSM (the software one is refused in production), and every key the unit needs;
//! 6. migrations from empty; retention and timers;
//! 7. the internal TLS listener (and, for front, the outer one). No plain HTTP anywhere.

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::crypto::{self, DualPublic};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::hsm::{self, Hsm, KeyRef};
use crate::net::{self, UnitClient};
use crate::policy::{self, SignedPolicy};
use crate::tls::Identity;
use crate::unit::{Clock, Mode, Role};

/// What every unit has once it passed the start-up checks.
pub struct Started {
    /// The configuration.
    pub cfg: Config,
    /// The verified policy.
    pub policy: Arc<SignedPolicy>,
    /// The HSM.
    pub hsm: Arc<dyn Hsm>,
    /// Internal TLS identity.
    pub identity: Identity,
    /// The clock.
    pub clock: Clock,
}

fn keys_for(role: Role) -> &'static [KeyRef] {
    match role {
        Role::Front => &[KeyRef::Seal],
        Role::Core => crate::core::HSM_KEYS,
        Role::Keys => crate::keys::HSM_KEYS,
        Role::Anon => crate::anon::HSM_KEYS,
    }
}

/// Steps 1–5.
///
/// # Errors
/// The first check that fails, with a reason an operator can act on.
pub fn start(config_path: &Path, role: Role) -> Result<Started> {
    crypto::self_test()?;
    let cfg = Config::load(config_path, role)?;
    let clock = Clock::system();
    let root_bytes = std::fs::read(&cfg.identity_root)
        .map_err(|e| Error::internal(format!("{}: {e}", cfg.identity_root.display())))?;
    let root = DualPublic::from_bytes(&root_bytes)?;
    let policy = Arc::new(policy::load(
        &cfg.policy,
        &root,
        &cfg.data_dir,
        clock.now(),
    )?);
    let mode = policy.policy.mode;
    crate::stubs::check(role, mode)?;
    if mode == Mode::Production {
        if let Some(db) = &cfg.database {
            if !crate::config::database_is_local(&db.url) {
                return Err(Error::forbidden(
                    "database_not_local",
                    "In production the database must be on a Unix socket or loopback (replication carries it between sites).",
                ));
            }
        }
    }
    let hsm = hsm::open(&cfg.hsm, mode, &cfg.data_dir, keys_for(role))?;
    let identity = Identity::load(&cfg.tls.cert, &cfg.tls.key, &cfg.tls.ca)?;
    tracing::info!(unit = role.as_str(), policy = policy.policy.version, mode = ?mode, suite = crypto_suite(), "started");
    Ok(Started {
        cfg,
        policy,
        hsm,
        identity,
        clock,
    })
}

fn crypto_suite() -> &'static str {
    "HUMID-PQ2/1"
}

/// A client for another unit named in `[units]`.
///
/// # Errors
/// It isn't configured.
pub fn client(s: &Started, role: Role) -> Result<UnitClient> {
    let url = s
        .cfg
        .units
        .get(&role)
        .ok_or_else(|| Error::bad("bad_config", format!("[units] needs {}", role.as_str())))?;
    UnitClient::new(&s.identity, role, url)
}

/// The unit's database, migrated.
///
/// # Errors
/// Unreachable or a migration fails.
pub async fn database(s: &Started, unit: &str, migrations: &[crate::db::Migration]) -> Result<Db> {
    let d = s
        .cfg
        .database
        .as_ref()
        .ok_or_else(|| Error::bad("bad_config", "this unit needs [database]"))?;
    let db = Db::connect(&d.url, d.pool, None)?;
    db.migrate(unit, migrations).await?;
    Ok(db)
}

/// Serve on the internal TLS listener until the process is stopped.
///
/// # Errors
/// The listener can't be bound.
pub async fn serve_internal(s: &Started, role: Role, router: axum::Router) -> Result<()> {
    let (addr, task) = net::spawn(
        s.cfg.listen,
        s.identity.server_config()?,
        router,
        role.callers(),
        false,
    )
    .await?;
    tracing::info!(%addr, "listening (internal TLS, SecP384r1MLKEM1024 only)");
    wait(task).await
}

async fn wait(task: tokio::task::JoinHandle<()>) -> Result<()> {
    tokio::select! {
        r = task => r.map_err(|e| Error::internal(e.to_string())),
        _ = tokio::signal::ctrl_c() => { tracing::info!("stopping"); Ok(()) }
    }
}

/// Front's outer listener (public TLS 1.3, PQ group required).
///
/// # Errors
/// Bad certificate files; the listener can't be bound.
pub async fn serve_outer(s: &Started, router: axum::Router) -> Result<()> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let p = s
        .cfg
        .public_tls
        .as_ref()
        .ok_or_else(|| Error::bad("bad_config", "front needs [public_tls]"))?;
    let chain = CertificateDer::pem_file_iter(&p.cert)
        .and_then(|i| i.collect::<std::result::Result<Vec<_>, _>>())
        .map_err(|e| Error::internal(format!("{}: {e}", p.cert.display())))?;
    let key = PrivateKeyDer::from_pem_file(&p.key)
        .map_err(|e| Error::internal(format!("{}: {e}", p.key.display())))?;
    let cfg = rustls::ServerConfig::builder_with_provider(crate::tls::outer_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::internal(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| Error::internal(format!("public certificate: {e}")))?;
    let (addr, task) = net::spawn(s.cfg.listen, Arc::new(cfg), router, &[], true).await?;
    tracing::info!(%addr, "listening (public TLS 1.3, post-quantum group required)");
    wait(task).await
}

/// Logging to stderr (`RUST_LOG`), one line per event, no request bodies ever.
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .try_init();
}

/// The config path from `--config <path>` (default `/etc/humid/<role>.toml`).
#[must_use]
pub fn config_arg(role: Role) -> std::path::PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" {
            if let Some(p) = args.next() {
                return p.into();
            }
        }
    }
    format!("/etc/humid/{}.toml", role.as_str()).into()
}

/// Exit with the error, as an operator reads it.
pub fn fail(e: &Error) -> ! {
    eprintln!("humid-server: {}", e.message());
    tracing::error!(code = e.code_str(), "{}", e.message());
    std::process::exit(1)
}
