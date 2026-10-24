//! `humid-server-core --config /etc/humid/core.toml`

use humid_server::core::{self, Core, ledger};
use humid_server::run;
use humid_server::unit::Role;

#[tokio::main]
async fn main() {
    run::init_logging();
    if let Err(e) = go().await {
        run::fail(&e);
    }
}

async fn go() -> humid_server::Result<()> {
    let s = run::start(&run::config_arg(Role::Core), Role::Core)?;
    let db = run::database(&s, "core", core::MIGRATIONS).await?;
    let keys = run::client(&s, Role::Keys)?;
    let c = Core::new(
        db.clone(),
        s.hsm.clone(),
        s.policy.clone(),
        s.clock.clone(),
        keys,
    );
    humid_server::retention::spawn(db.clone(), core::RETENTION, s.clock.clone(), 600_000);
    ledger::spawn_checkpoints(db, s.hsm.clone(), s.clock.clone(), 60_000);
    let sweeper = c.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            t.tick().await;
            if let Err(e) = core::checkin::sweep_erased(&sweeper).await {
                tracing::warn!(error = %e, "check-in sweep");
            }
            let _ = sweeper.redact_closed().await;
        }
    });
    run::serve_internal(&s, Role::Core, c.router()).await
}
