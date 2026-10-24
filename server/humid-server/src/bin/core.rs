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
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("dev-setup") {
        let dir = args
            .get(2)
            .ok_or_else(|| humid_server::Error::bad("usage", "dev-setup <dir> [database-url]"))?;
        let db = args
            .get(3)
            .map_or("host=/run/postgresql dbname=humid_dev", String::as_str);
        humid_server::devsetup::write(std::path::Path::new(dir), db)?;
        println!(
            "Development setup written to {dir} (software HSMs; development policy). Start each unit with --config {dir}/<unit>.toml"
        );
        return Ok(());
    }
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
    // HTP/2 ends here: front forwards opaque calls; /v1/* answers only what the endpoint
    // dispatched from an authenticated session.
    let ep = humid_server::htp::Endpoint::new(
        Role::Core,
        s.hsm.clone(),
        humid_server::hsm::KeyRef::CoreStatement,
        s.clock.clone(),
    );
    humid_server::htp::spawn_ticks(ep.clone());
    let router = humid_server::htp::mount(c.router(), &ep);
    run::serve_internal(&s, Role::Core, router).await
}
