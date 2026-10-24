//! `humid-server-anon --config /etc/humid/anon.toml`
//! `humid-server-anon --config … mint <count> <batch>` prints access codes.

use humid_server::anon::{self, Anon, relay};
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
    let s = run::start(&run::config_arg(Role::Anon), Role::Anon)?;
    let db = run::database(&s, "anon", anon::MIGRATIONS).await?;
    let a = Anon::new(
        db.clone(),
        s.hsm.clone(),
        s.policy.clone(),
        s.clock.clone(),
        3072,
    )
    .await?;
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|x| x == "mint") {
        let n: usize = args.get(i + 1).and_then(|n| n.parse().ok()).unwrap_or(1);
        let batch = args.get(i + 2).cloned().unwrap_or_else(|| "default".into());
        for code in a.mint(n.min(100_000), &batch).await? {
            println!("{code}");
        }
        return Ok(());
    }
    humid_server::retention::spawn(db, anon::RETENTION, s.clock.clone(), 600_000);
    let upkeep = a.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            t.tick().await;
            let _ = relay::expire(&upkeep).await;
            let _ = upkeep.prune_codes().await;
        }
    });
    let ep = humid_server::htp::Endpoint::new(
        Role::Anon,
        s.hsm.clone(),
        humid_server::hsm::KeyRef::AnonStatement,
        s.clock.clone(),
    );
    humid_server::htp::spawn_ticks(ep.clone());
    let router = humid_server::htp::mount(a.router(), &ep);
    run::serve_internal(&s, Role::Anon, router).await
}
