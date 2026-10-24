//! `humid-server-keys --config /etc/humid/keys.toml`

use humid_server::keys::{self, Keys};
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
    let s = run::start(&run::config_arg(Role::Keys), Role::Keys)?;
    let db = run::database(&s, "keys", keys::MIGRATIONS).await?;
    let kem = keys::load_kem(s.hsm.as_ref(), &s.cfg.data_dir)?;
    let k = Keys::new(
        db.clone(),
        s.hsm.clone(),
        s.policy.clone(),
        s.clock.clone(),
        kem,
    )
    .await?;
    humid_server::retention::spawn(db, keys::RETENTION, s.clock.clone(), 600_000);
    k.spawn_timer();
    run::serve_internal(&s, Role::Keys, k.router()).await
}
