//! `humid-server-front --config /etc/humid/front.toml`

use humid_server::front::Front;
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
    let s = run::start(&run::config_arg(Role::Front), Role::Front)?;
    let f = Front::new(
        s.policy.clone(),
        s.clock.clone(),
        run::client(&s, Role::Core)?,
        run::client(&s, Role::Anon)?,
    );
    run::serve_outer(&s, f.router()).await
}
