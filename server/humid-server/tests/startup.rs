//! Start-up as the binaries do it (run::start): config, identity root, signed policy,
//! forward-only rule, HSM. And front's outer listener: PQ group required.

use std::sync::Arc;

use humid_server::front::Front;
use humid_server::hsm::{Hsm, SoftHsm};
use humid_server::policy::{self, Policy};
use humid_server::run;
use humid_server::testkit::cluster::Cluster;
use humid_server::tls;
use humid_server::unit::Role;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tmp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "humid-startup-{}",
        hex::encode(humid_server::crypto::random::<8>().unwrap())
    ))
}

#[test]
fn units_start_from_a_dev_setup_and_refuse_a_bad_policy() {
    let dir = tmp();
    humid_server::devsetup::write(&dir, &humid_server::db::test::url()).unwrap();
    assert!(
        humid_server::devsetup::write(&dir, "x").is_err(),
        "dev-setup never overwrites keys"
    );
    for r in Role::ALL {
        let s = run::start(&dir.join(format!("{}.toml", r.as_str())), r)
            .unwrap_or_else(|e| panic!("{}: {e}", r.as_str()));
        assert_eq!(s.policy.policy.version, 1);
    }
    // a file for another role
    assert_eq!(
        run::start(&dir.join("keys.toml"), Role::Core)
            .err()
            .unwrap()
            .code(),
        "bad_config"
    );

    // one byte changed in the policy: refused
    let p = dir.join("policy.json");
    let good = std::fs::read(&p).unwrap();
    let mut bad = good.clone();
    bad.push(b'\n');
    std::fs::write(&p, &bad).unwrap();
    assert_eq!(
        run::start(&dir.join("core.toml"), Role::Core)
            .err()
            .unwrap()
            .code(),
        "bad_policy_signature"
    );

    // a newer policy, properly signed, is accepted; then the old one is a rollback
    let root = SoftHsm::open_dir(&dir.join("root")).unwrap();
    let mut v2: Policy = serde_json::from_slice(&good).unwrap();
    v2.version = 2;
    v2.limits.share_releases_per_hour = 60;
    let b2 = serde_json::to_vec(&v2).unwrap();
    std::fs::write(&p, &b2).unwrap();
    std::fs::write(
        dir.join("policy.json.sig"),
        policy::sign(&root, &b2).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run::start(&dir.join("core.toml"), Role::Core)
            .unwrap()
            .policy
            .policy
            .version,
        2
    );
    std::fs::write(&p, &good).unwrap();
    std::fs::write(
        dir.join("policy.json.sig"),
        policy::sign(&root, &good).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run::start(&dir.join("core.toml"), Role::Core)
            .err()
            .unwrap()
            .code(),
        "policy_rollback",
        "a validly signed but older policy is refused"
    );
    // keys hasn't seen v2, so for it v1 is still current: each unit keeps its own state
    assert!(run::start(&dir.join("keys.toml"), Role::Keys).is_ok());

    // a policy signed by some other root
    let other = SoftHsm::ephemeral().unwrap();
    v2.version = 3;
    let b3 = serde_json::to_vec(&v2).unwrap();
    std::fs::write(&p, &b3).unwrap();
    std::fs::write(
        dir.join("policy.json.sig"),
        policy::sign(&other, &b3).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run::start(&dir.join("core.toml"), Role::Core)
            .err()
            .unwrap()
            .code(),
        "bad_policy_signature"
    );
    std::fs::remove_dir_all(&dir).ok();
}

async fn get(
    cfg: Arc<rustls::ClientConfig>,
    addr: std::net::SocketAddr,
    path: &str,
) -> std::io::Result<String> {
    let s = tokio::net::TcpStream::connect(addr).await?;
    let mut t = tokio_rustls::TlsConnector::from(cfg)
        .connect(
            ServerName::try_from("front.unit.humid.internal").unwrap(),
            s,
        )
        .await?;
    t.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").as_bytes())
        .await?;
    let mut out = String::new();
    t.read_to_string(&mut out).await?;
    Ok(out)
}

#[tokio::test]
async fn front_requires_a_post_quantum_group_and_serves_the_signed_policy() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let front = Front::new(
        c.policy.clone(),
        c.clock.clone(),
        c.to_core.clone(),
        c.to_anon.clone(),
    );
    let id = c.front_identity.clone();
    let scfg = rustls::ServerConfig::builder_with_provider(tls::outer_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(id.chain.clone(), PrivateKeyDer::Pkcs8(id.key.clone_key()))
        .unwrap();
    let (addr, _task) = humid_server::net::spawn(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(scfg),
        front.router(),
        &[],
        true,
    )
    .await
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(id.ca.clone()).unwrap();
    let client = |groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>| {
        let mut p = rustls::crypto::aws_lc_rs::default_provider();
        p.kx_groups = groups;
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(p))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth(),
        )
    };
    use rustls::crypto::aws_lc_rs::kx_group;
    // a classical-only client is refused
    assert!(
        get(
            client(vec![kx_group::X25519, kx_group::SECP384R1]),
            addr,
            "/healthz"
        )
        .await
        .is_err()
    );
    // X25519MLKEM768 (what browsers and phones offer today) is accepted
    let r = get(client(vec![kx_group::X25519MLKEM768]), addr, "/healthz")
        .await
        .unwrap();
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    // the signed policy, exactly as the root signed it; the app verifies it against its pin
    // the key bundle: the signed policy exactly as the root signed it, and each unit's
    // certified HTP/2 KEM key; the app verifies the whole chain against its pinned root
    let r = get(client(vec![tls::P384_MLKEM1024]), addr, "/healthz")
        .await
        .unwrap();
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let mut t = humid_server::testkit::cluster::OuterTransport::new(addr, &id.ca).unwrap();
    let bundle = humid_link::Transport::keys(&mut t).await.unwrap();
    let b = humid_htp::cert::Bundle::decode(&bundle).unwrap();
    policy::verify(&b.policy, &b.policy_sig, &c.root, c.clock.now()).unwrap();
    let root = humid_pq2::DualVerifyingKey::from_bytes(&c.root.to_bytes()).unwrap();
    let now = u64::try_from(c.clock.now()).unwrap();
    for unit in [humid_htp::Unit::Core, humid_htp::Unit::Anon] {
        let cert = b
            .verified(&root, unit, now, humid_server::htp::statement_key_of)
            .unwrap();
        // and that key really terminates a session behind this front
        let (hs, hello) = humid_htp::client::Handshake::full(unit, &cert, now).unwrap();
        let ans = humid_link::Transport::call(&mut t, hello).await.unwrap();
        assert!(hs.finish(&ans).is_ok(), "{unit:?}");
    }
    // a bundle checked against another root is refused: the app stops
    let other = SoftHsm::ephemeral().unwrap();
    let other = humid_pq2::DualVerifyingKey::from_bytes(
        &other
            .dual_public(humid_server::hsm::KeyRef::IdentityRoot)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert!(
        b.verified(
            &other,
            humid_htp::Unit::Core,
            now,
            humid_server::htp::statement_key_of
        )
        .is_err()
    );
    c.stop().await.unwrap();
}
