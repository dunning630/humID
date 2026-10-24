#![no_main]
//! The client against arbitrary answers: to a handshake (never yields a session without the
//! server's confirmation) and inside a session (never panics, never yields a response it
//! didn't get from the genuine server). The signing key and certificate are made once per
//! process (review #97 L-4); the handshakes are per input.
use std::sync::OnceLock;

use humid_htp::cert::Cert;
use humid_htp::client::{Event, Handshake};
use humid_htp::msg::{Encoding, Method};
use humid_htp::server::{Config, Server};
use humid_htp::{Unit, label};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_798_761_600_000;

/// The certificate (shared) and a factory for a server holding its key.
fn cert() -> &'static (Cert, std::sync::Mutex<Server>) {
    static C: OnceLock<(Cert, std::sync::Mutex<Server>)> = OnceLock::new();
    C.get_or_init(|| {
        let st = humid_pq2::MlDsaSigningKey::generate().expect("key");
        let mut srv = Server::new(Config::new(Unit::Core)).expect("server");
        let pk = Server::prepare_key(NOW - 1, NOW + 1_000_000).expect("kem");
        let sig = st
            .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
            .expect("sign")
            .to_bytes();
        let cert = Cert::decode(&srv.install_key(pk, &sig).expect("install")).expect("cert");
        (cert, std::sync::Mutex::new(srv))
    })
}

fuzz_target!(|data: &[u8]| {
    let (cert, srv) = cert();
    let (hs, _) = Handshake::full(Unit::Core, cert, NOW).expect("hello");
    assert!(
        hs.finish(data).is_err(),
        "a session only from the real server's reply"
    );
    let Ok(mut srv) = srv.lock() else { return };
    let (hs, hello) = Handshake::full(Unit::Core, cert, NOW).expect("hello");
    let r = srv.receive(&hello, NOW);
    let sid = r.sid;
    let mut s = hs.finish(&r.frames).expect("finish");
    let _ = s.request(Method::Get, "/v1/me", Encoding::Raw, &[], b"");
    let mut d = data.to_vec();
    if d.len() >= 32 {
        d[8..24].copy_from_slice(&s.sid());
    }
    if let Ok(events) = s.receive(&d) {
        assert!(!events.iter().any(|e| matches!(e, Event::Response { .. })));
    }
    srv.close(&sid);
});
