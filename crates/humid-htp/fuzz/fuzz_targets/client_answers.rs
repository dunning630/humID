#![no_main]
//! The client against arbitrary answers: to a handshake (never yields a session without the
//! server's confirmation) and inside a session (never panics, never yields a response).
use humid_htp::client::{Event, Handshake};
use humid_htp::msg::{Encoding, Method};
use humid_htp::server::{Config, Server};
use humid_htp::{Unit, label};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_798_761_600_000;

fuzz_target!(|data: &[u8]| {
    let st = humid_pq2::MlDsaSigningKey::generate().expect("key");
    let mut srv = Server::new(Config::new(Unit::Core)).expect("server");
    let pk = Server::prepare_key(NOW - 1, NOW + 1_000_000).expect("kem");
    let sig = st
        .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
        .expect("sign")
        .to_bytes();
    let cert =
        humid_htp::cert::Cert::decode(&srv.install_key(pk, &sig).expect("install")).expect("cert");
    let (hs, _) = Handshake::full(Unit::Core, &cert, NOW).expect("hello");
    assert!(
        hs.finish(data).is_err(),
        "a session only from the real server's reply"
    );

    let (hs, hello) = Handshake::full(Unit::Core, &cert, NOW).expect("hello");
    let r = srv.receive(&hello, NOW);
    let mut s = hs.finish(&r.frames).expect("finish");
    let _ = s.request(Method::Get, "/v1/me", Encoding::Raw, &[], b"");
    let mut d = data.to_vec();
    if d.len() >= 32 {
        d[8..24].copy_from_slice(&s.sid());
    }
    if let Ok(events) = s.receive(&d) {
        assert!(!events.iter().any(|e| matches!(e, Event::Response { .. })));
    }
});
