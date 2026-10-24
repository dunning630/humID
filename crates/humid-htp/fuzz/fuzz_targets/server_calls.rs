#![no_main]
//! The server state machine against arbitrary calls, after a genuine handshake: never panics,
//! never hands the unit a request it didn't get from the genuine client, and always answers.
//! Fuzzed bytes are also spliced into the genuine session's id, so records reach the opener.

use humid_htp::client::Handshake;
use humid_htp::server::{Config, Server};
use humid_htp::{Unit, label};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_798_761_600_000;

fn setup() -> (Server, [u8; 16]) {
    let st = humid_pq2::MlDsaSigningKey::generate().expect("key");
    let mut srv = Server::new(Config::new(Unit::Core)).expect("server");
    let pk = Server::prepare_key(NOW - 1, NOW + 1_000_000).expect("kem");
    let sig = st
        .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
        .expect("sign")
        .to_bytes();
    let cert =
        humid_htp::cert::Cert::decode(&srv.install_key(pk, &sig).expect("install")).expect("cert");
    let (hs, hello) = Handshake::full(Unit::Core, &cert, NOW).expect("hello");
    let r = srv.receive(&hello, NOW);
    let s = hs.finish(&r.frames).expect("finish");
    (srv, s.sid())
}

fuzz_target!(|data: &[u8]| {
    // a fresh server per input keeps runs independent
    let (mut srv, sid) = setup();
    let r = srv.receive(data, NOW);
    assert!(r.ready.is_empty(), "nothing forged reaches the unit");
    assert!(!r.frames.is_empty());
    if data.len() >= 32 {
        let mut d = data.to_vec();
        d[..2].copy_from_slice(b"HT");
        d[2] = 1;
        d[3] = 4;
        d[4] = 1;
        d[8..24].copy_from_slice(&sid);
        let r = srv.receive(&d, NOW);
        assert!(r.ready.is_empty());
    }
});
