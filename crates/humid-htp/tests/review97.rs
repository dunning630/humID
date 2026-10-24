//! Regression tests for the PR #97 review (each was a probe that passed while its finding was
//! present; each assertion here is the fixed behaviour).

use humid_htp::cert::Cert;
use humid_htp::client::{Event, Handshake, Session};
use humid_htp::frame::{self, CLASSES};
use humid_htp::msg::{Encoding, HeaderName, Method};
use humid_htp::server::{COVER_MAX_CLASS, Config, Server};
use humid_htp::{CHUNK, Code, Unit, label};
use humid_pq2::MlDsaSigningKey;

const NOW: u64 = 1_798_761_600_000;

fn server(cfg: Config) -> (Server, Cert) {
    let st = MlDsaSigningKey::generate().unwrap();
    let mut srv = Server::new(cfg).unwrap();
    let pk = Server::prepare_key(NOW - 1000, NOW + 86_400_000).unwrap();
    let sig = st
        .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
        .unwrap()
        .to_bytes();
    let cert = Cert::decode(&srv.install_key(pk, &sig).unwrap()).unwrap();
    (srv, cert)
}

fn connect_from(srv: &mut Server, cert: &Cert, net: &str, now: u64) -> Session {
    let (hs, hello) = Handshake::full(Unit::Core, cert, now).unwrap();
    let r = srv.receive_from(&hello, net, now);
    hs.finish(&r.frames).unwrap()
}

fn connect(srv: &mut Server, cert: &Cert) -> Session {
    connect_from(srv, cert, "v4:192.0.2.1", NOW)
}

fn refusals(s: &mut Session, frames: &[u8]) -> Vec<Code> {
    s.receive(frames)
        .unwrap()
        .into_iter()
        .filter_map(|e| match e {
            Event::Refused { code, .. } => Some(code),
            _ => None,
        })
        .collect()
}

/// H-1: a small answer is sealed in the class that fits it (cover only up to
/// COVER_MAX_CLASS), and N pulls of it in one call produce it once, not N times.
#[test]
fn h1_answers_are_not_amplified() {
    let (mut srv, cert) = server(Config::new(Unit::Core));
    let mut s = connect(&mut srv, &cert);
    s.set_min_class(5);
    let (rid, call) = s
        .request(
            Method::Post,
            "/v1/auth/challenge",
            Encoding::Raw,
            &[],
            b"{}",
        )
        .unwrap();
    let r = srv.receive(&call, NOW);
    assert!(
        call.len() <= CLASSES[COVER_MAX_CLASS as usize],
        "the client's cover is capped too"
    );
    let out = srv
        .respond(&r.ready[0].sid, rid, 200, 0, b"{\"challenge\":\"x\"}", NOW)
        .unwrap();
    assert!(
        out.len() <= CLASSES[COVER_MAX_CLASS as usize],
        "a 17-byte answer isn't sealed in a 1 MiB frame: {}",
        out.len()
    );
    s.set_min_class(0);
    let mut pulls = vec![];
    for _ in 0..256 {
        pulls.extend_from_slice(&s.pull(rid, 0).unwrap());
    }
    let r = srv.receive(&pulls, NOW);
    assert!(
        r.frames.len() <= CLASSES[COVER_MAX_CLASS as usize],
        "256 pulls of one answer in one call: one answer back, got {} bytes for a {}-byte call",
        r.frames.len(),
        pulls.len()
    );
}

/// H-1: what one call makes the server emit is bounded, however many distinct answers it
/// pulls.
#[test]
fn h1_output_per_call_is_bounded() {
    let mut cfg = Config::new(Unit::Core);
    cfg.keep_answers = 64;
    let (mut srv, cert) = server(cfg);
    let mut s = connect(&mut srv, &cert);
    let mut rids = vec![];
    for _ in 0..8 {
        let (rid, call) = s
            .request(Method::Get, "/v1/x", Encoding::Raw, &[], b"")
            .unwrap();
        let r = srv.receive(&call, NOW);
        let _ = srv
            .respond(&r.ready[0].sid, rid, 200, 1, &vec![1u8; 512 << 10], NOW)
            .unwrap();
        rids.push(rid);
    }
    let mut pulls = vec![];
    for _ in 0..64 {
        for rid in &rids {
            pulls.extend_from_slice(&s.pull(*rid, 0).unwrap());
        }
    }
    let r = srv.receive(&pulls, NOW);
    assert!(
        r.frames.len() <= humid_htp::server::ANSWER_BUDGET + CLASSES[5],
        "{} bytes out",
        r.frames.len()
    );
}

/// M-4: a call carries at most MAX_FRAMES_PER_CALL frames (the 2000-request call is refused
/// whole), and dispatches at most MAX_READY_PER_CALL requests; the rest are refused.
#[test]
fn m4_requests_per_call_are_capped() {
    let (mut srv, cert) = server(Config::new(Unit::Core));
    let mut s = connect(&mut srv, &cert);
    let mut call = vec![];
    for _ in 0..2000 {
        call.extend_from_slice(
            &s.request(
                Method::Post,
                "/v1/auth/challenge",
                Encoding::Raw,
                &[],
                b"{}",
            )
            .unwrap()
            .1,
        );
    }
    let r = srv.receive(&call, NOW);
    assert!(r.ready.is_empty());
    assert_eq!(
        frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
        Code::TooLarge
    );
    let n = frame::MAX_FRAMES_PER_CALL;
    let mut call = vec![];
    for _ in 0..n {
        call.extend_from_slice(
            &s.request(
                Method::Post,
                "/v1/auth/challenge",
                Encoding::Raw,
                &[],
                b"{}",
            )
            .unwrap()
            .1,
        );
    }
    let r = srv.receive(&call, NOW);
    assert_eq!(r.ready.len(), humid_htp::server::MAX_READY_PER_CALL);
    let refused = refusals(&mut s, &r.frames);
    assert!(refused.iter().all(|c| *c == Code::TooManyInFlight));
    assert_eq!(refused.len(), n - humid_htp::server::MAX_READY_PER_CALL);
}

/// M-2: a request head for a route the unit doesn't serve is refused before any of its
/// body is buffered.
#[test]
fn m2_unknown_routes_buffer_nothing() {
    let (mut srv, cert) = server(Config::new(Unit::Core));
    srv.set_admission(Box::new(|h, _signed_in| {
        if h.path.starts_with("/v1/") {
            Ok(humid_htp::MAX_BODY)
        } else {
            Err(Code::RouteNotFound)
        }
    }));
    let mut a = connect(&mut srv, &cert);
    let (_, call) = a
        .request(
            Method::Post,
            "/not/a/route",
            Encoding::Raw,
            &[],
            &vec![0u8; 3 * CHUNK],
        )
        .unwrap();
    let f = frame::split(&call).unwrap();
    let r = srv.receive(f[0].bytes, NOW);
    assert_eq!(srv.buffered(), 0);
    assert_eq!(refusals(&mut a, &r.frames), [Code::RouteNotFound]);
}

/// M-2: a session that hasn't signed in can't hold more than a small body, and an assembly
/// that stops arriving is dropped, so squatters can't keep others' uploads out.
#[test]
fn m2_assembly_buffer_squatting_is_bounded() {
    let mut cfg = Config::new(Unit::Core);
    cfg.max_buffered = 8 * CHUNK;
    let (mut srv, cert) = server(cfg.clone());
    let mut attacker = connect(&mut srv, &cert);
    let big = vec![0u8; 3 * CHUNK];
    for _ in 0..4 {
        let (_, call) = attacker
            .request(Method::Post, "/v1/objects", Encoding::Raw, &[], &big)
            .unwrap();
        let f = frame::split(&call).unwrap();
        let first_two: Vec<u8> = [f[0].bytes, f[1].bytes].concat();
        let _ = srv.receive(&first_two, NOW);
    }
    assert!(
        srv.buffered() <= cfg.max_unauth_buffered,
        "an anonymous session holds at most {} bytes, held {}",
        cfg.max_unauth_buffered,
        srv.buffered()
    );
    // a keep-alive record doesn't keep a stalled assembly: after assembly_idle_ms it's gone
    let later = NOW + cfg.assembly_idle_ms + 1;
    let (_, ka) = attacker
        .request(Method::Get, "/x", Encoding::Raw, &[], b"")
        .unwrap();
    let _ = srv.receive(&ka, later);
    assert_eq!(srv.buffered(), 0, "a stalled assembly is dropped");
    let mut victim = connect_from(&mut srv, &cert, "v4:198.51.100.9", later);
    let _ = srv.mark_signed_in(&victim.sid(), later).unwrap();
    let (_, call) = victim
        .request(
            Method::Post,
            "/v1/objects",
            Encoding::Raw,
            &[],
            &vec![1u8; CHUNK + 1],
        )
        .unwrap();
    let r = srv.receive(&call, later + 1);
    assert_eq!(r.ready.len(), 1, "the victim's upload goes through");
}

/// M-3: hellos never evict a session that has authenticated a record; past the cap they are
/// refused (or replace sessions that never sent one), and one network has its own cap.
#[test]
fn m3_hellos_do_not_evict_live_sessions() {
    let mut cfg = Config::new(Unit::Core);
    cfg.max_sessions = 4;
    cfg.max_sessions_per_net = 2;
    let (mut srv, cert) = server(cfg);
    let mut victim = connect_from(&mut srv, &cert, "v4:192.0.2.1", NOW);
    let (_, call) = victim
        .request(Method::Get, "/v1/me", Encoding::Raw, &[], b"")
        .unwrap();
    assert_eq!(srv.receive(&call, NOW).ready.len(), 1);
    // one attacker network: its own cap
    let mut codes = vec![];
    for _ in 0..4 {
        let (_hs, hello) = Handshake::full(Unit::Core, &cert, NOW).unwrap();
        let r = srv.receive_from(&hello, "v4:203.0.113.7", NOW + 1);
        let f = frame::split(&r.frames).unwrap();
        codes.push(f[0].error_code().ok());
    }
    assert_eq!(codes[..2], [None, None]);
    assert_eq!(codes[2..], [Some(Code::Busy), Some(Code::Busy)]);
    // many networks: never the victim
    for i in 0..10 {
        let (_hs, hello) = Handshake::full(Unit::Core, &cert, NOW).unwrap();
        let _ = srv.receive_from(&hello, &format!("v4:198.51.100.{i}"), NOW + 2);
    }
    assert!(srv.has_session(&victim.sid()));
    assert!(srv.session_count() <= 4);
}

/// M-3 (the probe's exact case): a session just made, that hasn't sent a request yet, isn't
/// evicted by a flood of hellos either; they are refused `busy` until its grace has passed.
#[test]
fn m3_a_fresh_session_is_not_evicted_by_a_hello_flood() {
    let mut cfg = Config::new(Unit::Core);
    cfg.max_sessions = 4;
    let (mut srv, cert) = server(cfg);
    let victim = connect(&mut srv, &cert);
    for i in 0..4 {
        let (_hs, hello) = Handshake::full(Unit::Core, &cert, NOW).unwrap();
        let _ = srv.receive_from(&hello, &format!("v4:203.0.113.{i}"), NOW + 1);
    }
    assert!(srv.has_session(&victim.sid()));
    assert!(srv.session_count() <= 4);
}

/// M-6: the client refuses a certificate outside its dates.
#[test]
fn m6_an_expired_certificate_is_refused_by_the_client() {
    let (_srv, cert) = server(Config::new(Unit::Core));
    let much_later = cert.not_after + 30 * 86_400_000;
    assert_eq!(
        Handshake::full(Unit::Core, &cert, much_later).err(),
        Some(Code::BadCert)
    );
    assert_eq!(
        Handshake::full(Unit::Core, &cert, cert.not_before - 86_400_000).err(),
        Some(Code::BadCert)
    );
}

/// L-5: a request id whose answer is kept isn't answered with it for another request; and an
/// id reserved before a burst of newer requests still works afterwards.
#[test]
fn l5_request_id_edge_cases() {
    let (mut srv, cert) = server(Config::new(Unit::Core));
    let mut s = connect(&mut srv, &cert);
    let reserved = s.reserve().unwrap();
    let (rid, call) = s
        .request(Method::Get, "/v1/me", Encoding::Raw, &[], b"")
        .unwrap();
    let r = srv.receive(&call, NOW);
    let _ = srv
        .respond(&r.ready[0].sid, rid, 200, 0, b"{\"secret\":1}", NOW)
        .unwrap();
    // the same id, another head (a reordering client, or a forged replay of the id)
    let mut other = connect(&mut srv, &cert); // a raw message under s's keys isn't public: reuse s
    drop(other.take_ticket());
    let (_, again) = s
        .request_with_id(rid, Method::Post, "/v1/sync", Encoding::Raw, &[], b"{}")
        .unwrap();
    let r = srv.receive(&again, NOW);
    assert_eq!(refusals(&mut s, &r.frames), [Code::RidReused]);
    // 2000 newer requests, then the reserved one
    for _ in 0..2000 {
        let (_, call) = s
            .request(Method::Get, "/v1/me", Encoding::Raw, &[], b"")
            .unwrap();
        let _ = srv.receive(&call, NOW);
    }
    let (_, call) = s
        .request_reserved(reserved, Method::Get, "/v1/me", Encoding::Raw, &[], b"")
        .unwrap();
    assert_eq!(srv.receive(&call, NOW).ready.len(), 1);
}

/// L-6: a refusal and an ack travel in the request's (capped) class, not always class 0.
#[test]
fn l6_refusals_use_the_requests_class() {
    let (mut srv, cert) = server(Config::new(Unit::Core));
    srv.set_admission(Box::new(|_, _| Err(Code::RouteNotFound)));
    let mut s = connect(&mut srv, &cert);
    s.set_min_class(2);
    let (_, call) = s
        .request(
            Method::Get,
            "/v1/me",
            Encoding::Raw,
            &[(HeaderName::Session, b"t")],
            b"",
        )
        .unwrap();
    let r = srv.receive(&call, NOW);
    assert_eq!(r.frames.len(), CLASSES[2]);
}
