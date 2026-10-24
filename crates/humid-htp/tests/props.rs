//! Property tests over the whole client/server pair (HTP2.md §10): round trip, tamper,
//! replay, reorder, truncation, wrong session, downgrade, resumption, chunked resume.

use humid_htp::cert::{Bundle, Cert};
use humid_htp::client::{Event, Handshake, Session};
use humid_htp::frame::{self, HEADER_LEN, Header, Kind};
use humid_htp::msg::{Encoding, HeaderName, Method};
use humid_htp::server::{Config, Server};
use humid_htp::{CHUNK, Code, Unit, label};
use humid_pq2::{DualSigningKey, MlDsaSigningKey};
use proptest::prelude::*;

const NOW: u64 = 1_798_761_600_000;

struct World {
    server: Server,
    cert: Cert,
    root: DualSigningKey,
    bundle: Bundle,
    st_vk: Vec<u8>,
}

fn world() -> World {
    let root = DualSigningKey::generate().unwrap();
    let st = MlDsaSigningKey::generate().unwrap();
    let mut server = Server::new(Config::new(Unit::Core)).unwrap();
    let pk = Server::prepare_key(NOW - 1000, NOW + 86_400_000).unwrap();
    let sig = st
        .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
        .unwrap()
        .to_bytes();
    let cert_bytes = server.install_key(pk, &sig).unwrap();
    let policy = b"{\"test\":true}".to_vec();
    let psig = root
        .sign(label::POLICY, &humid_pq2::encoding::lp(&[&policy]).unwrap())
        .unwrap()
        .to_bytes();
    let bundle = Bundle {
        policy,
        policy_sig: psig,
        certs: vec![cert_bytes],
    };
    let st_vk = st.verifying_key().to_bytes();
    let cert = bundle
        .verified(root.verifying_key(), Unit::Core, NOW, |_, _| {
            Some(st_vk.clone())
        })
        .unwrap();
    World {
        server,
        cert,
        root,
        bundle,
        st_vk,
    }
}

fn connect(w: &mut World) -> Session {
    let (hs, hello) = Handshake::full(Unit::Core, &w.cert, NOW).unwrap();
    let r = w.server.receive(&hello, NOW);
    hs.finish(&r.frames).unwrap()
}

/// One request through the server, answered with `answer(body)`.
fn exchange(w: &mut World, s: &mut Session, body: &[u8], now: u64) -> Vec<Event> {
    let (_, call) = s
        .request(
            Method::Post,
            "/v1/echo",
            Encoding::Raw,
            &[(HeaderName::Session, b"tok")],
            body,
        )
        .unwrap();
    let r = w.server.receive(&call, now);
    let mut out = r.frames;
    for req in r.ready {
        let mut ans = req.body.to_vec();
        ans.reverse();
        out.extend_from_slice(
            &w.server
                .respond(&req.sid, req.head.rid, 200, 1, &ans, now)
                .unwrap(),
        );
    }
    s.receive(&out).unwrap()
}

fn body_of(ev: &[Event]) -> Option<Vec<u8>> {
    ev.iter().find_map(|e| match e {
        Event::Response { body, .. } => Some(body.to_vec()),
        _ => None,
    })
}

#[test]
fn bundle_verifies_under_the_pinned_root_only() {
    let w = world();
    let other = DualSigningKey::generate().unwrap();
    assert!(
        w.bundle
            .verified(other.verifying_key(), Unit::Core, NOW, |_, _| Some(
                w.st_vk.clone()
            ))
            .is_err()
    );
    assert!(
        w.bundle
            .verified(w.root.verifying_key(), Unit::Anon, NOW, |_, _| Some(
                w.st_vk.clone()
            ))
            .is_err()
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, .. ProptestConfig::default() })]

    #[test]
    fn round_trip(bodies in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..3000), 1..5)) {
        let mut w = world();
        let mut s = connect(&mut w);
        for b in bodies {
            let ev = exchange(&mut w, &mut s, &b, NOW);
            let mut want = b.clone();
            want.reverse();
            prop_assert_eq!(body_of(&ev), Some(want));
        }
    }

    #[test]
    fn any_flipped_bit_is_refused_and_does_not_burn_the_record(byte in 0usize..1024, bit in 0u8..8) {
        let mut w = world();
        let mut s = connect(&mut w);
        let (_, call) = s.request(Method::Post, "/v1/echo", Encoding::Raw, &[], b"hello").unwrap();
        let mut bad = call.clone();
        let i = byte % bad.len();
        bad[i] ^= 1 << bit;
        let r = w.server.receive(&bad, NOW);
        prop_assert!(r.ready.is_empty(), "a tampered record never reaches the unit");
        // the genuine record still opens afterwards (a forgery doesn't consume its seq)
        let r = w.server.receive(&call, NOW);
        prop_assert_eq!(r.ready.len(), 1);
        prop_assert_eq!(&r.ready[0].body[..], b"hello");
    }

    #[test]
    fn truncation_is_refused(cut in 1usize..1024) {
        let mut w = world();
        let mut s = connect(&mut w);
        let (_, call) = s.request(Method::Post, "/v1/echo", Encoding::Raw, &[], b"x").unwrap();
        let r = w.server.receive(&call[..call.len() - cut.min(call.len() - 1)], NOW);
        prop_assert!(r.ready.is_empty());
        prop_assert_eq!(frame::split(&r.frames).unwrap()[0].error_code().unwrap(), Code::BadFrame);
    }
}

#[test]
fn replay_and_reorder() {
    let mut w = world();
    let mut s = connect(&mut w);
    let (_, a) = s
        .request(Method::Post, "/v1/echo", Encoding::Raw, &[], b"a")
        .unwrap();
    let (_, b) = s
        .request(Method::Post, "/v1/echo", Encoding::Raw, &[], b"b")
        .unwrap();
    // reordered: b before a, both accepted once
    assert_eq!(&w.server.receive(&b, NOW).ready[0].body[..], b"b");
    assert_eq!(&w.server.receive(&a, NOW).ready[0].body[..], b"a");
    // replayed: refused, unauthenticated
    for call in [&a, &b] {
        let r = w.server.receive(call, NOW);
        assert!(r.ready.is_empty());
        assert_eq!(
            frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
            Code::Replay
        );
    }
    // the same request id in a new record (a client bug or a malicious core): refused
    let mut s2 = connect(&mut w);
    let (rid, c1) = s2
        .request(Method::Post, "/v1/echo", Encoding::Raw, &[], b"1")
        .unwrap();
    let r = w.server.receive(&c1, NOW);
    assert_eq!(r.ready.len(), 1);
    let resent = s2.resend(rid, 0);
    assert!(
        resent.is_ok(),
        "the client can resend while it hasn't seen the answer"
    );
    let r2 = w.server.receive(&resent.unwrap(), NOW);
    assert!(r2.ready.is_empty(), "nothing runs twice");
}

#[test]
fn a_record_from_another_session_is_refused() {
    let mut w = world();
    let mut s1 = connect(&mut w);
    let s2 = connect(&mut w);
    let (_, call) = s1
        .request(Method::Post, "/v1/echo", Encoding::Raw, &[], b"x")
        .unwrap();
    // front relabels the record with the other session's id
    let mut moved = call.clone();
    moved[8..24].copy_from_slice(&s2.sid());
    let r = w.server.receive(&moved, NOW);
    assert!(r.ready.is_empty());
    assert_eq!(
        frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
        Code::BadRecord
    );
    // and an unknown session id
    let mut unknown = call.clone();
    unknown[8..24].copy_from_slice(&[0xEE; 16]);
    let r = w.server.receive(&unknown, NOW);
    assert_eq!(
        frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
        Code::SessionUnknown
    );
    // the right one still works
    assert_eq!(w.server.receive(&call, NOW).ready.len(), 1);
}

#[test]
fn downgrade_and_version() {
    let mut w = world();
    let (hs, hello) = Handshake::full(Unit::Core, &w.cert, NOW).unwrap();
    for v in [0u8, 2, 0xFF] {
        let mut h = hello.clone();
        h[2] = v;
        let r = w.server.receive(&h, NOW);
        assert_eq!(
            frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
            Code::VersionUnsupported
        );
    }
    // a "reply" an attacker builds without the server key: the confirmation fails
    let r = w.server.receive(&hello, NOW);
    let mut forged = r.frames.clone();
    forged[HEADER_LEN + 4 + 40] ^= 1; // inside ct_c
    assert!(hs.finish(&forged).is_err());
    // a hello to a key the server doesn't hold
    let (_, hello2) = Handshake::full(Unit::Core, &w.cert, NOW).unwrap();
    let mut h = hello2.clone();
    h[HEADER_LEN + 4] ^= 1; // kid
    assert_eq!(
        frame::split(&w.server.receive(&h, NOW).frames).unwrap()[0]
            .error_code()
            .unwrap(),
        Code::KeyUnknown
    );
    // a hello replayed: refused (the server never does the handshake twice for one nonce)
    let r = w.server.receive(&hello2, NOW);
    assert_eq!(frame::split(&r.frames).unwrap()[0].header.kind, Kind::Reply);
    let r = w.server.receive(&hello2, NOW);
    assert_eq!(
        frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
        Code::Replay
    );
    // a stale hello
    let (_, old) = Handshake::full(Unit::Core, &w.cert, NOW - 6 * 60_000).unwrap();
    assert_eq!(
        frame::split(&w.server.receive(&old, NOW).frames).unwrap()[0]
            .error_code()
            .unwrap(),
        Code::StaleHello
    );
    // a hello for another unit, sent to this one
    let mut wrong_unit = hello2;
    wrong_unit[4] = Unit::Anon.to_u8();
    assert_eq!(
        frame::split(&w.server.receive(&wrong_unit, NOW).frames).unwrap()[0]
            .error_code()
            .unwrap(),
        Code::UnitUnknown
    );
}

#[test]
fn unauthenticated_errors_do_not_change_the_session() {
    let mut w = world();
    let mut s = connect(&mut w);
    let fake = frame::error(Unit::Core, s.sid(), Code::SessionUnknown);
    assert_eq!(s.receive(&fake).err(), Some(Code::SessionUnknown));
    // the session still works: the app treats it as a hint, and its next call proves it
    let ev = exchange(&mut w, &mut s, b"still here", NOW);
    assert!(body_of(&ev).is_some());
}

#[test]
fn resumption_keeps_the_chain_transcript_and_tickets_are_single_use() {
    let mut w = world();
    let mut s = connect(&mut w);
    let th = s.th();
    let t = s.take_ticket().unwrap();
    let (hs, call) = Handshake::resume(t, NOW + 1000).unwrap();
    let r = w.server.receive(&call, NOW + 1000);
    let mut s2 = hs.finish(&r.frames).unwrap();
    assert_eq!(
        s2.th(),
        th,
        "sign-ins stay bound to the chain's full handshake"
    );
    assert_ne!(s2.sid(), s.sid());
    assert_eq!(
        s2.proof_seq(1),
        (1u64 << 32) | 1,
        "a resumed session's proofs can't match an earlier session's"
    );
    assert!(body_of(&exchange(&mut w, &mut s2, b"r", NOW + 1000)).is_some());
    // the same ticket again: refused
    let r = w.server.receive(&call, NOW + 2000);
    let code = frame::split(&r.frames).unwrap()[0].error_code().unwrap();
    assert!(code == Code::TicketUnknown || code == Code::Replay);
    // a ticket past the chain's lifetime: refused
    let t2 = s2.take_ticket().unwrap();
    let late = NOW + 8 * 3_600_000 + 1;
    let (_, call) = Handshake::resume(Ticket2::extend(t2), late).unwrap();
    let r = w.server.receive(&call, late);
    assert_eq!(
        frame::split(&r.frames).unwrap()[0].error_code().unwrap(),
        Code::TicketUnknown
    );
}

/// A test helper: pretend the client clock thinks a ticket is still good.
struct Ticket2;
impl Ticket2 {
    fn extend(mut t: humid_htp::client::Ticket) -> humid_htp::client::Ticket {
        t.expires_at = u64::MAX;
        t
    }
}

#[test]
fn large_bodies_travel_in_1_mib_chunks_and_resume_after_a_cut() {
    let mut w = world();
    let mut s = connect(&mut w);
    let _ = w.server.mark_signed_in(&s.sid(), NOW).unwrap(); // large bodies: a signed-in session
    let body: Vec<u8> = (0..(5 * CHUNK / 2)).map(|i| (i % 251) as u8).collect();
    let (rid, call) = s
        .request(Method::Post, "/v1/objects", Encoding::Raw, &[], &body)
        .unwrap();
    let frames = frame::split(&call).unwrap();
    assert_eq!(frames.len(), 3, "three chunks");
    for f in &frames {
        assert_eq!(
            f.bytes.len(),
            frame::CLASSES[5],
            "full chunks use the top class"
        );
    }
    // the call is cut after the first chunk: the server acks what it has
    let first = frames[0].bytes.to_vec();
    let r = w.server.receive(&first, NOW);
    assert!(r.ready.is_empty());
    let ev = s.receive(&r.frames).unwrap();
    let next = ev
        .iter()
        .find_map(|e| match e {
            Event::Ack { next, .. } => Some(*next),
            _ => None,
        })
        .unwrap();
    assert_eq!(next, 1);
    let rest = s.resend(rid, next).unwrap();
    let r = w.server.receive(&rest, NOW);
    assert_eq!(r.ready.len(), 1);
    assert_eq!(&r.ready[0].body[..], &body[..]);
    // a large answer, cut after its head: pull the rest, no new request
    let req = &r.ready[0];
    let out = w.server.respond(&req.sid, rid, 200, 1, &body, NOW).unwrap();
    let fs = frame::split(&out).unwrap();
    assert_eq!(fs.len(), 3);
    let ev = s.receive(fs[0].bytes).unwrap();
    let next = ev
        .iter()
        .find_map(|e| match e {
            Event::Partial { next, .. } => Some(*next),
            _ => None,
        })
        .unwrap();
    assert_eq!(next, 1);
    let pull = s.pull(rid, next).unwrap();
    let r = w.server.receive(&pull, NOW + 500);
    let ev = s.receive(&r.frames).unwrap();
    assert_eq!(body_of(&ev).unwrap(), body);
}

#[test]
fn size_classes_hide_small_differences() {
    let mut w = world();
    let mut s = connect(&mut w);
    let (_, a) = s
        .request(Method::Get, "/v1/me", Encoding::Raw, &[], b"")
        .unwrap();
    let (_, b) = s
        .request(Method::Post, "/v1/sync", Encoding::Raw, &[], &[7; 600])
        .unwrap();
    assert_eq!(a.len(), b.len(), "both in the 1 KiB class");
    s.set_min_class(2);
    let (_, c) = s
        .request(Method::Get, "/v1/me", Encoding::Raw, &[], b"")
        .unwrap();
    assert_eq!(c.len(), frame::CLASSES[2]);
    let h = Header::decode(&c).unwrap();
    assert_eq!(h.class, 2);
}

#[test]
fn the_server_bounds_what_it_buffers() {
    let mut cfg = Config::new(Unit::Core);
    cfg.max_in_flight = 2;
    let mut w = world();
    w.server = {
        let st = MlDsaSigningKey::generate().unwrap();
        let mut srv = Server::new(cfg).unwrap();
        let pk = Server::prepare_key(NOW - 1000, NOW + 86_400_000).unwrap();
        let sig = st
            .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
            .unwrap()
            .to_bytes();
        let c = srv.install_key(pk, &sig).unwrap();
        w.cert = Cert::decode(&c).unwrap();
        srv
    };
    let mut s = connect(&mut w);
    let _ = w.server.mark_signed_in(&s.sid(), NOW).unwrap();
    let big = vec![0u8; CHUNK + 1];
    for _ in 0..2 {
        let (_, call) = s
            .request(Method::Post, "/v1/objects", Encoding::Raw, &[], &big)
            .unwrap();
        let f = frame::split(&call).unwrap();
        let _ = w.server.receive(f[0].bytes, NOW);
    }
    let (rid, call) = s
        .request(Method::Post, "/v1/objects", Encoding::Raw, &[], &big)
        .unwrap();
    let f = frame::split(&call).unwrap();
    let r = w.server.receive(f[0].bytes, NOW);
    let ev = s.receive(&r.frames).unwrap();
    assert!(
        ev.iter().any(
            |e| matches!(e, Event::Refused { rid: x, code: Code::TooManyInFlight } if *x == rid)
        )
    );
    assert!(w.server.buffered() <= 2 * CHUNK);
    // idle sessions end, and their buffers with them
    w.server.tick(NOW + 16 * 60_000);
    assert_eq!(w.server.session_count(), 0);
    assert_eq!(w.server.buffered(), 0);
}
