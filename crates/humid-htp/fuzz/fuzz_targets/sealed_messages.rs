#![no_main]
//! The server past its AEAD (review #97 L-4): fuzzer-chosen message bytes, sealed under a
//! genuine client session's keys, in fuzzer-chosen calls against one long-lived server. This
//! reaches assembly, acks, pulls, kept answers, admission and the per-call bounds. Invariants:
//! never panics; the bytes one call makes the server emit stay within its budget; buffered and
//! kept bytes stay within their caps; every request the server hands on has a body matching
//! its announced hash; and the client decodes whatever comes back without panicking.
//!
//! Input: a sequence of `u8 op ‖ u16 len ‖ bytes`. op & 3 = 0: a message sealed as is;
//! 1: a REQUEST head built from the bytes; 2: a PULL; 3: end the call. Bit 2 of op answers
//! the call's ready requests with a fuzzed-size body; bit 3 advances the clock a minute.

use std::sync::{Mutex, OnceLock};

use humid_htp::client::{Handshake, Session};
use humid_htp::msg::{Encoding, Method, Msg, RequestHead};
use humid_htp::server::{ANSWER_BUDGET, Config, MAX_KEPT_BYTES, Server};
use humid_htp::{Unit, frame, label};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_798_761_600_000;

struct World {
    srv: Server,
    s: Session,
    now: u64,
    cfg: Config,
}

fn world() -> &'static Mutex<World> {
    static W: OnceLock<Mutex<World>> = OnceLock::new();
    W.get_or_init(|| {
        let mut cfg = Config::new(Unit::Core);
        cfg.max_buffered = 32 << 20;
        let st = humid_pq2::MlDsaSigningKey::generate().expect("key");
        let mut srv = Server::new(cfg.clone()).expect("server");
        srv.set_admission(Box::new(|h, signed_in| {
            if !h.path.starts_with("/v1/") {
                return Err(humid_htp::Code::RouteNotFound);
            }
            Ok(if signed_in { 8 << 20 } else { 256 << 10 })
        }));
        let pk = Server::prepare_key(NOW - 1, NOW + 2 * 86_400_000).expect("kem");
        let sig = st
            .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
            .expect("sign")
            .to_bytes();
        let cert = humid_htp::cert::Cert::decode(&srv.install_key(pk, &sig).expect("install"))
            .expect("cert");
        let (hs, hello) = Handshake::full(Unit::Core, &cert, NOW).expect("hello");
        let r = srv.receive(&hello, NOW);
        let s = hs.finish(&r.frames).expect("finish");
        let _ = srv.mark_signed_in(&s.sid(), NOW);
        Mutex::new(World {
            srv,
            s,
            now: NOW,
            cfg,
        })
    })
}

fn head_from(b: &[u8]) -> Msg {
    let rid = u32::from(b.first().copied().unwrap_or(1)).max(1);
    let len = u64::from(u16::from_be_bytes([
        b.get(1).copied().unwrap_or(0),
        b.get(2).copied().unwrap_or(0),
    ])) * 64;
    let path = if b.get(3).is_some_and(|x| x & 1 == 1) {
        "/v1/objects"
    } else {
        "/nope"
    };
    let c0 = vec![7u8; usize::try_from(len.min(humid_htp::CHUNK as u64)).unwrap_or(0)];
    Msg::Request(
        RequestHead {
            rid,
            method: Method::Post,
            enc: Encoding::Raw,
            headers: vec![],
            path: path.into(),
            body_len: len,
            body_hash: humid_pq2::sha3_512(&c0),
        },
        c0,
    )
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut w) = world().lock() else { return };
    let mut call = vec![];
    let mut rest = data;
    while rest.len() >= 3 {
        let op = rest[0];
        let n = usize::from(u16::from_be_bytes([rest[1], rest[2]])).min(rest.len() - 3);
        let bytes = &rest[3..3 + n];
        rest = &rest[3 + n..];
        let class = (op >> 4) & 7;
        let sealed = match op & 3 {
            0 => w.s.seal_raw(bytes, class),
            1 => w.s.seal_raw(&head_from(bytes).encode(), class),
            2 => {
                let rid = u32::from(bytes.first().copied().unwrap_or(1));
                w.s.pull(rid, u32::from(bytes.get(1).copied().unwrap_or(0)))
            }
            _ => Ok(vec![]),
        };
        if let Ok(f) = sealed {
            call.extend_from_slice(&f);
        }
        if op & 3 == 3 || rest.len() < 3 {
            if op & 8 != 0 {
                // the clock moves, and wraps inside the certificate (and the idle limit)
                w.now = NOW + (w.now - NOW + 60_000) % (10 * 60_000);
            }
            if call.is_empty() {
                continue;
            }
            let now = w.now;
            let r = w.srv.receive(&call, now);
            let mut out = r.frames;
            for req in &r.ready {
                assert_eq!(
                    humid_pq2::sha3_512(&req.body),
                    req.head.body_hash,
                    "only whole, matching bodies are handed on"
                );
            }
            if op & 4 != 0 {
                for req in r.ready {
                    let size = usize::from(bytes.first().copied().unwrap_or(0)) << 12;
                    if let Ok(a) =
                        w.srv
                            .respond(&req.sid, req.head.rid, 200, 1, &vec![1; size], now)
                    {
                        out.extend_from_slice(&a);
                    }
                }
            }
            assert!(
                out.len()
                    <= ANSWER_BUDGET
                        + frame::MAX_FRAMES_PER_CALL * frame::CLASSES[5] / 4
                        + (16 << 20),
                "one call's output is bounded: {}",
                out.len()
            );
            assert!(w.srv.buffered() <= w.cfg.max_buffered);
            assert!(w.srv.kept() <= MAX_KEPT_BYTES);
            let _ = w.s.receive(&out);
            call.clear();
        }
    }
});
