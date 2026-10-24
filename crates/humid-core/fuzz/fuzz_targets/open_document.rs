#![no_main]
//! The streaming envelope reader on arbitrary bytes, through the real core: a fuzzed slot
//! and a fuzzed envelope never panic and never open, and nothing is written to the viewer
//! unless a chunk authenticated (none can here).
use std::sync::Mutex;
use std::sync::OnceLock;

use humid_core::gate::{Prompt, Purpose};
use humid_core::soft_gate::{SoftGate, SoftMode};
use humid_core::store::MemStore;
use humid_core::{Core, DocMeta};
use humid_pq2::KemSecretKey;
use libfuzzer_sys::fuzz_target;

struct W {
    core: Core<SoftGate, MemStore>,
    slot: Vec<u8>,
}

static W: OnceLock<Mutex<W>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let w = W.get_or_init(|| {
        let mut core = Core::new(
            SoftGate::new(SoftMode::PublicTarget, 8),
            MemStore::default(),
        )
        .expect("core");
        let p = Prompt::new(Purpose::Seal, "fuzz");
        core.enroll(&p, b"").expect("enroll");
        let ks = KemSecretKey::generate().expect("rng");
        let meta = DocMeta {
            name: "f".into(),
            media_type: "t".into(),
        };
        let r = core
            .seal_document(
                &p,
                &meta,
                &mut &b"seed"[..],
                &mut Vec::new(),
                ks.public_key(),
                b"",
            )
            .expect("seal");
        Mutex::new(W { core, slot: r.slot })
    });
    let mut w = w.lock().expect("lock");
    let slot = w.slot.clone();
    let p = Prompt::new(Purpose::Open, "fuzz");
    // a fuzzed slot
    let _ = w.core.begin_open(&p, data, b"");
    // a real slot, a fuzzed share and a fuzzed envelope
    if let Ok(st) = w.core.begin_open(&p, &slot, b"") {
        let (share, env) = data.split_at(data.len().min(1661));
        let mut view = Vec::new();
        assert!(
            w.core
                .finish_open(st.handle, share, &mut &env[..], &mut view)
                .is_err()
        );
        assert!(view.is_empty());
    }
});
