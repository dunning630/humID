#![allow(clippy::cast_possible_truncation)]
//! Property tests: random documents round-trip; any single-bit change to an envelope is
//! caught; the ratchet only moves forward over random unlock / crash / restore schedules.

use humid_core::gate::{Prompt, Purpose};
use humid_core::soft_gate::{SoftGate, SoftMode};
use humid_core::store::MemStore;
use humid_core::{Core, CoreError, DocMeta};
use humid_pq2::{KemSecretKey, ShareDirection, open_share, seal_share};
use proptest::prelude::*;

fn pr() -> Prompt {
    Prompt::new(Purpose::Open, "t")
}

struct World {
    c: Core<SoftGate, MemStore>,
    ks: KemSecretKey,
}

fn world() -> World {
    let mut c = Core::new(
        SoftGate::new(SoftMode::PublicTarget, 8),
        MemStore::default(),
    )
    .unwrap();
    c.enroll(&pr(), b"").unwrap();
    World {
        c,
        ks: KemSecretKey::generate().unwrap(),
    }
}

fn seal(w: &mut World, data: &[u8]) -> (Vec<u8>, Vec<u8>, humid_pq2::Secret32, [u8; 32], [u8; 64]) {
    let mut env = Vec::new();
    let meta = DocMeta {
        name: "f".into(),
        media_type: "t".into(),
    };
    let r =
        w.c.seal_document(
            &pr(),
            &meta,
            &mut &data[..],
            &mut env,
            w.ks.public_key(),
            b"",
        )
        .unwrap();
    let acct = w.c.identity().unwrap().account_id();
    let share = open_share(
        ShareDirection::Upload,
        &w.ks,
        &acct,
        &r.doc_id,
        &r.manifest_hash,
        &r.share_upload,
    )
    .unwrap();
    (env, r.slot, share, r.doc_id, r.manifest_hash)
}

fn open(
    w: &mut World,
    slot: &[u8],
    share: &humid_pq2::Secret32,
    env: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let st = w.c.begin_open(&pr(), slot, b"")?;
    let req = humid_core::envelope::ShareRequest::decode(&st.share_request).unwrap();
    let sealed = seal_share(
        ShareDirection::Release,
        &req.one_time,
        &req.account_id,
        &req.doc_id,
        &req.binding().unwrap(),
        share,
    )
    .unwrap();
    let mut v = Vec::new();
    w.c.finish_open(st.handle, &sealed, &mut &env[..], &mut v)?;
    Ok(v)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn documents_round_trip(data in proptest::collection::vec(any::<u8>(), 0..300_000)) {
        let mut w = world();
        let (env, slot, share, _, _) = seal(&mut w, &data);
        prop_assert_eq!(open(&mut w, &slot, &share, &env).unwrap(), data);
    }

    #[test]
    fn any_bit_flip_is_caught(len in 0usize..150_000, pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut w = world();
        let data = vec![0x42u8; len];
        let (mut env, slot, share, _, _) = seal(&mut w, &data);
        let i = pos.index(env.len());
        env[i] ^= 1 << bit;
        let r = open(&mut w, &slot, &share, &env);
        prop_assert!(r.is_err(), "flip at {} of {} opened", i, env.len());
    }

    #[test]
    fn ratchet_only_moves_forward(ops in proptest::collection::vec(0u8..4, 1..12)) {
        let mut c = Core::new(SoftGate::new(SoftMode::ImportedKey, 8), MemStore::default()).unwrap();
        c.enroll(&pr(), b"").unwrap();
        c.lock();
        let mut images = vec![c.store().clone()];
        let mut high = 0u64;
        for op in ops {
            match op {
                // unlock
                0 | 1 => {
                    let u = c.unlock(&pr(), b"").unwrap();
                    prop_assert!(u.wrap_counter >= high);
                    high = u.wrap_counter;
                    c.lock();
                    images.push(c.store().clone());
                }
                // a failed write during unlock
                2 => {
                    c.store_mut().fail_next_write = true;
                    let u = c.unlock(&pr(), b"").unwrap();
                    prop_assert_eq!(u.wrap_counter, high);
                    c.lock();
                }
                // restore an old image of the files (not the floor): refused if older
                _ => {
                    let floor = c.store().floor;
                    let saved = c.store().clone();
                    let old = images[0].clone();
                    *c.store_mut() = MemStore { floor, ..old };
                    if high > 0 {
                        prop_assert_eq!(c.unlock(&pr(), b"").unwrap_err(), CoreError::Rollback);
                    }
                    *c.store_mut() = saved;
                }
            }
        }
    }
}
