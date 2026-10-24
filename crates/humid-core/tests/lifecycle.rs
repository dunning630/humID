#![allow(clippy::cast_possible_truncation)]
//! The core's lifecycle against the software gate: enrol, unlock and ratchet, rollback
//! refusal, three-key documents, both share directions, adding a device, decoy, lock.

use humid_core::gate::{GateError, Prompt, Purpose};
use humid_core::soft_gate::{SoftGate, SoftMode};
use humid_core::store::{DeviceStore, MemStore};
use humid_core::{Core, CoreError, DocMeta};
use humid_pq2::{KemSecretKey, ShareDirection, open_share, seal_share};

type C = Core<SoftGate, MemStore>;

fn p(purpose: Purpose) -> Prompt {
    Prompt::new(purpose, "test")
}

fn core(mode: SoftMode) -> C {
    Core::new(SoftGate::new(mode, 8), MemStore::default()).unwrap()
}

const MODES: [SoftMode; 3] = [
    SoftMode::PublicTarget,
    SoftMode::ImportedKey,
    SoftMode::SymmetricInput,
];

/// A stand-in key-share service: stores uploaded shares, releases them to the request's key.
struct KeyService {
    sk: KemSecretKey,
    shares: std::collections::BTreeMap<[u8; 32], humid_pq2::Secret32>,
}

impl KeyService {
    fn new() -> Self {
        Self {
            sk: KemSecretKey::generate().unwrap(),
            shares: Default::default(),
        }
    }
    fn upload(&mut self, account: &[u8; 32], doc: [u8; 32], mh: &[u8; 64], sealed: &[u8]) {
        let s = open_share(ShareDirection::Upload, &self.sk, account, &doc, mh, sealed).unwrap();
        self.shares.insert(doc, s);
    }
    fn release(&self, request: &[u8]) -> Vec<u8> {
        let req = humid_core::envelope::ShareRequest::decode(request).unwrap();
        let s = &self.shares[&req.doc_id];
        seal_share(
            ShareDirection::Release,
            &req.one_time,
            &req.account_id,
            &req.doc_id,
            &req.binding().unwrap(),
            s,
        )
        .unwrap()
    }
}

struct Doc {
    envelope: Vec<u8>,
    slot: Vec<u8>,
}

fn seal(c: &mut C, ks: &mut KeyService, data: &[u8]) -> Doc {
    let mut env = Vec::new();
    let meta = DocMeta {
        name: "passport.pdf".into(),
        media_type: "application/pdf".into(),
    };
    let before = c.gate().prompts;
    let r = c
        .seal_document(
            &p(Purpose::Seal),
            &meta,
            &mut &data[..],
            &mut env,
            ks.sk.public_key(),
            b"ch",
        )
        .unwrap();
    assert_eq!(c.gate().prompts, before + 1, "sealing is one prompt");
    assert!(!r.live.sigs.is_empty());
    let acct = c.identity().unwrap().account_id();
    ks.upload(&acct, r.doc_id, &r.manifest_hash, &r.share_upload);
    Doc {
        envelope: env,
        slot: r.slot,
    }
}

fn open(c: &mut C, ks: &KeyService, slot: &[u8], env: &[u8]) -> Result<Vec<u8>, CoreError> {
    let before = c.gate().prompts;
    let st = c.begin_open(&p(Purpose::Open), slot, b"ch")?;
    assert_eq!(c.gate().prompts, before + 1, "opening is one prompt");
    let share = ks.release(&st.share_request);
    let mut view = Vec::new();
    let o = c.finish_open(st.handle, &share, &mut &env[..], &mut view)?;
    assert_eq!(o.size, view.len() as u64);
    assert_eq!(o.meta.name, "passport.pdf");
    Ok(view)
}

#[test]
fn enroll_unlock_ratchet_one_prompt_each() {
    for mode in MODES {
        let mut c = core(mode);
        let id = c.enroll(&p(Purpose::Enroll), b"ch").unwrap().identity;
        assert_eq!(c.gate().prompts, 1);
        c.lock();
        let mut last = 0;
        for i in 0..5 {
            let u = c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
            assert_eq!(c.gate().prompts, 2 + i, "{mode:?}: one prompt per unlock");
            assert_eq!(u.identity, id);
            assert!(u.advanced);
            assert_eq!(u.wrap_counter, i as u64 + 1);
            assert!(u.wrap_counter > last || i == 0);
            last = u.wrap_counter;
            // exactly one wrap on disk after each unlock, at the floor
            let wraps: Vec<_> = ["wrap-0", "wrap-1"]
                .iter()
                .filter(|n| c.store().files.contains_key(**n))
                .collect();
            assert_eq!(wraps.len(), 1);
            assert_eq!(c.store().floor, u.wrap_counter);
            c.lock();
        }
        assert!(
            c.gate().max_ops_seen <= 3,
            "{mode:?}: at most HW_n, HW_n+1 and the live signature"
        );
    }
}

#[test]
fn old_wraps_are_unusable_after_the_ratchet() {
    for mode in MODES {
        let mut c = core(mode);
        c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
        c.lock();
        let image = c.store().clone(); // a forensic copy of W_0 and the floor
        c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
        c.lock();
        // Restore the old files (backup / image) but not the separately-held floor.
        let floor = c.store().floor;
        *c.store_mut() = MemStore {
            floor,
            ..image.clone()
        };
        assert_eq!(
            c.unlock(&p(Purpose::Unlock), b"ch").unwrap_err(),
            CoreError::Rollback,
            "{mode:?}"
        );
        // Even with the floor rolled back too, a retired hardware input no longer opens W_0
        // on platforms that can delete the key behind it.
        *c.store_mut() = image;
        let r = c.unlock(&p(Purpose::Unlock), b"ch");
        match mode {
            SoftMode::PublicTarget | SoftMode::ImportedKey => {
                assert_eq!(
                    r.unwrap_err(),
                    CoreError::Gate(GateError::UnknownInput),
                    "{mode:?}"
                );
            }
            // One fixed HMAC key can't forget an input: only the floor protects this case.
            SoftMode::SymmetricInput => assert!(r.is_ok()),
        }
    }
}

#[test]
fn crash_between_writing_next_wrap_and_raising_floor() {
    for mode in MODES {
        let mut c = core(mode);
        c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
        c.lock();
        // W_1 is written, then the floor raise fails (power lost): both wraps stay, floor 0,
        // W_0's hardware key is kept.
        c.store_mut().fail_next_floor = true;
        let u = c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
        assert!(!u.advanced);
        assert_eq!(u.wrap_counter, 1);
        assert!(c.store().files.contains_key("wrap-0") && c.store().files.contains_key("wrap-1"));
        assert_eq!(c.store().floor, 0);
        c.lock();
        // The next unlock opens the higher wrap, W_1, and completes the step to W_2,
        // retiring both W_0's and W_1's hardware inputs.
        let keys_before = c.gate().live_keys();
        let u = c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
        if mode != SoftMode::SymmetricInput {
            assert_eq!(
                c.gate().live_keys(),
                keys_before - 1,
                "{mode:?}: +W_2, -W_1, -W_0"
            );
        }
        assert!(u.advanced, "{mode:?}");
        assert_eq!(u.wrap_counter, 2);
        assert_eq!(c.store().floor, 2);
        c.lock();
        assert_eq!(
            c.unlock(&p(Purpose::Unlock), b"ch").unwrap().wrap_counter,
            3
        );
    }
}

#[test]
fn a_failed_write_keeps_the_current_wrap() {
    let mut c = core(SoftMode::ImportedKey);
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    c.lock();
    c.store_mut().fail_next_write = true;
    let u = c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
    assert!(!u.advanced);
    assert_eq!(u.wrap_counter, 0);
    c.lock();
    let u = c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
    assert!(u.advanced);
    assert_eq!(u.wrap_counter, 1);
}

#[test]
fn cancel_and_invalidation_leave_it_locked() {
    let mut c = core(SoftMode::PublicTarget);
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    c.lock();
    let keys_before = c.gate().live_keys();
    c.gate_mut().cancel_next = true;
    assert_eq!(
        c.unlock(&p(Purpose::Unlock), b"ch").unwrap_err(),
        CoreError::Gate(GateError::Cancelled)
    );
    assert!(!c.is_unlocked());
    assert_eq!(
        c.gate().live_keys(),
        keys_before,
        "the unused next target was retired"
    );
    c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
    c.lock();
    c.gate_mut().invalidated = true;
    assert_eq!(
        c.unlock(&p(Purpose::Unlock), b"ch").unwrap_err(),
        CoreError::Gate(GateError::KeyInvalidated)
    );
    assert_eq!(c.held_secrets(), 0);
}

#[test]
fn not_enrolled_and_double_enrol() {
    let mut c = core(SoftMode::PublicTarget);
    assert_eq!(
        c.unlock(&p(Purpose::Unlock), b"ch").unwrap_err(),
        CoreError::NotEnrolled
    );
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    assert_eq!(
        c.enroll(&p(Purpose::Enroll), b"ch").unwrap_err(),
        CoreError::AlreadyEnrolled
    );
}

#[test]
fn three_key_documents_seal_and_open() {
    for mode in MODES {
        let mut c = core(mode);
        let mut ks = KeyService::new();
        c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
        let d = seal(&mut c, &mut ks, &data);
        assert_eq!(
            open(&mut c, &ks, &d.slot, &d.envelope).unwrap(),
            data,
            "{mode:?}"
        );
        // after lock and a ratchet step, it still opens (documents don't depend on W_n)
        c.lock();
        c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
        assert_eq!(open(&mut c, &ks, &d.slot, &d.envelope).unwrap(), data);
    }
}

#[test]
fn documents_resist_tampering_and_substitution() {
    let mut c = core(SoftMode::PublicTarget);
    let mut ks = KeyService::new();
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    let d1 = seal(&mut c, &mut ks, &[1u8; 100_000]);
    let d2 = seal(&mut c, &mut ks, &[2u8; 1000]);
    // flip a byte in the body
    let mut e = d1.envelope.clone();
    let n = e.len();
    e[n - 100] ^= 1;
    assert_eq!(
        open(&mut c, &ks, &d1.slot, &e).unwrap_err(),
        CoreError::Tampered
    );
    // truncated
    assert!(open(&mut c, &ks, &d1.slot, &d1.envelope[..d1.envelope.len() - 1]).is_err());
    // another document's envelope with this document's slot
    assert_eq!(
        open(&mut c, &ks, &d1.slot, &d2.envelope).unwrap_err(),
        CoreError::WrongDocument
    );
    // another document's share
    let st = c.begin_open(&p(Purpose::Open), &d1.slot, b"ch").unwrap();
    let st2 = c.begin_open(&p(Purpose::Open), &d2.slot, b"ch").unwrap();
    let wrong = ks.release(&st2.share_request);
    assert_eq!(
        c.finish_open(st.handle, &wrong, &mut &d1.envelope[..], &mut Vec::new())
            .unwrap_err(),
        CoreError::WrongDocument
    );
    // the handle is single use
    assert_eq!(
        c.finish_open(st.handle, &wrong, &mut &d1.envelope[..], &mut Vec::new())
            .unwrap_err(),
        CoreError::BadHandle
    );
}

#[test]
fn another_account_cannot_plant_a_document() {
    let mut a = core(SoftMode::PublicTarget);
    let mut b = core(SoftMode::PublicTarget);
    let mut ks = KeyService::new();
    a.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    b.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    let da = seal(&mut a, &mut ks, b"a's");
    let db = seal(&mut b, &mut ks, b"b's");
    // a's slot names a's device: b refuses it outright
    assert_eq!(
        b.begin_open(&p(Purpose::Open), &da.slot, b"ch")
            .unwrap_err(),
        CoreError::WrongDocument
    );
    // b's own slot with a's envelope: wrong signer / document
    assert!(open(&mut b, &ks, &db.slot, &da.envelope).is_err());
}

#[test]
fn adding_a_device_one_prompt_each_side() {
    for mode in MODES {
        let mut old = core(mode);
        let mut new = core(mode);
        let mut ks = KeyService::new();
        let id = old.enroll(&p(Purpose::Enroll), b"ch").unwrap().identity;
        let docs: Vec<Doc> = (0..5u8)
            .map(|i| seal(&mut old, &mut ks, &vec![i; 1000 + usize::from(i)]))
            .collect();

        let j = new.begin_join(id.account_id()).unwrap();
        let before = old.gate().prompts;
        let slots: Vec<Vec<u8>> = docs.iter().map(|d| d.slot.clone()).collect();
        let g = old
            .grant_device(&p(Purpose::AddDevice), &j.request, &j.code, &slots, b"ch")
            .unwrap();
        assert_eq!(g.prompts, 1, "5 documents fit one authorization of 8 ops");
        assert_eq!(old.gate().prompts, before + 1);

        let u = new
            .finish_join(&p(Purpose::Enroll), &g.join_seed, b"ch")
            .unwrap();
        assert_eq!(u.identity.account_id(), id.account_id());
        assert_ne!(u.identity.device_id(), id.device_id());
        assert_eq!(new.gate().prompts, 1);

        for (i, (d, pending)) in docs.iter().zip(&g.pending).enumerate() {
            // first open adopts the pending slot into a hardware slot, in the same prompt
            let st = new.begin_open(&p(Purpose::Open), pending, b"ch").unwrap();
            let adopted = st.adopted_slot.clone().expect("adopted");
            let share = ks.release(&st.share_request);
            let mut view = Vec::new();
            new.finish_open(st.handle, &share, &mut &d.envelope[..], &mut view)
                .unwrap();
            assert_eq!(view, vec![i as u8; 1000 + i], "{mode:?}");
            // from then on, the hardware slot
            assert_eq!(open(&mut new, &ks, &adopted, &d.envelope).unwrap(), view);
        }
        // the new device's pending slots don't open on the old device, or vice versa
        assert_eq!(
            old.begin_open(&p(Purpose::Open), &g.pending[0], b"ch")
                .unwrap_err(),
            CoreError::WrongDocument
        );
        assert_eq!(
            new.begin_open(&p(Purpose::Open), &docs[0].slot, b"ch")
                .unwrap_err(),
            CoreError::WrongDocument
        );
    }
}

#[test]
fn many_documents_need_more_prompts_and_say_so() {
    let mut old = Core::new(
        SoftGate::new(SoftMode::PublicTarget, 4),
        MemStore::default(),
    )
    .unwrap();
    let mut new = core(SoftMode::PublicTarget);
    let mut ks = KeyService::new();
    old.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    let slots: Vec<Vec<u8>> = (0..10u8)
        .map(|i| seal(&mut old, &mut ks, &[i]).slot)
        .collect();
    let id = old.identity().unwrap();
    let j = new.begin_join(id.account_id()).unwrap();
    let g = old
        .grant_device(&p(Purpose::AddDevice), &j.request, &j.code, &slots, b"ch")
        .unwrap();
    // 3 derives + live in the first prompt, then 4 per prompt: 3 + 4 + 3
    assert_eq!(g.prompts, 3);
    assert_eq!(g.pending.len(), 10);
}

#[test]
fn join_seed_is_bound_to_device_and_account() {
    let mut old = core(SoftMode::PublicTarget);
    let mut new = core(SoftMode::PublicTarget);
    let mut other = core(SoftMode::PublicTarget);
    let id = old.enroll(&p(Purpose::Enroll), b"ch").unwrap().identity;
    let j = new.begin_join(id.account_id()).unwrap();
    let _ = other.begin_join(id.account_id()).unwrap();
    let g = old
        .grant_device(&p(Purpose::AddDevice), &j.request, &j.code, &[], b"ch")
        .unwrap();
    // another joining device can't use it
    assert_eq!(
        other
            .finish_join(&p(Purpose::Enroll), &g.join_seed, b"ch")
            .unwrap_err(),
        CoreError::WrongDocument
    );
    // a grant made for another account (by a device of that account) doesn't open as this one
    let mut stranger = core(SoftMode::PublicTarget);
    let sid = stranger
        .enroll(&p(Purpose::Enroll), b"ch")
        .unwrap()
        .identity;
    let mut new2 = core(SoftMode::PublicTarget);
    let j2 = new2.begin_join(id.account_id()).unwrap();
    assert_eq!(
        stranger
            .grant_device(&p(Purpose::AddDevice), &j2.request, &j2.code, &[], b"ch")
            .unwrap_err(),
        CoreError::WrongDocument
    );
    let mut new3 = core(SoftMode::PublicTarget);
    let j3 = new3.begin_join(sid.account_id()).unwrap();
    let g3 = stranger
        .grant_device(&p(Purpose::AddDevice), &j3.request, &j3.code, &[], b"ch")
        .unwrap();
    assert_eq!(
        new2.finish_join(&p(Purpose::Enroll), &g3.join_seed, b"ch")
            .unwrap_err(),
        CoreError::WrongDocument
    );
    new.finish_join(&p(Purpose::Enroll), &g.join_seed, b"ch")
        .unwrap();
}

#[test]
fn lock_wipes_everything() {
    let mut c = core(SoftMode::PublicTarget);
    let mut ks = KeyService::new();
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    let d = seal(&mut c, &mut ks, b"x");
    let st = c.begin_open(&p(Purpose::Open), &d.slot, b"ch").unwrap();
    let mut j = core(SoftMode::PublicTarget);
    j.begin_join([1; 32]).unwrap();
    assert_eq!(j.held_secrets(), 1);
    j.lock();
    assert_eq!(j.held_secrets(), 0);
    assert!(c.held_secrets() >= 2);
    c.lock();
    assert_eq!(c.held_secrets(), 0);
    assert!(!c.is_unlocked());
    let share = ks.release(&st.share_request);
    assert_eq!(
        c.finish_open(st.handle, &share, &mut &d.envelope[..], &mut Vec::new())
            .unwrap_err(),
        CoreError::BadHandle
    );
    assert_eq!(c.identity().unwrap_err(), CoreError::Locked);
    assert_eq!(
        c.seal_index_entry(b"i", None, b"e").unwrap_err(),
        CoreError::Locked
    );
    assert_eq!(
        c.begin_open(&p(Purpose::Open), &d.slot, b"ch").unwrap_err(),
        CoreError::Locked
    );
}

#[test]
fn decoy_session_writes_nothing() {
    let mut c = core(SoftMode::PublicTarget);
    let mut ks = KeyService::new();
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    let d = seal(&mut c, &mut ks, b"real");
    let entry = c.seal_index_entry(b"item", None, b"Passport").unwrap();
    c.enter_decoy().unwrap();
    let files_before = c.store().files.clone();
    assert_eq!(
        c.seal_index_entry(b"item", Some(&entry), b"x").unwrap_err(),
        CoreError::Decoy
    );
    assert_eq!(c.set_setting("a", b"b").unwrap_err(), CoreError::Decoy);
    let mut out = Vec::new();
    let meta = DocMeta {
        name: "n".into(),
        media_type: "t".into(),
    };
    assert_eq!(
        c.seal_document(
            &p(Purpose::Seal),
            &meta,
            &mut &b"x"[..],
            &mut out,
            ks.sk.public_key(),
            b"ch"
        )
        .unwrap_err(),
        CoreError::Decoy
    );
    let acct = c.identity().unwrap().account_id();
    let j = core(SoftMode::PublicTarget).begin_join(acct).unwrap();
    assert_eq!(
        c.grant_device(&p(Purpose::AddDevice), &j.request, &j.code, &[], b"ch")
            .unwrap_err(),
        CoreError::Decoy
    );
    // reading still works, and leaves no trace
    assert_eq!(
        &c.open_index_entry(b"item", &entry).unwrap()[..],
        b"Passport"
    );
    assert_eq!(open(&mut c, &ks, &d.slot, &d.envelope).unwrap(), b"real");
    assert_eq!(c.store().files, files_before);
}

#[test]
fn index_rollback_refused_across_lock() {
    let mut c = core(SoftMode::PublicTarget);
    c.enroll(&p(Purpose::Enroll), b"ch").unwrap();
    let v1 = c.seal_index_entry(b"item", None, b"Passport").unwrap();
    let v2 = c
        .seal_index_entry(b"item", Some(&v1), b"Passport, renamed")
        .unwrap();
    assert_eq!(
        &c.open_index_entry(b"item", &v2).unwrap()[..],
        b"Passport, renamed"
    );
    c.lock();
    c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
    // the device remembers rev 2 across lock: the vault serving v1 back is caught
    assert_eq!(
        c.open_index_entry(b"item", &v1).unwrap_err(),
        CoreError::Rollback
    );
    assert_eq!(
        c.open_index_entry(b"other", &v2).unwrap_err(),
        CoreError::WrongDocument
    );
    c.set_setting("duress", b"two-finger").unwrap();
    c.lock();
    c.unlock(&p(Purpose::Unlock), b"ch").unwrap();
    assert_eq!(&c.setting("duress").unwrap().unwrap()[..], b"two-finger");
    assert_eq!(c.setting("none").unwrap(), None);
}

#[test]
fn store_floor_never_goes_backwards() {
    let mut s = MemStore::default();
    s.raise_floor(5).unwrap();
    assert!(s.raise_floor(4).is_err());
    assert_eq!(s.floor().unwrap(), 5);
}
