//! Regression tests for the independent review of PR #94: each reviewer probe (PROBE1–8,
//! review-94-probes.rs) turned into a test that failed on 4f55c24 and passes now, plus
//! tests for the other humid-core findings (M3, M4, M7, L4, L5).

use humid_core::envelope::ShareRequest;
use humid_core::gate::{GateError, Prompt, Purpose};
use humid_core::soft_gate::{SoftGate, SoftMode};
use humid_core::store::{DeviceStore, MemStore};
use humid_core::{Core, CoreError, DocMeta, JoinRequest};
use humid_pq2::encoding::HEADER_LEN;
use humid_pq2::{
    KEM_PUBLIC_KEY_LEN, KemSecretKey, MLDSA_SIG_LEN, MLDSA_VK_LEN, ObjectType, ShareDirection,
    open_sealed, open_share, seal_share,
};

type C = Core<SoftGate, MemStore>;

fn p() -> Prompt {
    Prompt::new(Purpose::Unlock, "t")
}

fn core(mode: SoftMode, max_ops: usize) -> C {
    Core::new(SoftGate::new(mode, max_ops), MemStore::default()).unwrap()
}

fn seal(c: &mut C, ks: &KemSecretKey, data: &[u8]) -> (Vec<u8>, Vec<u8>, humid_pq2::Secret32) {
    let mut env = Vec::new();
    let meta = DocMeta {
        name: "a".into(),
        media_type: "b".into(),
    };
    let r = c
        .seal_document(
            &p(),
            &meta,
            &mut &data[..],
            &mut env,
            ks.public_key(),
            b"ch",
        )
        .unwrap();
    let acct = c.identity().unwrap().account_id();
    let share = open_share(
        ShareDirection::Upload,
        ks,
        &acct,
        &r.doc_id,
        &r.manifest_hash,
        &r.share_upload,
    )
    .unwrap();
    (env, r.slot, share)
}

fn release(req: &[u8], share: &humid_pq2::Secret32) -> Vec<u8> {
    let r = ShareRequest::decode(req).unwrap();
    seal_share(
        ShareDirection::Release,
        &r.one_time,
        &r.account_id,
        &r.doc_id,
        &r.binding().unwrap(),
        share,
    )
    .unwrap()
}

/* -------------------------------- H1 / PROBE1 ------------------------------- */

/// The server swaps the joiner's KEM key for its own, keeping the device key. The request's
/// signature no longer verifies, so nothing is sealed to the attacker.
#[test]
fn h1_join_kem_substitution_is_refused() {
    let mut old = core(SoftMode::PublicTarget, 8);
    let mut new = core(SoftMode::PublicTarget, 8);
    let id = old.enroll(&p(), b"ch").unwrap().identity;
    let real = new.begin_join(id.account_id()).unwrap();
    let attacker = KemSecretKey::generate().unwrap();
    let mut forged = real.request.clone();
    let at = HEADER_LEN + 32 + MLDSA_VK_LEN;
    forged[at..at + KEM_PUBLIC_KEY_LEN].copy_from_slice(attacker.public_key().to_bytes());
    assert_eq!(
        old.grant_device(&p(), &forged, &real.code, &[], b"ch")
            .unwrap_err(),
        CoreError::WrongSigner
    );
}

/// The relay replaces the whole request with one of its own (its own device key and KEM
/// key, validly self-signed). The code the person reads on the real new device doesn't
/// match it.
#[test]
fn h1_substituted_request_fails_the_code() {
    let mut old = core(SoftMode::PublicTarget, 8);
    let mut new = core(SoftMode::PublicTarget, 8);
    let mut evil = core(SoftMode::PublicTarget, 8);
    let id = old.enroll(&p(), b"ch").unwrap().identity;
    let real = new.begin_join(id.account_id()).unwrap();
    let theirs = evil.begin_join(id.account_id()).unwrap();
    assert_eq!(
        old.grant_device(&p(), &theirs.request, &real.code, &[], b"ch")
            .unwrap_err(),
        CoreError::CodeMismatch
    );
    // and the honest path still works, sealing only to the real join key
    let g = old
        .grant_device(&p(), &real.request, &real.code, &[], b"ch")
        .unwrap();
    let req = JoinRequest::decode(&real.request).unwrap();
    assert!(
        open_sealed(
            &KemSecretKey::generate().unwrap(),
            ObjectType::JOIN_SEED,
            &[&id.account_id(), &req.device_id(), &g.binding],
            &g.join_seed
        )
        .is_err()
    );
    let u = new.finish_join(&p(), &g.join_seed, b"ch").unwrap();
    assert_eq!(u.identity.account_id(), id.account_id());
}

/// A request for another account, or a garbled one, is refused before any prompt.
#[test]
fn h1_wrong_account_and_garbage() {
    let mut old = core(SoftMode::PublicTarget, 8);
    let mut new = core(SoftMode::PublicTarget, 8);
    old.enroll(&p(), b"ch").unwrap();
    let j = new.begin_join([9u8; 32]).unwrap();
    let before = old.gate().prompts;
    assert_eq!(
        old.grant_device(&p(), &j.request, &j.code, &[], b"ch")
            .unwrap_err(),
        CoreError::WrongDocument
    );
    assert!(
        old.grant_device(&p(), &j.request[..100], &j.code, &[], b"ch")
            .is_err()
    );
    let mut sig = j.request.clone();
    let n = sig.len();
    sig[n - MLDSA_SIG_LEN + 5] ^= 1;
    assert!(old.grant_device(&p(), &sig, &j.code, &[], b"ch").is_err());
    assert_eq!(old.gate().prompts, before);
}

/* -------------------------------- H2 / PROBE2 ------------------------------- */

/// A W_{n+1} write that lands but reports an error must not brick the device.
#[test]
fn h2_write_landed_but_reported_error() {
    for mode in [
        SoftMode::PublicTarget,
        SoftMode::ImportedKey,
        SoftMode::SymmetricInput,
    ] {
        let mut c = core(mode, 8);
        c.enroll(&p(), b"ch").unwrap();
        c.lock();
        c.store_mut().lie_next_write = true;
        let u = c.unlock(&p(), b"ch").unwrap();
        // the core read W_1 back, so the step completed despite the reported error
        assert!(u.advanced, "{mode:?}");
        c.lock();
        for _ in 0..3 {
            c.unlock(&p(), b"ch").unwrap();
            c.lock();
        }
    }
}

/// A write that fails without landing keeps the target, and the next unlock still works.
#[test]
fn h2_failed_write_then_recover() {
    for mode in [SoftMode::PublicTarget, SoftMode::ImportedKey] {
        let mut c = core(mode, 8);
        c.enroll(&p(), b"ch").unwrap();
        c.lock();
        c.store_mut().fail_next_write = true;
        let u = c.unlock(&p(), b"ch").unwrap();
        assert!(!u.advanced);
        assert_eq!(u.wrap_counter, 0);
        c.lock();
        let u = c.unlock(&p(), b"ch").unwrap();
        assert!(u.advanced && u.wrap_counter == 1, "{mode:?}");
    }
}

/// PROBE8: a planted higher-n wrap (a copy of W_n relabelled n = 1) doesn't block unlock;
/// the core falls back to the wrap that opens.
#[test]
fn h2_planted_higher_wrap_falls_back() {
    for mode in [
        SoftMode::PublicTarget,
        SoftMode::ImportedKey,
        SoftMode::SymmetricInput,
    ] {
        let mut c = core(mode, 8);
        c.enroll(&p(), b"ch").unwrap();
        c.lock();
        let mut w = c.store().files["wrap-0"].clone();
        w[13..21].copy_from_slice(&1u64.to_be_bytes());
        c.store_mut().files.insert("wrap-1".into(), w);
        let u = c.unlock(&p(), b"ch").unwrap();
        assert_eq!(u.wrap_counter, 1, "{mode:?}");
        c.lock();
        // garbage in a slot is ignored too
        let other = if c.store().files.contains_key("wrap-0") {
            "wrap-1"
        } else {
            "wrap-0"
        };
        c.store_mut().files.insert(other.into(), vec![0xff; 300]);
        c.unlock(&p(), b"ch").unwrap();
        c.lock();
        c.unlock(&p(), b"ch").unwrap();
    }
}

/// Only junk on disk: the error says the wrap is unusable, not "not enrolled".
#[test]
fn h2_only_junk_is_unusable_not_unenrolled() {
    let mut c = core(SoftMode::PublicTarget, 8);
    c.enroll(&p(), b"ch").unwrap();
    c.lock();
    let names: Vec<String> = c
        .store()
        .files
        .keys()
        .filter(|k| k.starts_with("wrap-"))
        .cloned()
        .collect();
    for n in names {
        c.store_mut().files.insert(n, vec![1, 2, 3]);
    }
    assert_eq!(c.unlock(&p(), b"ch").unwrap_err(), CoreError::WrapUnusable);
}

/* ---------------------------------- M1 ------------------------------------- */

// M1 (gate and store accessors reachable by the UI) is enforced at compile time: the
// accessors exist only under `cfg(test)` or the `software-gate` feature, which no release
// build enables. `cargo clippy -p humid-core` without features builds the release API.

/* -------------------------------- M2 / PROBE3 ------------------------------- */

#[test]
fn m2_revisions_restore_or_delete_is_rollback() {
    let mut c = core(SoftMode::PublicTarget, 8);
    c.enroll(&p(), b"ch").unwrap();
    let v1 = c.seal_index_entry(b"item", None, b"old").unwrap();
    let revs_after_v1 = c.store().files["revs"].clone();
    let v2 = c.seal_index_entry(b"item", Some(&v1), b"new").unwrap();
    c.lock();
    // restore the older revisions file only (wrap and counters untouched)
    c.store_mut().files.insert("revs".into(), revs_after_v1);
    let u = c.unlock(&p(), b"ch").unwrap();
    assert!(!u.records_ok);
    assert_eq!(
        c.open_index_entry(b"item", &v1).unwrap_err(),
        CoreError::RecordsUnavailable
    );
    c.lock();
    c.store_mut().files.remove("revs");
    let u = c.unlock(&p(), b"ch").unwrap();
    assert!(!u.records_ok);
    assert_eq!(
        c.open_index_entry(b"item", &v1).unwrap_err(),
        CoreError::RecordsUnavailable
    );
    // after the person is told and the device resets its record history, it works again
    c.reset_records().unwrap();
    assert_eq!(&c.open_index_entry(b"item", &v2).unwrap()[..], b"new");
    assert_eq!(
        c.open_index_entry(b"item", &v1).unwrap_err(),
        CoreError::Rollback
    );
}

/// A damaged revisions file no longer bricks unlock.
#[test]
fn m2_corrupt_revisions_dont_brick_unlock() {
    let mut c = core(SoftMode::PublicTarget, 8);
    c.enroll(&p(), b"ch").unwrap();
    c.seal_index_entry(b"item", None, b"x").unwrap();
    c.lock();
    c.store_mut().files.get_mut("revs").unwrap()[20] ^= 1;
    let u = c.unlock(&p(), b"ch").unwrap();
    assert!(!u.records_ok);
    assert!(u.advanced);
    c.lock();
    assert!(c.unlock(&p(), b"ch").is_ok());
}

/* -------------------------------- M3 / PROBE4 ------------------------------- */

/// Grant with max_ops = 1 (Android A/C): the live signature gets its own prompt, then one
/// document per prompt.
#[test]
fn m3_grant_with_max_ops_1() {
    let mut old = core(SoftMode::PublicTarget, 8);
    let mut new = core(SoftMode::PublicTarget, 8);
    let id = old.enroll(&p(), b"ch").unwrap().identity;
    let ks = KemSecretKey::generate().unwrap();
    let slots: Vec<Vec<u8>> = (0..3u8).map(|i| seal(&mut old, &ks, &[i]).1).collect();
    // the platform carries one op per prompt from here (Android proposal A/C, CORE.md §5.3)
    old.gate_mut().max_ops = 1;
    old.gate_mut().max_ops_seen = 0;
    let j = new.begin_join(id.account_id()).unwrap();
    let g = old
        .grant_device(&p(), &j.request, &j.code, &slots, b"ch")
        .unwrap();
    assert_eq!(g.prompts, 4);
    assert_eq!(g.pending.len(), 3);
    assert!(old.gate().max_ops_seen <= 1);
}

/// A gate that can't unlock in one prompt is refused at enrolment, not stuck later.
#[test]
fn m3_enrol_refuses_a_gate_that_cannot_unlock_in_one_prompt() {
    let mut c = core(SoftMode::SymmetricInput, 2);
    assert_eq!(c.enroll(&p(), b"ch").unwrap_err(), CoreError::Unsupported);
    assert_eq!(c.gate().prompts, 0);
    assert_eq!(c.store().files.len(), 0);
    let mut c = core(SoftMode::SymmetricInput, 3);
    c.enroll(&p(), b"ch").unwrap();
    c.lock();
    c.unlock(&p(), b"ch").unwrap();
    // public targets need only 2
    let mut c = core(SoftMode::PublicTarget, 2);
    c.enroll(&p(), b"ch").unwrap();
    c.lock();
    c.unlock(&p(), b"ch").unwrap();
}

/* -------------------------------- M4 / PROBE5 ------------------------------- */

#[test]
fn m4_decoy_does_not_adopt_and_marks_duress() {
    let mut old = core(SoftMode::PublicTarget, 8);
    let id = old.enroll(&p(), b"ch").unwrap().identity;
    let ks = KemSecretKey::generate().unwrap();
    let mut new2 = core(SoftMode::PublicTarget, 8);
    let j2 = new2.begin_join(id.account_id()).unwrap();
    let (_, slot2, _) = seal(&mut old, &ks, b"y");
    let g2 = old
        .grant_device(&p(), &j2.request, &j2.code, &[slot2], b"ch")
        .unwrap();
    new2.finish_join(&p(), &g2.join_seed, b"ch").unwrap();
    new2.enter_decoy().unwrap();
    let keys = new2.gate().live_keys();
    let files = new2.store().files.clone();
    let st = new2.begin_open(&p(), &g2.pending[0], b"ch").unwrap();
    assert!(st.adopted_slot.is_none());
    assert_eq!(
        new2.gate().live_keys(),
        keys,
        "no hardware key made in duress"
    );
    assert_eq!(new2.store().files, files, "nothing written in duress");
    assert_eq!(new2.pending_adoptions().unwrap(), 1);
}

/* -------------------------------- M7 ------------------------------------- */

/// Two devices write the same synced entry: the second write, made from the first's
/// current entry, is accepted everywhere; a write from a stale view is still ordered.
#[test]
fn m7_index_revisions_across_devices() {
    let mut a = core(SoftMode::PublicTarget, 8);
    let mut b = core(SoftMode::PublicTarget, 8);
    let id = a.enroll(&p(), b"ch").unwrap().identity;
    let j = b.begin_join(id.account_id()).unwrap();
    let g = a
        .grant_device(&p(), &j.request, &j.code, &[], b"ch")
        .unwrap();
    b.finish_join(&p(), &g.join_seed, b"ch").unwrap();
    let e1 = a.seal_index_entry(b"item", None, b"v1 (A)").unwrap();
    // B hasn't seen e1 but writes from the vault's current entry: rev 2, accepted by A
    let e2 = b.seal_index_entry(b"item", Some(&e1), b"v2 (B)").unwrap();
    assert_eq!(&a.open_index_entry(b"item", &e2).unwrap()[..], b"v2 (B)");
    assert_eq!(
        a.open_index_entry(b"item", &e1).unwrap_err(),
        CoreError::Rollback
    );
    // concurrent writes at the same rev from both devices are still totally ordered
    let x = a.seal_index_entry(b"item", Some(&e2), b"A3").unwrap();
    let y = b.seal_index_entry(b"item", Some(&e2), b"B3").unwrap();
    let mut c = core(SoftMode::PublicTarget, 8);
    let j = c.begin_join(id.account_id()).unwrap();
    let g = a
        .grant_device(&p(), &j.request, &j.code, &[], b"ch")
        .unwrap();
    c.finish_join(&p(), &g.join_seed, b"ch").unwrap();
    let rx = c.open_index_entry(b"item", &x).map(|v| v.to_vec());
    let ry = c.open_index_entry(b"item", &y).map(|v| v.to_vec());
    // whichever is higher opens; then the lower one is refused (one of the two orders)
    assert!(rx.is_ok());
    let a_id = a.identity().unwrap().device_id();
    let b_id = b.identity().unwrap().device_id();
    assert_eq!(ry.is_ok(), b_id > a_id);
}

/* -------------------------------- L4 ------------------------------------- */

#[test]
fn l4_setting_names_cannot_name_other_files() {
    let mut c = core(SoftMode::PublicTarget, 8);
    c.enroll(&p(), b"ch").unwrap();
    for bad in ["../wrap-0", "a/b", "", "UPPER", "x.y"] {
        assert_eq!(
            c.set_setting(bad, b"v").unwrap_err(),
            CoreError::Format,
            "{bad}"
        );
        assert_eq!(c.setting(bad).unwrap_err(), CoreError::Format);
    }
}

/* -------------------------------- L5 ------------------------------------- */

/// Pending slots are sealed to a per-join key, which the new device destroys once every
/// granted document is adopted: a captured pending slot then opens with nothing.
#[test]
fn l5_join_key_is_destroyed_after_adoption() {
    let mut old = core(SoftMode::PublicTarget, 8);
    let mut new = core(SoftMode::PublicTarget, 8);
    let id = old.enroll(&p(), b"ch").unwrap().identity;
    let ks = KemSecretKey::generate().unwrap();
    let docs: Vec<_> = (0..2u8).map(|i| seal(&mut old, &ks, &[i; 10])).collect();
    let slots: Vec<Vec<u8>> = docs.iter().map(|d| d.1.clone()).collect();
    let j = new.begin_join(id.account_id()).unwrap();
    let g = old
        .grant_device(&p(), &j.request, &j.code, &slots, b"ch")
        .unwrap();
    new.finish_join(&p(), &g.join_seed, b"ch").unwrap();
    assert_eq!(new.pending_adoptions().unwrap(), 2);
    for ((env, _, share), pending) in docs.iter().zip(&g.pending) {
        let st = new.begin_open(&p(), pending, b"ch").unwrap();
        assert!(st.adopted_slot.is_some());
        let mut v = Vec::new();
        new.finish_open(
            st.handle,
            &release(&st.share_request, share),
            &mut &env[..],
            &mut v,
        )
        .unwrap();
    }
    assert_eq!(new.pending_adoptions().unwrap(), 0);
    assert!(!new.store().files.contains_key("join-key"));
    // the captured pending slot no longer opens on this device
    assert_eq!(
        new.begin_open(&p(), &g.pending[0], b"ch").unwrap_err(),
        CoreError::WrongDocument
    );
}

/* -------------------------------- L7 ------------------------------------- */

/// A failed unlock leaks no hardware key (the fresh target is retired).
#[test]
fn l7_failed_unlock_retires_the_unused_target() {
    let mut c = core(SoftMode::PublicTarget, 8);
    c.enroll(&p(), b"ch").unwrap();
    c.lock();
    let keys = c.gate().live_keys();
    c.gate_mut().cancel_next = true;
    assert_eq!(
        c.unlock(&p(), b"ch").unwrap_err(),
        CoreError::Gate(GateError::Cancelled)
    );
    let names: Vec<String> = c
        .store()
        .files
        .keys()
        .filter(|k| k.starts_with("wrap-"))
        .cloned()
        .collect();
    for n in &names {
        // corrupt the sealed seeds (the tail), not the header or hardware input
        let w = c.store_mut().files.get_mut(n).unwrap();
        let last = w.len() - 1;
        w[last] ^= 1;
    }
    assert_eq!(c.unlock(&p(), b"ch").unwrap_err(), CoreError::WrapUnusable);
    assert_eq!(c.gate().live_keys(), keys);
}

/// The store trait's counters can't go backwards.
#[test]
fn counters_never_go_backwards() {
    let mut s = MemStore::default();
    s.raise_counter("revs", 3).unwrap();
    assert!(s.raise_counter("revs", 2).is_err());
    assert_eq!(s.counter("revs").unwrap(), 3);
    assert_eq!(s.counter("other").unwrap(), 0);
}
