#![no_main]
//! Everything a phone sends that humid-attest reads: certificates, KeyDescriptions, CBOR,
//! whole chains, App Attest objects and assertions, Google's status list. None may panic,
//! and none may be accepted (there is no trust anchor for fuzzer bytes).
use humid_attest::{Mode, StatusList, Trust, Verifier, android, apple, cbor, x509};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = x509::Cert::parse(data);
    let _ = android::KeyDescription::parse(data);
    let _ = cbor::decode(data);
    let _ = StatusList::parse(data, 0, true, 1);
    let v = Verifier::new(Trust::pinned(), Mode::Development).unwrap();
    let mid = data.len() / 2;
    let chain = vec![data[..mid].to_vec(), data[mid..].to_vec()];
    let p = android::AndroidPolicy {
        packages: vec!["app.humid.vault".into()],
        signers: vec![[1; 32]],
        min_os_version: 0,
        min_patch_level: 0,
        strongbox_required: false,
    };
    assert!(android::verify(&v, &chain, &[], &[], &p, &StatusList::empty(false, 1), 0).is_err());
    let ap = apple::ApplePolicy {
        app_ids: vec!["TEAM123456.app.humid.vault".into()],
        environment: apple::Environment::Development,
        min_os_major: 0,
    };
    assert!(apple::verify_attestation(&v, data, &[0; 32], &ap, 0).is_err());
    let attested = apple::AppleAttested {
        key_id: vec![0; 32],
        public_key: [&[4u8][..], &[1; 64]].concat(),
        app_id: "TEAM123456.app.humid.vault".into(),
        environment: apple::Environment::Development,
        os_version: "26.0".into(),
    };
    assert!(apple::verify_assertion(data, &attested, &[0; 32], 0).is_err());
});
