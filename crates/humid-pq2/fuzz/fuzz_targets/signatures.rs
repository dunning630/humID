#![no_main]
//! Every signature and verifying-key decoder, and verification of whatever decodes against a
//! fixed key: must never panic, and never accept.
use std::sync::OnceLock;

use humid_pq2::{
    DualSignature, DualVerifyingKey, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey,
    SlhSignature, SlhVerifyingKey,
};
use libfuzzer_sys::fuzz_target;

static K: OnceLock<MlDsaSigningKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let k = K.get_or_init(|| MlDsaSigningKey::generate().expect("rng"));
    let _ = MlDsaVerifyingKey::from_bytes(data);
    let _ = SlhVerifyingKey::from_bytes(data);
    let _ = DualVerifyingKey::from_bytes(data);
    let _ = SlhSignature::from_bytes(data);
    let _ = DualSignature::from_bytes(data);
    if let Ok(sig) = MlDsaSignature::from_bytes(data) {
        assert!(
            k.verifying_key()
                .verify("HUMID-PQ2 fuzz", b"fuzz", &sig)
                .is_err()
        );
    }
    // the raw form used inside larger structures
    if let Ok(sig) = MlDsaSignature::from_raw(data) {
        assert!(
            k.verifying_key()
                .verify("HUMID-PQ2 fuzz", b"fuzz", &sig)
                .is_err()
        );
    }
});
