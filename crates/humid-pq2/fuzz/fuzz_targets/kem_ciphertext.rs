#![no_main]
//! KemCiphertext decoder and decapsulation of whatever decodes (implicit rejection, low-order
//! X25519 points): must never panic.
use std::sync::OnceLock;

use humid_pq2::{KemCiphertext, KemSecretKey};
use libfuzzer_sys::fuzz_target;

static SK: OnceLock<KemSecretKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let sk = SK.get_or_init(|| KemSecretKey::generate().expect("rng"));
    if let Ok(ct) = KemCiphertext::from_bytes(data) {
        assert_eq!(&ct.to_bytes()[..], data);
        let _ = sk.decapsulate(&ct);
    }
});
