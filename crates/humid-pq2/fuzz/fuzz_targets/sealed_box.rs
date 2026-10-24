#![no_main]
//! open_sealed and open_share on arbitrary bytes: never panic, never open a forgery.
use std::sync::OnceLock;

use humid_pq2::{KemSecretKey, ObjectType, ShareDirection, open_sealed, open_share};
use libfuzzer_sys::fuzz_target;

static SK: OnceLock<KemSecretKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let sk = SK.get_or_init(|| KemSecretKey::generate().expect("rng"));
    assert!(open_sealed(sk, ObjectType::SEALED_BOX, &[], data).is_err());
    assert!(open_share(ShareDirection::Upload, sk, b"a", b"d", b"b", data).is_err());
    assert!(open_share(ShareDirection::Release, sk, b"a", b"d", b"b", data).is_err());
});
