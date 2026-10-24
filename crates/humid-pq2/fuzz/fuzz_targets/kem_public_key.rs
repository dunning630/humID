#![no_main]
//! KemPublicKey decoder (header, length, FIPS 203 modulus check). A key that decodes must
//! re-encode to the same bytes.
use humid_pq2::KemPublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pk) = KemPublicKey::from_bytes(data) {
        assert_eq!(&pk.to_bytes()[..], data);
        let _ = pk.key_id();
    }
});
