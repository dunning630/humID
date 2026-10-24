#![no_main]
//! Typed request bodies and binary live proofs.
use humid_htp::parts::{self, Proof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(ps) = parts::decode(data) {
        assert_eq!(parts::encode(&ps), data);
    }
    if let Ok(p) = Proof::decode(data) {
        assert_eq!(p.encode(), data);
    }
});
