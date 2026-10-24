#![no_main]
//! KEM certificates and key bundles. Never panic; a bundle that decodes re-encodes the same.
use humid_htp::cert::{Bundle, Cert};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Cert::decode(data);
    if let Ok(b) = Bundle::decode(data) {
        assert_eq!(b.encode(), data);
    }
});
