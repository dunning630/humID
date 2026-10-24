#![no_main]
//! HELLO, RESUME and REPLY bodies: never panic; what decodes re-encodes identically.
use humid_htp::handshake::{Hello, Reply, Resume};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Hello::decode(data) {
        assert_eq!(h.encode(), data);
    }
    if let Ok(r) = Resume::decode(data) {
        assert_eq!(r.encode(), data);
    }
    if let Ok(r) = Reply::decode(data) {
        assert_eq!(r.encode(), data);
    }
});
