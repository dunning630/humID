#![no_main]
//! Frame headers, splitting and front's routing check. Never panics; a header that decodes
//! re-encodes to the same 32 bytes; padding that unpads is zeros.
use humid_htp::frame::{self, HEADER_LEN, Header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::decode(data) {
        assert_eq!(&h.encode()[..], &data[..HEADER_LEN]);
    }
    if let Ok(frames) = frame::split(data) {
        let total: usize = frames.iter().map(|f| f.bytes.len()).sum();
        assert_eq!(total, data.len());
        for f in &frames {
            let _ = f.clear_body();
            let _ = f.error_code();
        }
    }
    let _ = frame::route(data);
    if let Ok(b) = frame::unpad(data) {
        assert!(data[4 + b.len()..].iter().all(|&x| x == 0));
    }
});
