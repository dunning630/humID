#![no_main]
//! Every humid-core decoder on arbitrary bytes: wraps, manifests, device and pending slots,
//! share requests, join requests (which verify their own signature). None may panic;
//! whatever decodes must re-encode to the same bytes.
use humid_core::envelope::{AnySlot, DeviceSlot, Manifest, PendingSlot, ShareRequest};
use humid_core::join::JoinRequest;
use humid_core::ratchet::Wrap;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(w) = Wrap::decode(data) {
        assert_eq!(w.encode(), data);
    }
    if let Ok(m) = Manifest::decode(data) {
        assert_eq!(m.encode(), data);
    }
    if let Ok(s) = DeviceSlot::decode(data) {
        assert_eq!(s.encode(), data);
    }
    if let Ok(s) = PendingSlot::decode(data) {
        assert_eq!(s.encode(), data);
    }
    if let Ok(r) = ShareRequest::decode(data) {
        assert_eq!(r.encode(), data);
    }
    if let Ok(j) = JoinRequest::decode(data) {
        assert_eq!(j.encode(), data);
    }
    let _ = AnySlot::decode(data);
});
