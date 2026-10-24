#![no_main]
//! open_at_rest on arbitrary bytes, under a fixed key: never panics, never opens a forgery.
use std::sync::OnceLock;

use humid_pq2::{ObjectType, Secret32, open_at_rest};
use libfuzzer_sys::fuzz_target;

static K: OnceLock<Secret32> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let k = K.get_or_init(|| Secret32::random().expect("rng"));
    for t in [
        ObjectType::AT_REST_BOX,
        ObjectType::INDEX_ENTRY,
        ObjectType::DEVICE_WRAP,
    ] {
        assert!(open_at_rest(k, t, &[b"fuzz"], data).is_err());
    }
});
