#![no_main]
//! Messages inside records, both directions. A message that decodes re-encodes to the same
//! bytes (one encoding per message).
use humid_htp::msg::{Dir, Msg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for dir in [Dir::Up, Dir::Down] {
        if let Ok(m) = Msg::decode(data, dir) {
            assert_eq!(m.encode(), data);
        }
    }
});
