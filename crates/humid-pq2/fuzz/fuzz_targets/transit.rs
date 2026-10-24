#![no_main]
//! TransitOpener: an arbitrary sequence of (seq, record) inputs. Never panics; forged records
//! never open; a genuine record opens at most once.
use humid_pq2::{Role, Secret32, transit_channel};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let k = Secret32::from_slice(&[7u8; 32]).expect("32 bytes");
    let (mut tx, _) = transit_channel(k.duplicate(), b"fuzz", Role::Initiator).expect("channel");
    let real: Vec<_> = (0..4).map(|i| tx.seal(b"", &[i]).expect("seal")).collect();
    let (_, mut rx) = transit_channel(k, b"fuzz", Role::Responder).expect("channel");
    let mut opened = [0u8; 4];
    for chunk in data.chunks(9) {
        if chunk.len() < 9 {
            break;
        }
        let seq = u64::from_be_bytes(chunk[1..9].try_into().expect("8 bytes"));
        if chunk[0] & 1 == 0 {
            // a genuine record replayed under a fuzzed seq
            let (s, ct) = &real[(chunk[0] as usize >> 1) % 4];
            if rx.open(seq, b"", ct).is_ok() {
                assert_eq!(seq, *s);
                opened[*s as usize] += 1;
                assert_eq!(opened[*s as usize], 1);
            }
        } else {
            assert!(rx.open(seq, b"", &chunk[1..]).is_err());
        }
    }
});
