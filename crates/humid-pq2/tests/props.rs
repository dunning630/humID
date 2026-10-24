//! Property tests over the public API: round trips, tamper detection, and decoders that
//! never panic on arbitrary bytes.

use humid_pq2::*;
use proptest::prelude::*;

fn key() -> Secret32 {
    Secret32::random().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn at_rest_round_trip(pt in proptest::collection::vec(any::<u8>(), 0..2048), id in "[a-z0-9]{0,16}", rev in any::<u32>()) {
        let k = key();
        let r = rev.to_be_bytes();
        let b = seal_at_rest(&k, ObjectType::INDEX_ENTRY, &[id.as_bytes(), &r], &pt).unwrap();
        prop_assert_eq!(&open_at_rest(&k, ObjectType::INDEX_ENTRY, &[id.as_bytes(), &r], &b).unwrap()[..], &pt[..]);
    }

    #[test]
    fn at_rest_any_flip_fails(pt in proptest::collection::vec(any::<u8>(), 0..256), pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let k = key();
        let mut b = seal_at_rest(&k, ObjectType::SETTINGS, &[b"x"], &pt).unwrap();
        let i = pos.index(b.len());
        b[i] ^= 1 << bit;
        prop_assert!(open_at_rest(&k, ObjectType::SETTINGS, &[b"x"], &b).is_err());
    }

    #[test]
    fn transit_in_any_order_once(order in Just((0u64..40).collect::<Vec<_>>()).prop_shuffle()) {
        let k = key();
        let (mut tx, _) = transit_channel(k.duplicate(), b"chan", Role::Initiator).unwrap();
        let recs: Vec<_> = (0..40).map(|i| tx.seal(b"", &[i as u8]).unwrap()).collect();
        let (_, mut rx) = transit_channel(k, b"chan", Role::Responder).unwrap();
        for &s in &order {
            let (seq, ct) = &recs[s as usize];
            prop_assert_eq!(&rx.open(*seq, b"", ct).unwrap()[..], &[s as u8][..]);
        }
        for (seq, ct) in &recs {
            prop_assert_eq!(rx.open(*seq, b"", ct).unwrap_err(), Error::Counter);
        }
    }

    #[test]
    fn kdf_injective_over_part_boundaries(a in proptest::collection::vec(any::<u8>(), 0..40), cut in any::<prop::sample::Index>()) {
        // Splitting the same bytes differently between two parts gives a different key.
        let i = cut.index(a.len() + 1);
        let x: Secret32 = kdf("HUMID-PQ2 test", &[&a[..i], &a[i..]], &[]).unwrap();
        let y: Secret32 = kdf("HUMID-PQ2 test", &[&a], &[]).unwrap();
        prop_assert!(!x.ct_eq(&y));
    }

    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = KemPublicKey::from_bytes(&bytes);
        let _ = KemCiphertext::from_bytes(&bytes);
        let _ = MlDsaVerifyingKey::from_bytes(&bytes);
        let _ = MlDsaSignature::from_bytes(&bytes);
        let _ = SlhVerifyingKey::from_bytes(&bytes);
        let _ = SlhSignature::from_bytes(&bytes);
        let _ = DualVerifyingKey::from_bytes(&bytes);
        let _ = DualSignature::from_bytes(&bytes);
        let k = key();
        let _ = open_at_rest(&k, ObjectType::AT_REST_BOX, &[], &bytes);
    }
}

#[test]
fn decoders_never_panic_on_well_sized_junk() {
    // Correct header and length, random body: decoders and verifiers refuse, never panic.
    let mut rnd = vec![0u8; 40_000];
    random_bytes(&mut rnd).unwrap();
    let with = |t: ObjectType, n: usize| {
        let mut v = encoding::header(t).to_vec();
        v.extend_from_slice(&rnd[..n]);
        v
    };
    let _ = KemPublicKey::from_bytes(&with(ObjectType::KEM_PUBLIC_KEY, 1600));
    let sk = KemSecretKey::generate().unwrap();
    let ct = KemCiphertext::from_bytes(&with(ObjectType::KEM_CIPHERTEXT, 1600)).unwrap();
    let _ = sk.decapsulate(&ct);
    let vk = MlDsaVerifyingKey::from_bytes(&with(ObjectType::MLDSA_VERIFYING_KEY, MLDSA_VK_LEN))
        .unwrap();
    let sig =
        MlDsaSignature::from_bytes(&with(ObjectType::MLDSA_SIGNATURE, MLDSA_SIG_LEN)).unwrap();
    assert_eq!(vk.verify("HUMID-PQ2 test", b"m", &sig), Err(Error::Verify));
    let svk =
        SlhVerifyingKey::from_bytes(&with(ObjectType::SLH_VERIFYING_KEY, SLH_VK_LEN)).unwrap();
    let ssig = SlhSignature::from_bytes(&with(ObjectType::SLH_SIGNATURE, SLH_SIG_LEN)).unwrap();
    assert_eq!(
        svk.verify("HUMID-PQ2 test", b"m", &ssig),
        Err(Error::Verify)
    );
    let boxed = with(
        ObjectType::SEALED_BOX,
        SEALED_OVERHEAD - encoding::HEADER_LEN + 10,
    );
    assert!(open_sealed(&sk, ObjectType::SEALED_BOX, &[], &boxed).is_err());
}

#[test]
fn self_test_passes() {
    self_test().unwrap();
}
