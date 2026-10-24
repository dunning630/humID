//! Cross-checks against humid-core (crates/humid-core, from v5-core): the server must accept
//! byte for byte what the phone's core emits, and bind it the same way.

use humid_core::envelope::ShareRequest as CoreShareRequest;
use humid_pq2::{KemSecretKey, Secret32, ShareDirection, open_share, seal_share};
use humid_server::crypto::{self, KemPublic, ShareRequest};

#[test]
fn the_server_parses_and_binds_humid_cores_share_request() {
    let once = KemSecretKey::generate().unwrap();
    let req = CoreShareRequest {
        account_id: [1; 32],
        doc_id: [2; 32],
        manifest_hash: [3; 64],
        one_time: once.public_key().clone(),
    };
    let bytes = req.encode();
    let parsed = ShareRequest::parse(&bytes).unwrap();
    assert_eq!(parsed.account, [1; 32]);
    assert_eq!(parsed.doc, [2; 32]);
    assert_eq!(parsed.manifest_hash, [3; 64]);
    assert_eq!(
        parsed.binding,
        req.binding().unwrap(),
        "the same binding the phone's live check signed"
    );
    assert_eq!(
        ShareRequest::encode(
            &[1; 32],
            &[2; 32],
            &[3; 64],
            &KemPublic::from_bytes(once.public_key().to_bytes()).unwrap()
        ),
        bytes
    );

    // a release sealed by the server opens in the phone's core under the core's own binding
    let share = Secret32::random().unwrap();
    let sealed = crypto::seal_release_share(
        &parsed.one_time,
        &[1; 32],
        &[2; 32],
        &parsed.binding,
        &share,
    )
    .unwrap();
    let got = open_share(
        ShareDirection::Release,
        &once,
        &[1; 32],
        &[2; 32],
        &req.binding().unwrap(),
        &sealed,
    )
    .unwrap();
    assert!(got.ct_eq(&share));

    // truncated, extended or retyped requests are refused
    assert!(ShareRequest::parse(&bytes[..bytes.len() - 1]).is_err());
    assert!(ShareRequest::parse(&[bytes.clone(), vec![0]].concat()).is_err());
    let mut retyped = bytes.clone();
    retyped[12] ^= 1;
    assert!(ShareRequest::parse(&retyped).is_err());
}

#[test]
fn the_server_parses_humid_cores_join_request_and_its_code() {
    use humid_core::soft_gate::{SoftGate, SoftMode};
    use humid_core::store::MemStore;
    let mut new = humid_core::Core::new(
        SoftGate::new(SoftMode::PublicTarget, 8),
        MemStore::default(),
    )
    .unwrap();
    let started = new.begin_join([7; 32]).unwrap();
    let parsed = crypto::JoinRequest::parse(&started.request).unwrap();
    assert_eq!(parsed.account, [7; 32]);
    assert_eq!(
        parsed.code,
        started.code.replace('-', ""),
        "the 100-bit code both screens show"
    );
    let core_req = humid_core::JoinRequest::decode(&started.request).unwrap();
    assert_eq!(parsed.binding, core_req.binding().unwrap());
    assert_eq!(parsed.device_id, core_req.device_id());
    // a swapped join key no longer verifies (humid-core review H1, on the server's side too)
    let mut forged = started.request.clone();
    let at = humid_pq2::encoding::HEADER_LEN + 32 + humid_pq2::MLDSA_VK_LEN + 5;
    forged[at] ^= 1;
    assert!(crypto::JoinRequest::parse(&forged).is_err());
    assert!(crypto::JoinRequest::parse(&started.request[1..]).is_err());
}

#[test]
fn an_upload_share_is_bound_to_the_manifest_hash() {
    // the phone seals with binding = manifest hash (CORE.md §6.3); the server opens with it
    let ks = crypto::KemSecret::generate().unwrap();
    let pk = KemPublic::from_bytes(&ks.public().to_bytes()).unwrap();
    let share = Secret32::random().unwrap();
    let phone_pk = humid_pq2::KemPublicKey::from_bytes(&pk.to_bytes()).unwrap();
    let sealed = seal_share(
        ShareDirection::Upload,
        &phone_pk,
        &[1; 32],
        &[2; 32],
        &[3; 64],
        &share,
    )
    .unwrap();
    assert!(
        crypto::open_upload_share(&ks, &[1; 32], &[2; 32], &[3; 64], &sealed)
            .unwrap()
            .ct_eq(&share)
    );
    assert!(
        crypto::open_upload_share(&ks, &[1; 32], &[2; 32], &[4; 64], &sealed).is_err(),
        "another manifest doesn't open it"
    );
}
