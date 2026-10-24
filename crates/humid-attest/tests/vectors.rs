//! Real devices' output: the 4.x fixtures (Google's sample Android chains, Apache-2.0) and a
//! real iPhone's App Attest attestation and assertion (devicecheck-appattest, Apache-2.0).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use humid_attest::android::{self, SecurityLevel};
use humid_attest::apple::{self, ApplePolicy, Environment};
use humid_attest::{Mode, Trust, Verifier, x509};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    STANDARD.decode(b64).unwrap()
}

fn chain(dir: &str) -> Vec<Vec<u8>> {
    (0..4)
        .map(|i| {
            pem_to_der(
                &std::fs::read_to_string(format!("{FIX}/android-attestation/{dir}/cert{i}.pem"))
                    .unwrap(),
            )
        })
        .collect()
}

/// 1 Jan 2027.
const T2027: i64 = 1_798_761_600_000;

#[test]
fn googles_sample_tee_chains_end_in_googles_own_root_key() {
    // the TEE samples chain to Google's RSA root key (its 2016 certificate): a production
    // verifier with only the pinned roots accepts the chain itself
    let v = Verifier::new(Trust::pinned(), Mode::Production).unwrap();
    for (dir, level) in [
        ("algorithm_EC_SecurityLevel_TEE", SecurityLevel::Tee),
        ("algorithm_RSA_SecurityLevel_TEE", SecurityLevel::Tee),
    ] {
        let c = chain(dir);
        let r = android::read_chain(&v, &c, T2027).unwrap();
        let kd = &r.description;
        assert_eq!(kd.attestation_version, 3, "{dir}");
        assert_eq!(kd.keymint_version, 4);
        assert_eq!(kd.attestation_level, level);
        assert_eq!(kd.keymint_level, level);
        assert_eq!(kd.challenge, b"abc");
        let app = kd.app_id().unwrap();
        assert!(app.packages.iter().any(|p| p == "android"), "{dir}");
        assert!(kd.root_of_trust().unwrap().is_some());
        assert_eq!(r.serials().len(), 4);
        assert_eq!(
            r.serials()[3],
            "e8fa196314d2fa18",
            "the root's serial, as Google's list writes it"
        );
    }
}

#[test]
fn googles_strongbox_sample_has_another_root() {
    let c = chain("algorithm_EC_SecurityLevel_StrongBox");
    let prod = Verifier::new(Trust::pinned(), Mode::Production).unwrap();
    assert_eq!(
        android::read_chain(&prod, &c, T2027).unwrap_err().code,
        "untrusted_root"
    );
    // trusted explicitly (development), it parses as StrongBox
    let anchor = humid_attest::Anchor::from_der(&c[3]).unwrap();
    let dev = Verifier::new(
        Trust::pinned().with_test_anchors(vec![anchor.clone()], vec![]),
        Mode::Development,
    )
    .unwrap();
    let r = android::read_chain(&dev, &c, T2027).unwrap();
    assert_eq!(r.description.attestation_level, SecurityLevel::StrongBox);
    // and a production verifier can't be given that root at all
    assert_eq!(
        Verifier::new(
            Trust::pinned().with_test_anchors(vec![anchor], vec![]),
            Mode::Production
        )
        .unwrap_err()
        .code,
        "test_root_in_production"
    );
}

#[test]
fn googles_samples_are_not_live_keys() {
    // they need no authentication and may verify as well as sign: either refusal is right
    let v = Verifier::new(Trust::pinned(), Mode::Production).unwrap();
    let c = chain("algorithm_EC_SecurityLevel_TEE");
    let r = android::read_chain(&v, &c, T2027).unwrap();
    let p = android::AndroidPolicy {
        packages: vec!["android".into()],
        signers: vec![[0; 32]],
        min_os_version: 0,
        min_patch_level: 0,
        strongbox_required: false,
    };
    let e = android::check_policy(&r, b"abc", &p).unwrap_err();
    assert!(
        ["bad_key", "no_biometric", "imported_key"].contains(&e.code),
        "{e}"
    );
    assert_eq!(
        android::check_policy(&r, b"abd", &p).unwrap_err().code,
        "wrong_challenge"
    );
}

#[test]
fn a_sample_chain_out_of_date_or_tampered_is_refused() {
    let v = Verifier::new(Trust::pinned(), Mode::Production).unwrap();
    let c = chain("algorithm_EC_SecurityLevel_TEE");
    // the intermediates expire in March 2028
    let t2029 = T2027 + 2 * 365 * 86_400_000;
    assert_eq!(
        android::read_chain(&v, &c, t2029).unwrap_err().code,
        "bad_attestation"
    );
    let mut t = c.clone();
    let n = t[0].len();
    t[0][n - 10] ^= 1;
    assert_eq!(
        android::read_chain(&v, &t, T2027).unwrap_err().code,
        "bad_attestation"
    );
    // out of order
    let swapped = vec![c[1].clone(), c[0].clone(), c[2].clone(), c[3].clone()];
    assert!(android::read_chain(&v, &swapped, T2027).is_err());
    // the leaf alone, or the root left off
    assert!(android::read_chain(&v, &c[..1], T2027).is_err());
    assert_eq!(
        android::read_chain(&v, &c[..3], T2027).unwrap_err().code,
        "untrusted_root"
    );
}

#[test]
fn the_single_leaf_fixture_parses() {
    let leaf = pem_to_der(
        &std::fs::read_to_string(format!("{FIX}/android-attestation/leaf-challenge-abc.pem"))
            .unwrap(),
    );
    let c = x509::Cert::parse(&leaf).unwrap();
    let kd =
        android::KeyDescription::parse(c.extension(x509::oid::KEY_DESCRIPTION).unwrap()).unwrap();
    assert_eq!(kd.challenge, b"abc");
}

/* ------------------------------- App Attest ------------------------------- */

#[derive(serde::Deserialize)]
struct AppleFixture {
    team_id: String,
    bundle_id: String,
    ios_version: String,
    key_id_b64: String,
    client_data_hash_b64: String,
    attestation_b64: String,
    assertion: AssertionFixture,
}

#[derive(serde::Deserialize)]
struct AssertionFixture {
    client_data_hash_b64: String,
    counter: u32,
    assertion_b64: String,
}

fn apple_fixture() -> AppleFixture {
    serde_json::from_str(
        &std::fs::read_to_string(format!("{FIX}/app-attest/ios-14.4.json")).unwrap(),
    )
    .unwrap()
}

/// 23 Jan 2021, 12:13:33 UTC: when the iPhone made the attestation.
const T_ATTEST: i64 = 1_611_404_013_335;

fn cdh(b64: &str) -> [u8; 32] {
    STANDARD.decode(b64).unwrap().try_into().unwrap()
}

#[test]
fn a_real_iphones_app_attest_attestation_and_assertion_verify() {
    let f = apple_fixture();
    let app_id = format!("{}.{}", f.team_id, f.bundle_id);
    let object = STANDARD.decode(&f.attestation_b64).unwrap();
    let policy = ApplePolicy {
        app_ids: vec![app_id.clone()],
        environment: Environment::Development,
        min_os_major: 14,
    };
    // a development (Xcode) build: only a development verifier takes it
    let dev = Verifier::new(Trust::pinned(), Mode::Development).unwrap();
    let a = apple::verify_attestation(
        &dev,
        &object,
        &cdh(&f.client_data_hash_b64),
        &policy,
        T_ATTEST,
    )
    .unwrap();
    assert_eq!(a.key_id, STANDARD.decode(&f.key_id_b64).unwrap());
    assert_eq!(a.environment, Environment::Development);
    assert_eq!(a.os_version, f.ios_version);
    assert_eq!(a.app_id, app_id);

    // the assertion it made next, counter 1
    let assertion = STANDARD.decode(&f.assertion.assertion_b64).unwrap();
    let ok = apple::verify_assertion(&assertion, &a, &cdh(&f.assertion.client_data_hash_b64), 0)
        .unwrap();
    assert_eq!(ok.counter, f.assertion.counter);
    // counter rollback / replay
    assert_eq!(
        apple::verify_assertion(&assertion, &a, &cdh(&f.assertion.client_data_hash_b64), 1)
            .unwrap_err()
            .code,
        "assertion_replayed"
    );
    // another check's data
    assert_eq!(
        apple::verify_assertion(&assertion, &a, &[0; 32], 0)
            .unwrap_err()
            .code,
        "bad_assertion"
    );
}

#[test]
fn a_real_development_attestation_is_refused_by_production() {
    let f = apple_fixture();
    let object = STANDARD.decode(&f.attestation_b64).unwrap();
    let app_id = format!("{}.{}", f.team_id, f.bundle_id);
    let prod = Verifier::new(Trust::pinned(), Mode::Production).unwrap();
    let mut policy = ApplePolicy {
        app_ids: vec![app_id],
        environment: Environment::Production,
        min_os_major: 14,
    };
    let c = cdh(&f.client_data_hash_b64);
    assert_eq!(
        apple::verify_attestation(&prod, &object, &c, &policy, T_ATTEST)
            .unwrap_err()
            .code,
        "wrong_environment",
        "a development AAGUID on a production server"
    );
    // even a policy that names development can't make production take it
    policy.environment = Environment::Development;
    assert_eq!(
        apple::verify_attestation(&prod, &object, &c, &policy, T_ATTEST)
            .unwrap_err()
            .code,
        "wrong_environment"
    );
}

#[test]
fn a_real_attestation_fails_every_other_binding() {
    let f = apple_fixture();
    let object = STANDARD.decode(&f.attestation_b64).unwrap();
    let dev = Verifier::new(Trust::pinned(), Mode::Development).unwrap();
    let app_id = format!("{}.{}", f.team_id, f.bundle_id);
    let p = |ids: Vec<String>, min| ApplePolicy {
        app_ids: ids,
        environment: Environment::Development,
        min_os_major: min,
    };
    let c = cdh(&f.client_data_hash_b64);
    let code = |o: &[u8], c: &[u8; 32], pol: &ApplePolicy, now| {
        apple::verify_attestation(&dev, o, c, pol, now)
            .unwrap_err()
            .code
    };
    assert_eq!(
        code(&object, &[1; 32], &p(vec![app_id.clone()], 14), T_ATTEST),
        "wrong_challenge"
    );
    assert_eq!(
        code(
            &object,
            &c,
            &p(vec!["6MURL8TA57.app.humid.vault".into()], 14),
            T_ATTEST
        ),
        "wrong_app"
    );
    assert_eq!(
        code(&object, &c, &p(vec![], 14), T_ATTEST),
        "not_configured"
    );
    // the owner's floor: iOS 26
    assert_eq!(
        code(&object, &c, &p(vec![app_id.clone()], 26), T_ATTEST),
        "old_ios"
    );
    // the credential certificate lives days: years later it is expired
    assert_eq!(
        code(&object, &c, &p(vec![app_id.clone()], 14), T2027),
        "bad_attestation"
    );
    // flip one byte anywhere outside the receipt (the server doesn't read it; it is for
    // Apple's fraud-metric service): never accepted, never a panic
    let receipt = {
        let o = humid_attest::cbor::decode(&object).unwrap();
        let r = o
            .get("attStmt")
            .unwrap()
            .get("receipt")
            .unwrap()
            .bytes()
            .unwrap();
        let start = r.as_ptr() as usize - object.as_ptr() as usize;
        start..start + r.len()
    };
    for i in (0..object.len())
        .step_by(7)
        .filter(|i| !receipt.contains(i))
    {
        let mut o = object.clone();
        o[i] ^= 0x01;
        assert!(
            apple::verify_attestation(&dev, &o, &c, &p(vec![app_id.clone()], 14), T_ATTEST)
                .is_err(),
            "byte {i}"
        );
    }
    // truncated anywhere
    for n in (0..object.len()).step_by(13) {
        assert!(
            apple::verify_attestation(
                &dev,
                &object[..n],
                &c,
                &p(vec![app_id.clone()], 14),
                T_ATTEST
            )
            .is_err()
        );
    }
}
