//! HumID's rules, positive and negative, over the testkit's phone-shaped attestations.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use humid_attest::android::{self, AndroidPolicy};
use humid_attest::apple::{self, ApplePolicy, Environment};
use humid_attest::testkit::{self, AppAttestKey, ChainOpts, KeyDesc, TestPki};
use humid_attest::{Mode, StatusList, Trust, Verifier};

/// 1 Jan 2027.
const NOW: i64 = 1_798_761_600_000;

fn live_spki() -> Vec<u8> {
    let k = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    // SubjectPublicKeyInfo for P-256: fixed 26-byte prefix + the point
    let mut spki = hex_prefix();
    spki.extend_from_slice(k.public_key().as_ref());
    spki
}

fn hex_prefix() -> Vec<u8> {
    vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]
}

fn policy() -> AndroidPolicy {
    AndroidPolicy {
        packages: vec![testkit::PACKAGE.into()],
        signers: vec![testkit::SIGNER],
        min_os_version: android::ANDROID_17,
        min_patch_level: 202_601,
        strongbox_required: false,
    }
}

struct Env {
    pki: TestPki,
    dev: Verifier,
    status: StatusList,
}

fn env() -> Env {
    let pki = TestPki::new(NOW);
    let dev = Verifier::new(pki.trust(), Mode::Development).unwrap();
    Env {
        pki,
        dev,
        status: StatusList::parse(br#"{"entries":{}}"#, NOW, true, 48 * 3_600_000).unwrap(),
    }
}

impl Env {
    fn android(
        &self,
        kd: &KeyDesc,
        o: &ChainOpts,
        p: &AndroidPolicy,
    ) -> humid_attest::Result<android::AndroidAttested> {
        let spki = live_spki();
        let chain = self.pki.android_chain(kd, &spki, o);
        android::verify(
            &self.dev,
            &chain,
            &kd.challenge,
            &spki,
            p,
            &self.status,
            NOW,
        )
    }
    fn code(&self, kd: &KeyDesc, o: &ChainOpts, p: &AndroidPolicy) -> &'static str {
        self.android(kd, o, p).unwrap_err().code
    }
}

const CH: &[u8] = &[7u8; 32];

#[test]
fn android_live_keys_in_strongbox_and_tee() {
    let e = env();
    let sb = e
        .android(&KeyDesc::strongbox(CH), &ChainOpts::default(), &policy())
        .unwrap();
    assert_eq!(sb.proven(), "android-strongbox");
    assert_eq!(sb.patch_level, 202_609);
    assert_eq!(sb.serials.len(), 3);
    let tee = e
        .android(&KeyDesc::tee(CH), &ChainOpts::default(), &policy())
        .unwrap();
    assert_eq!(tee.proven(), "android-tee");
    // StrongBox without EC_CURVE (some chips state only the size): the leaf's key settles it
    let mut kd = KeyDesc::strongbox(CH);
    kd.curve = None;
    e.android(&kd, &ChainOpts::default(), &policy()).unwrap();
}

#[test]
fn android_downgrades_are_refused() {
    let e = env();
    let o = ChainOpts::default();
    let mut sb_only = policy();
    sb_only.strongbox_required = true;
    assert_eq!(
        e.code(&KeyDesc::tee(CH), &o, &sb_only),
        "not_strongbox",
        "TEE where StrongBox is required"
    );
    let mut mixed = KeyDesc::strongbox(CH);
    mixed.keymint_level = 1;
    assert_eq!(e.code(&mixed, &o, &sb_only), "not_strongbox");
    for (a, k) in [(0, 0), (1, 0), (0, 1), (100, 100), (3, 3)] {
        let mut kd = KeyDesc::tee(CH);
        kd.attestation_level = a;
        kd.keymint_level = k;
        assert_eq!(e.code(&kd, &o, &policy()), "software_key", "{a}/{k}");
    }
}

#[test]
fn android_key_rules_match_the_gate_keys() {
    let e = env();
    let o = ChainOpts::default();
    let p = policy();
    let with = |f: &dyn Fn(&mut KeyDesc)| {
        let mut kd = KeyDesc::strongbox(CH);
        f(&mut kd);
        e.code(&kd, &o, &p)
    };
    assert_eq!(with(&|k| k.user_auth_type = Some(3)), "pin_allowed");
    assert_eq!(with(&|k| k.user_auth_type = Some(1)), "pin_allowed");
    assert_eq!(with(&|k| k.user_auth_type = None), "no_biometric");
    assert_eq!(with(&|k| k.no_auth_required = true), "no_biometric");
    assert_eq!(with(&|k| k.auth_timeout = Some(30)), "not_per_use");
    assert_eq!(with(&|k| k.allow_while_on_body = true), "not_per_use");
    assert_eq!(
        with(&|k| k.unlocked_device_required = false),
        "unlocked_use"
    );
    assert_eq!(
        with(&|k| k.purposes = vec![2, 3]),
        "bad_key",
        "sign and verify"
    );
    assert_eq!(
        with(&|k| k.purposes = vec![2, 7]),
        "bad_key",
        "sign and attest"
    );
    assert_eq!(with(&|k| k.purposes = vec![3]), "bad_key");
    assert_eq!(with(&|k| k.algorithm = 1), "bad_key", "RSA");
    assert_eq!(with(&|k| k.curve = Some(2)), "bad_key", "P-384");
    assert_eq!(with(&|k| k.origin = Some(2)), "imported_key");
    assert_eq!(with(&|k| k.origin = None), "imported_key");
    // auth timeout 0 is per use
    let mut kd = KeyDesc::strongbox(CH);
    kd.auth_timeout = Some(0);
    e.android(&kd, &o, &p).unwrap();
}

#[test]
fn android_device_rules() {
    let e = env();
    let o = ChainOpts::default();
    let p = policy();
    let with = |f: &dyn Fn(&mut KeyDesc)| {
        let mut kd = KeyDesc::strongbox(CH);
        f(&mut kd);
        e.code(&kd, &o, &p)
    };
    assert_eq!(with(&|k| k.device_locked = false), "unlocked_device");
    assert_eq!(
        with(&|k| k.boot_state = 1),
        "unlocked_device",
        "self-signed (yellow)"
    );
    assert_eq!(
        with(&|k| k.boot_state = 2),
        "unlocked_device",
        "unverified (orange)"
    );
    assert_eq!(with(&|k| k.os_version = Some(160_000)), "old_android");
    assert_eq!(with(&|k| k.os_version = None), "old_android");
    assert_eq!(with(&|k| k.patch_level = Some(202_512)), "old_patch");
    assert_eq!(with(&|k| k.patch_level = None), "old_patch");
}

#[test]
fn android_app_rules() {
    let e = env();
    let o = ChainOpts::default();
    let mut kd = KeyDesc::strongbox(CH);
    kd.package = "com.example.bot".into();
    assert_eq!(e.code(&kd, &o, &policy()), "wrong_app");
    let mut kd = KeyDesc::strongbox(CH);
    kd.signer = [9; 32];
    assert_eq!(e.code(&kd, &o, &policy()), "wrong_app", "a re-signed copy");
    let mut none = policy();
    none.signers.clear();
    assert_eq!(e.code(&KeyDesc::strongbox(CH), &o, &none), "not_configured");
    // the leaked test key, even when a policy lists it
    let mut kd = KeyDesc::strongbox(CH);
    kd.signer = android::REVOKED_SIGNERS[0];
    let mut lists_it = policy();
    lists_it.signers.push(android::REVOKED_SIGNERS[0]);
    assert_eq!(e.code(&kd, &o, &lists_it), "revoked_signer");
    assert_ne!(android::HUMID_RELEASE_SIGNER, android::REVOKED_SIGNERS[0]);
}

#[test]
fn android_challenge_key_and_chain() {
    let e = env();
    let o = ChainOpts::default();
    let kd = KeyDesc::strongbox(CH);
    let spki = live_spki();
    let chain = e.pki.android_chain(&kd, &spki, &o);
    let p = policy();
    let v = |ch: &[u8], key: &[u8], c: &[Vec<u8>], now| {
        android::verify(&e.dev, c, ch, key, &p, &e.status, now)
    };
    v(CH, &spki, &chain, NOW).unwrap();
    assert_eq!(
        v(&[8; 32], &spki, &chain, NOW).unwrap_err().code,
        "wrong_challenge"
    );
    assert_eq!(
        v(CH, &live_spki(), &chain, NOW).unwrap_err().code,
        "wrong_key"
    );
    assert_eq!(
        e.code(
            &kd,
            &ChainOpts {
                intermediate_expired_ms: Some(86_400_000),
                ..ChainOpts::default()
            },
            &p
        ),
        "bad_attestation",
        "expired intermediate"
    );
    assert_eq!(
        e.code(
            &kd,
            &ChainOpts {
                intermediate_not_ca: true,
                ..ChainOpts::default()
            },
            &p
        ),
        "bad_attestation"
    );
    assert_eq!(
        e.code(
            &kd,
            &ChainOpts {
                description_on_intermediate: true,
                ..ChainOpts::default()
            },
            &p
        ),
        "bad_attestation"
    );
    // a chain from another (unknown) root
    let other = TestPki::new(NOW);
    let foreign = other.android_chain(&kd, &spki, &o);
    assert_eq!(
        v(CH, &spki, &foreign, NOW).unwrap_err().code,
        "untrusted_root"
    );
    // too long, too big
    let long: Vec<Vec<u8>> = std::iter::repeat_n(chain[0].clone(), 11).collect();
    assert_eq!(
        v(CH, &spki, &long, NOW).unwrap_err().code,
        "bad_attestation"
    );
}

#[test]
fn android_revocation_list() {
    let e = env();
    let kd = KeyDesc::strongbox(CH);
    let spki = live_spki();
    let chain = e.pki.android_chain(&kd, &spki, &ChainOpts::default());
    let p = policy();
    let serials = android::read_chain(&e.dev, &chain, NOW).unwrap().serials();
    let listed = StatusList::parse(
        format!(
            r#"{{"entries":{{"{}":{{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}}}}"#,
            serials[1].to_uppercase()
        )
        .as_bytes(),
        NOW,
        true,
        48 * 3_600_000,
    )
    .unwrap();
    assert_eq!(
        android::verify(&e.dev, &chain, CH, &spki, &p, &listed, NOW)
            .unwrap_err()
            .code,
        "revoked"
    );
    // a stored chain is re-checked against today's list (sign-in, schedule)
    android::recheck(&e.dev, &chain, &e.status, NOW).unwrap();
    assert_eq!(
        android::recheck(&e.dev, &chain, &listed, NOW)
            .unwrap_err()
            .code,
        "revoked"
    );
    // a required list that is missing or stale fails closed
    let missing = StatusList::empty(true, 1000);
    assert_eq!(
        android::verify(&e.dev, &chain, CH, &spki, &p, &missing, NOW)
            .unwrap_err()
            .code,
        "status_unavailable"
    );
    assert_eq!(
        android::recheck(&e.dev, &chain, &e.status, NOW + 49 * 3_600_000)
            .unwrap_err()
            .code,
        "status_stale"
    );
}

/* ------------------------------- the test root can't reach production ------------------------------- */

#[test]
fn the_test_root_is_impossible_in_production() {
    let pki = TestPki::new(NOW);
    // 1. a production verifier refuses to be built with it
    assert_eq!(
        Verifier::new(pki.trust(), Mode::Production)
            .unwrap_err()
            .code,
        "test_root_in_production"
    );
    // 2. a production verifier over the pinned roots refuses what it makes, on both platforms
    let prod = Verifier::new(Trust::pinned(), Mode::Production).unwrap();
    let kd = KeyDesc::strongbox(CH);
    let spki = live_spki();
    let chain = pki.android_chain(&kd, &spki, &ChainOpts::default());
    let status = StatusList::parse(br#"{"entries":{}}"#, NOW, true, 1 << 40).unwrap();
    assert_eq!(
        android::verify(&prod, &chain, CH, &spki, &policy(), &status, NOW)
            .unwrap_err()
            .code,
        "untrusted_root"
    );
    let key = AppAttestKey::generate();
    let cdh = [3; 32];
    let obj = pki.app_attestation(&key, &cdh, testkit::APP_ID, Environment::Production, "26.0");
    assert_eq!(
        apple::verify_attestation(&prod, &obj, &cdh, &apple_policy(), NOW)
            .unwrap_err()
            .code,
        "untrusted_root"
    );
    // 3. a test anchor that copies a pinned root's *name* doesn't count as pinned
    assert!(!pki.android_anchor().is_pinned());
    assert!(!pki.apple_anchor().is_pinned());
}

/* ------------------------------- App Attest ------------------------------- */

fn apple_policy() -> ApplePolicy {
    ApplePolicy {
        app_ids: vec![testkit::APP_ID.into()],
        environment: Environment::Production,
        min_os_major: 26,
    }
}

#[test]
fn app_attest_attestation_then_assertions() {
    let e = env();
    let key = AppAttestKey::generate();
    let spki = live_spki();
    let cdh = apple::enrolment_client_data_hash(CH, &spki);
    let obj = e
        .pki
        .app_attestation(&key, &cdh, testkit::APP_ID, Environment::Production, "26.1");
    let a = apple::verify_attestation(&e.dev, &obj, &cdh, &apple_policy(), NOW).unwrap();
    assert_eq!(a.os_version, "26.1");
    assert_eq!(a.public_key, key.point());
    // per-check assertions, counter strictly increasing
    let check = [5u8; 32];
    let s1 = key.assertion(testkit::APP_ID, &check, 1);
    assert_eq!(
        apple::verify_assertion(&s1, &a, &check, 0).unwrap().counter,
        1
    );
    assert_eq!(
        apple::verify_assertion(&s1, &a, &check, 1)
            .unwrap_err()
            .code,
        "assertion_replayed"
    );
    let s5 = key.assertion(testkit::APP_ID, &check, 5);
    assert_eq!(
        apple::verify_assertion(&s5, &a, &check, 1).unwrap().counter,
        5
    );
    let s3 = key.assertion(testkit::APP_ID, &check, 3);
    assert_eq!(
        apple::verify_assertion(&s3, &a, &check, 5)
            .unwrap_err()
            .code,
        "assertion_replayed",
        "counter rollback"
    );
    // another key, another app, another check
    let other = AppAttestKey::generate().assertion(testkit::APP_ID, &check, 9);
    assert_eq!(
        apple::verify_assertion(&other, &a, &check, 5)
            .unwrap_err()
            .code,
        "bad_assertion"
    );
    let wrong_app = key.assertion("OTHERTEAM.app.humid.vault", &check, 9);
    assert_eq!(
        apple::verify_assertion(&wrong_app, &a, &check, 5)
            .unwrap_err()
            .code,
        "bad_assertion"
    );
    assert_eq!(
        apple::verify_assertion(&key.assertion(testkit::APP_ID, &check, 9), &a, &[6; 32], 5)
            .unwrap_err()
            .code,
        "bad_assertion"
    );
}

#[test]
fn app_attest_refusals() {
    let e = env();
    let key = AppAttestKey::generate();
    let cdh = [4u8; 32];
    let p = apple_policy();
    let code = |obj: &[u8], c: &[u8; 32], pol: &ApplePolicy| {
        apple::verify_attestation(&e.dev, obj, c, pol, NOW)
            .unwrap_err()
            .code
    };
    let good = e
        .pki
        .app_attestation(&key, &cdh, testkit::APP_ID, Environment::Production, "26.0");
    assert_eq!(code(&good, &[9; 32], &p), "wrong_challenge");
    let dev = e.pki.app_attestation(
        &key,
        &cdh,
        testkit::APP_ID,
        Environment::Development,
        "26.0",
    );
    assert_eq!(
        code(&dev, &cdh, &p),
        "wrong_environment",
        "development AAGUID, production policy"
    );
    let other_app = e.pki.app_attestation(
        &key,
        &cdh,
        "OTHERTEAM.app.humid.vault",
        Environment::Production,
        "26.0",
    );
    assert_eq!(code(&other_app, &cdh, &p), "wrong_app");
    let old = e
        .pki
        .app_attestation(&key, &cdh, testkit::APP_ID, Environment::Production, "18.6");
    assert_eq!(code(&old, &cdh, &p), "old_ios");
    // a development policy on a development server takes development builds
    let mut dp = apple_policy();
    dp.environment = Environment::Development;
    apple::verify_attestation(&e.dev, &dev, &cdh, &dp, NOW).unwrap();
    // expired: a year later the credential certificate has lapsed
    assert_eq!(
        apple::verify_attestation(&e.dev, &good, &cdh, &p, NOW + 400 * 86_400_000)
            .unwrap_err()
            .code,
        "bad_attestation"
    );
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Random bytes and random mutations never panic and are never accepted.
    #[test]
    fn hostile_input_is_refused_never_a_panic(junk in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096), at in 0usize..4096, bit in 0u8..8) {
        let pki = TestPki::new(NOW);
        let dev = Verifier::new(pki.trust(), Mode::Development).unwrap();
        let status = StatusList::empty(false, 1);
        let spki = live_spki();
        proptest::prop_assert!(android::verify(&dev, &[junk.clone(), junk.clone()], CH, &spki, &policy(), &status, NOW).is_err());
        proptest::prop_assert!(apple::verify_attestation(&dev, &junk, &[0; 32], &apple_policy(), NOW).is_err());
        let _ = humid_attest::cbor::decode(&junk);
        let _ = humid_attest::x509::Cert::parse(&junk);
        let _ = android::KeyDescription::parse(&junk);
        // one flipped bit in a genuine chain
        let mut chain = pki.android_chain(&KeyDesc::strongbox(CH), &spki, &ChainOpts::default());
        let i = at % chain[0].len();
        chain[0][i] ^= 1 << bit;
        proptest::prop_assert!(android::verify(&dev, &chain, CH, &spki, &policy(), &status, NOW).is_err());
    }
}
