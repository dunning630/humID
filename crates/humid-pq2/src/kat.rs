//! Known-answer tests and cross-checks.
//!
//! * NIST ACVP (pinned ACVP-Server commit, `tests/fixtures/acvp/` shared with the 4.x JS
//!   KATs, plus `tests/fixtures/acvp-pq2/`; both made by `tools/acvp-vectors.mjs`):
//!   ML-KEM-1024 keyGen / encap / decap / key checks, ML-DSA-87 keyGen / sigGen (deterministic
//!   and hedged) / sigVer, SLH-DSA-SHA2-256s keyGen / sigGen / sigVer, KMAC-256 (AFT + MVT,
//!   XOF and not), SHA3-512 (AFT + Monte Carlo), SHAKE-256 (AFT + VOT).
//! * NIST SP 800-185 KMAC256 samples 4–6.
//! * RFC 8452 C.2/C.3 AES-256-GCM-SIV, NIST CAVS AES-256-GCM, RFC 7748 X25519
//!   (`crates/humid-pq2/tests/vectors/`, re-checked with OpenSSL by tools/pq2-rfc-vectors.py).
//! * Cross-checks against the JS the 4.x app ships (@noble), including HUMID-PQ2's own
//!   combiner, KDF and boxes computed independently in JS (tools/pq2-noble-vectors.mjs).

#![allow(deprecated)] // the expanded-key forms are what ACVP's keyGen/sigGen vectors carry

use std::path::PathBuf;

use flate2::read::GzDecoder;
use ml_dsa::MlDsa87;
use ml_kem::{Decapsulate, ExpandedKeyEncoding, KeyExport, MlKem1024};
use serde_json::Value;
use slh_dsa::Sha2_256s;

use crate::aead::{
    gcm_cipher, gcm_open, gcm_seal, open_at_rest, open_sealed, seal_at_rest_with_nonce,
    seal_to_with, siv_open, siv_seal,
};
use crate::encoding::{HEADER_LEN, ObjectType};
use crate::hash::{key_id, labelled_hash, sha3_512, shake256};
use crate::kdf::{kdf_into, kmac256};
use crate::kem::{KemCiphertext, KemSecretKey};
use crate::rng::FixedRng;
use crate::secret::{Secret, Secret32};
use crate::sign::{MlDsaSigningKey, SlhSigningKey, mldsa_sign_expanded, slh_sign};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn acvp(dir: &str, name: &str) -> Value {
    let p = root()
        .join("../../tests/fixtures")
        .join(dir)
        .join(format!("{name}.json.gz"));
    let f = std::fs::File::open(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let v: Value = serde_json::from_reader(GzDecoder::new(f)).unwrap();
    assert!(
        v["source"]
            .as_str()
            .unwrap()
            .starts_with("https://github.com/usnistgov/ACVP-Server/blob/")
    );
    v
}

fn vectors(name: &str) -> Value {
    let p = root().join("tests/vectors").join(name);
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))).unwrap()
}

fn a<const N: usize>(v: &Value) -> [u8; N] {
    h(v).try_into().unwrap()
}

/// Every (group, test) pair whose group matches `keep`.
fn cases<'a>(
    doc: &'a Value,
    keep: impl Fn(&Value) -> bool + 'a,
) -> impl Iterator<Item = (&'a Value, &'a Value)> + 'a {
    doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(move |g| keep(g))
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

fn tc(t: &Value) -> String {
    format!("tcId {} {}", t["tcId"], t["reason"].as_str().unwrap_or(""))
}

/* ------------------------------ ML-KEM-1024 ------------------------------ */

#[test]
fn mlkem1024_keygen() {
    let doc = acvp("acvp", "ML-KEM-keyGen-FIPS203");
    let mut n = 0;
    for (_, t) in cases(&doc, |g| g["parameterSet"] == "ML-KEM-1024") {
        let mut seed = [0u8; 96];
        seed[..32].copy_from_slice(&h(&t["d"]));
        seed[32..64].copy_from_slice(&h(&t["z"]));
        let k = KemSecretKey::from_seed(&Secret::new(&mut seed));
        assert_eq!(
            k.public_key().to_bytes()[HEADER_LEN..HEADER_LEN + 1568],
            h(&t["ek"])[..],
            "{}",
            tc(t)
        );
        assert_eq!(
            k.dk.to_expanded_bytes().as_slice(),
            &h(&t["dk"])[..],
            "{}",
            tc(t)
        );
        n += 1;
    }
    assert!(n >= 10);
}

#[test]
fn mlkem1024_encap_decap_and_key_checks() {
    let doc = acvp("acvp", "ML-KEM-encapDecap-FIPS203");
    let (mut enc, mut dec, mut ekc, mut dkc) = (0, 0, 0, 0);
    for (g, t) in cases(&doc, |g| g["parameterSet"] == "ML-KEM-1024") {
        match g["function"].as_str().unwrap() {
            "encapsulation" => {
                let ek = ml_kem::EncapsulationKey::<MlKem1024>::new(
                    &h(&t["ek"])[..].try_into().unwrap(),
                )
                .unwrap();
                let (c, k) = ek.encapsulate_deterministic(&a::<32>(&t["m"]).into());
                assert_eq!(c.as_slice(), &h(&t["c"])[..], "{}", tc(t));
                assert_eq!(k.as_slice(), &h(&t["k"])[..], "{}", tc(t));
                enc += 1;
            }
            "decapsulation" => {
                let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_expanded_bytes(
                    &h(&t["dk"])[..].try_into().unwrap(),
                )
                .unwrap();
                let k = dk.decapsulate(&h(&t["c"])[..].try_into().unwrap());
                assert_eq!(k.as_slice(), &h(&t["k"])[..], "{}", tc(t));
                dec += 1;
            }
            "encapsulationKeyCheck" => {
                let ek = h(&t["ek"]);
                let ok = ek.len() == 1568
                    && ml_kem::EncapsulationKey::<MlKem1024>::new(&ek[..].try_into().unwrap())
                        .is_ok();
                assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "{}", tc(t));
                // and through the suite's own decoder
                let mut enc_pk = crate::encoding::header(ObjectType::KEM_PUBLIC_KEY).to_vec();
                enc_pk.extend_from_slice(&ek);
                enc_pk.extend_from_slice(&[9u8; 32]);
                assert_eq!(
                    crate::kem::KemPublicKey::from_bytes(&enc_pk).is_ok(),
                    ok,
                    "{}",
                    tc(t)
                );
                ekc += 1;
            }
            "decapsulationKeyCheck" => {
                let dk = h(&t["dk"]);
                let ok = dk.len() == 3168
                    && ml_kem::DecapsulationKey::<MlKem1024>::from_expanded_bytes(
                        &dk[..].try_into().unwrap(),
                    )
                    .is_ok();
                assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "{}", tc(t));
                dkc += 1;
            }
            other => panic!("{other}"),
        }
    }
    assert!(enc >= 10 && dec >= 10 && ekc >= 10 && dkc >= 10);
}

/* ------------------------------- ML-DSA-87 ------------------------------- */

#[test]
fn mldsa87_keygen() {
    let doc = acvp("acvp", "ML-DSA-keyGen-FIPS204");
    let mut n = 0;
    for (_, t) in cases(&doc, |g| g["parameterSet"] == "ML-DSA-87") {
        let mut xi = a::<32>(&t["seed"]);
        let k = MlDsaSigningKey::from_seed(&Secret32::new(&mut xi));
        assert_eq!(&k.verifying_key().raw()[..], &h(&t["pk"])[..], "{}", tc(t));
        assert_eq!(
            k.sk.expanded_key().to_expanded().as_slice(),
            &h(&t["sk"])[..],
            "{}",
            tc(t)
        );
        assert_eq!(k.seed().expose()[..], h(&t["seed"])[..]);
        n += 1;
    }
    assert!(n >= 10);
}

#[test]
fn mldsa87_siggen_deterministic_and_hedged() {
    let doc = acvp("acvp", "ML-DSA-sigGen-FIPS204");
    let (mut det, mut hedged) = (0, 0);
    for (g, t) in cases(&doc, |g| g["parameterSet"] == "ML-DSA-87") {
        let sk = ml_dsa::ExpandedSigningKey::<MlDsa87>::from_expanded(
            &h(&t["sk"])[..].try_into().unwrap(),
        );
        let rnd = if g["deterministic"].as_bool().unwrap() {
            det += 1;
            [0u8; 32]
        } else {
            hedged += 1;
            a::<32>(&t["rnd"])
        };
        let sig =
            mldsa_sign_expanded(&sk, &h(&t["message"]), &h(&t["context"]), Some(&rnd)).unwrap();
        assert_eq!(&sig[..], &h(&t["signature"])[..], "{}", tc(t));
        // and the verifying key it implies verifies it
        let vk = crate::sign::MlDsaVerifyingKey::from_raw(&h(&t["pk"])).unwrap();
        vk.verify_ctx(&h(&t["message"]), &h(&t["context"]), &sig[..])
            .unwrap();
    }
    assert!(det >= 5 && hedged >= 5);
}

#[test]
fn mldsa87_sigver() {
    let doc = acvp("acvp", "ML-DSA-sigVer-FIPS204");
    let (mut good, mut bad) = (0, 0);
    for (_, t) in cases(&doc, |g| g["parameterSet"] == "ML-DSA-87") {
        let vk = crate::sign::MlDsaVerifyingKey::from_raw(&h(&t["pk"])).unwrap();
        let ok = vk
            .verify_ctx(&h(&t["message"]), &h(&t["context"]), &h(&t["signature"]))
            .is_ok();
        assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "{}", tc(t));
        if ok { good += 1 } else { bad += 1 }
    }
    assert!(good >= 1 && bad >= 5);
}

/* --------------------------- SLH-DSA-SHA2-256s --------------------------- */

#[test]
fn slh_dsa_sha2_256s_keygen() {
    let doc = acvp("acvp-pq2", "SLH-DSA-keyGen-FIPS205");
    let mut n = 0;
    for (_, t) in cases(&doc, |g| g["parameterSet"] == "SLH-DSA-SHA2-256s") {
        let mut seed = [0u8; 96];
        seed[..32].copy_from_slice(&h(&t["skSeed"]));
        seed[32..64].copy_from_slice(&h(&t["skPrf"]));
        seed[64..].copy_from_slice(&h(&t["pkSeed"]));
        let k = SlhSigningKey::from_seed(&Secret::new(&mut seed));
        assert_eq!(&k.verifying_key().raw()[..], &h(&t["pk"])[..], "{}", tc(t));
        assert_eq!(k.sk.to_bytes().as_slice(), &h(&t["sk"])[..], "{}", tc(t));
        n += 1;
    }
    assert!(n >= 10);
}

#[test]
fn slh_dsa_sha2_256s_siggen() {
    let doc = acvp("acvp-pq2", "SLH-DSA-sigGen-FIPS205");
    let (mut det, mut hedged) = (0, 0);
    for (g, t) in cases(&doc, |g| g["parameterSet"] == "SLH-DSA-SHA2-256s") {
        let sk = slh_dsa::SigningKey::<Sha2_256s>::try_from(&h(&t["sk"])[..]).unwrap();
        let rnd: Option<[u8; 32]> = if g["deterministic"].as_bool().unwrap() {
            det += 1;
            None
        } else {
            hedged += 1;
            Some(a::<32>(&t["additionalRandomness"]))
        };
        let sig = slh_sign(&sk, &h(&t["message"]), &h(&t["context"]), rnd.as_ref()).unwrap();
        assert_eq!(&sig[..], &h(&t["signature"])[..], "{}", tc(t));
    }
    assert!(det >= 2 && hedged >= 2);
}

#[test]
fn slh_dsa_sha2_256s_sigver() {
    let doc = acvp("acvp-pq2", "SLH-DSA-sigVer-FIPS205");
    let mut reasons = std::collections::BTreeSet::new();
    for (_, t) in cases(&doc, |g| g["parameterSet"] == "SLH-DSA-SHA2-256s") {
        let vk = crate::sign::SlhVerifyingKey::from_raw(&h(&t["pk"])).unwrap();
        let ok = vk
            .verify_ctx(&h(&t["message"]), &h(&t["context"]), &h(&t["signature"]))
            .is_ok();
        assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "{}", tc(t));
        reasons.insert(t["reason"].as_str().unwrap().to_owned());
    }
    assert!(reasons.len() >= 7, "{reasons:?}");
}

/* ------------------------- KMAC256 / SHA3 / SHAKE ------------------------- */

/// KMAC256 with an output of `bits` (the ACVP vectors include lengths that aren't whole
/// bytes: L enters the computation as a bit count; whole output bytes are compared).
fn kmac_bits(key: &[u8], msg: &[u8], custom: &[u8], bits: usize, xof: bool) -> Vec<u8> {
    // Re-implemented from SP 800-185 with the crate's cSHAKE, independent of `kmac256`'s
    // L = 8·len, so a whole-byte KAT can't mask an L-encoding bug.
    use cshake::CShake256;
    use cshake::digest::{ExtendableOutput, Update, XofReader};
    fn le(x: u64) -> Vec<u8> {
        let b = x.to_be_bytes();
        let i = b.iter().take_while(|&&c| c == 0).count().min(7);
        let mut v = vec![(8 - i) as u8];
        v.extend_from_slice(&b[i..]);
        v
    }
    fn re(x: u64) -> Vec<u8> {
        let b = x.to_be_bytes();
        let i = b.iter().take_while(|&&c| c == 0).count().min(7);
        let mut v = b[i..].to_vec();
        v.push((8 - i) as u8);
        v
    }
    let mut c = CShake256::new_with_function_name(b"KMAC", custom);
    let mut bp = le(136);
    bp.extend(le(key.len() as u64 * 8));
    bp.extend_from_slice(key);
    while !bp.len().is_multiple_of(136) {
        bp.push(0);
    }
    c.update(&bp);
    c.update(msg);
    c.update(&re(if xof { 0 } else { bits as u64 }));
    let mut out = vec![0u8; bits / 8];
    c.finalize_xof().read(&mut out);
    out
}

#[test]
fn kmac256_acvp() {
    let doc = acvp("acvp-pq2", "KMAC-256-1.0");
    let mut n = 0;
    for (g, t) in cases(&doc, |_| true) {
        let custom = if g["hexCustomization"].as_bool().unwrap() {
            h(&t["customizationHex"])
        } else {
            t["customization"].as_str().unwrap().as_bytes().to_vec()
        };
        let bits = t["macLen"].as_u64().unwrap() as usize;
        let xof = g["xof"].as_bool().unwrap();
        let (key, msg) = (h(&t["key"]), h(&t["msg"]));
        let got = kmac_bits(&key, &msg, &custom, bits, xof);
        let want = h(&t["mac"]);
        let same = got[..] == want[..bits / 8];
        let expected = t["testPassed"].as_bool().unwrap_or(true);
        assert_eq!(same, expected, "{}", tc(t));
        if bits.is_multiple_of(8) {
            // the suite's own KMAC agrees
            let mut o = vec![0u8; bits / 8];
            kmac256(&key, &msg, &custom, &mut o, xof).unwrap();
            assert_eq!(o, got);
        }
        n += 1;
    }
    assert!(n >= 10);
}

#[test]
fn kmac256_sp800_185_samples() {
    // NIST SP 800-185 KMAC samples 4, 5 and 6 (KMAC256; 6 is with S, 5 without).
    let key: Vec<u8> = (0x40u8..=0x5f).collect();
    let d200: Vec<u8> = (0u8..200).collect();
    let mut out = [0u8; 64];
    kmac256(
        &key,
        &[0, 1, 2, 3],
        b"My Tagged Application",
        &mut out,
        false,
    )
    .unwrap();
    assert_eq!(
        hex::encode_upper(out),
        "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"
    );
    kmac256(&key, &d200, b"", &mut out, false).unwrap();
    assert_eq!(
        hex::encode_upper(out),
        "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"
    );
    kmac256(&key, &d200, b"My Tagged Application", &mut out, false).unwrap();
    assert_eq!(
        hex::encode_upper(out),
        "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"
    );
    // KMACXOF256 samples 4–6
    kmac256(
        &key,
        &[0, 1, 2, 3],
        b"My Tagged Application",
        &mut out,
        true,
    )
    .unwrap();
    assert_eq!(
        hex::encode_upper(out),
        "1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B"
    );
    kmac256(&key, &d200, b"", &mut out, true).unwrap();
    assert_eq!(
        hex::encode_upper(out),
        "FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B"
    );
    kmac256(&key, &d200, b"My Tagged Application", &mut out, true).unwrap();
    assert_eq!(
        hex::encode_upper(out),
        "D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D"
    );
}

#[test]
fn sha3_512_acvp() {
    let doc = acvp("acvp-pq2", "SHA3-512-2.0");
    let (mut aft, mut mct) = (0, 0);
    for (g, t) in cases(&doc, |_| true) {
        match g["testType"].as_str().unwrap() {
            "AFT" => {
                let len = t["len"].as_u64().unwrap() as usize / 8;
                let msg = h(&t["msg"]);
                assert_eq!(sha3_512(&msg[..len])[..], h(&t["md"])[..], "{}", tc(t));
                aft += 1;
            }
            "MCT" => {
                // ACVP SHA-3 Monte Carlo ("standard"): MD = seed; 100 × { 1000 × MD = H(MD) }
                let mut md = h(&t["msg"]);
                for r in t["resultsArray"].as_array().unwrap() {
                    for _ in 0..1000 {
                        md = sha3_512(&md).to_vec();
                    }
                    assert_eq!(md, h(&r["md"]));
                }
                mct += 1;
            }
            other => panic!("{other}"),
        }
    }
    assert!(aft >= 40 && mct == 1);
}

#[test]
fn shake256_acvp() {
    let doc = acvp("acvp-pq2", "SHAKE-256-1.0");
    let mut n = 0;
    for (_, t) in cases(&doc, |_| true) {
        let len = t["len"].as_u64().unwrap() as usize / 8;
        let out_len = t["outLen"].as_u64().unwrap() as usize / 8;
        let msg = h(&t["msg"]);
        let mut out = vec![0u8; out_len];
        shake256(&msg[..len], &mut out);
        assert_eq!(out, h(&t["md"]), "{}", tc(t));
        n += 1;
    }
    assert!(n >= 80);
}

/* ------------------------- AES-256-GCM-SIV / GCM ------------------------- */

#[test]
fn aes256_gcm_siv_rfc8452() {
    let v = vectors("aes-256-gcm-siv-rfc8452.json");
    let mut n = 0;
    for t in v["vectors"].as_array().unwrap() {
        let mut k = a::<32>(&t["key"]);
        let key = Secret32::new(&mut k);
        let nonce = a::<12>(&t["nonce"]);
        let ct = siv_seal(&key, &nonce, &h(&t["aad"]), &h(&t["plaintext"])).unwrap();
        assert_eq!(ct, h(&t["ciphertext"]), "{t}");
        assert_eq!(
            &siv_open(&key, &nonce, &h(&t["aad"]), &ct).unwrap()[..],
            &h(&t["plaintext"])[..]
        );
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(siv_open(&key, &nonce, &h(&t["aad"]), &bad).is_err());
        n += 1;
    }
    assert!(n >= 20);
}

#[test]
fn aes256_gcm_cavs() {
    let v = vectors("aes-256-gcm-cavs.json");
    let mut n = 0;
    for t in v["vectors"].as_array().unwrap() {
        let mut k = a::<32>(&t["key"]);
        let c = gcm_cipher(&Secret32::new(&mut k));
        let nonce = a::<12>(&t["nonce"]);
        let mut want = h(&t["ciphertext"]);
        want.extend(h(&t["tag"]));
        let ct = gcm_seal(&c, &nonce, &h(&t["aad"]), &h(&t["plaintext"])).unwrap();
        assert_eq!(ct, want, "{t}");
        assert_eq!(
            &gcm_open(&c, &nonce, &h(&t["aad"]), &ct).unwrap()[..],
            &h(&t["plaintext"])[..]
        );
        n += 1;
    }
    assert!(n >= 20);
}

#[test]
fn x25519_rfc7748() {
    let v = vectors("x25519-rfc7748.json");
    for t in v["vectors"].as_array().unwrap() {
        assert_eq!(
            x25519_dalek::x25519(a(&t["scalar"]), a(&t["u"])),
            a::<32>(&t["out"])
        );
        if !t["public"].is_null() {
            let s = x25519_dalek::StaticSecret::from(a::<32>(&t["scalar"]));
            assert_eq!(
                x25519_dalek::PublicKey::from(&s).to_bytes(),
                a::<32>(&t["public"])
            );
        }
    }
}

/* ------------------------- cross-checks with noble ------------------------ */

#[test]
fn noble_mlkem_mldsa_x25519_slh() {
    let v = vectors("noble-interop.json");
    for t in v["mlkem"].as_array().unwrap() {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&h(&t["d"]));
        seed[32..].copy_from_slice(&h(&t["z"]));
        let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(seed.into());
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            &h(&t["ek"])[..]
        );
        assert_eq!(sha3_512(&dk.to_expanded_bytes())[..], h(&t["dkSha3"])[..]);
        let (c, k) = dk
            .encapsulation_key()
            .encapsulate_deterministic(&a::<32>(&t["m"]).into());
        assert_eq!(c.as_slice(), &h(&t["ct"])[..]);
        assert_eq!(k.as_slice(), &h(&t["ss"])[..]);
        // implicit rejection: both reject a random ciphertext to the same pseudo-random key
        let bad = dk.decapsulate(&h(&t["badCt"])[..].try_into().unwrap());
        assert_eq!(bad.as_slice(), &h(&t["badSs"])[..]);
    }
    for t in v["mldsa"].as_array().unwrap() {
        let mut xi = a::<32>(&t["xi"]);
        let k = MlDsaSigningKey::from_seed(&Secret32::new(&mut xi));
        assert_eq!(&k.verifying_key().raw()[..], &h(&t["pk"])[..]);
        let (msg, ctx) = (h(&t["msg"]), h(&t["ctx"]));
        // the hedged path, with noble's rnd: the randomness is used identically
        let s = k.sign_ctx(&msg, &ctx, Some(&a(&t["rnd"]))).unwrap();
        assert_eq!(&s[..], &h(&t["sigHedged"])[..]);
        let s = k.sign_ctx(&msg, &ctx, Some(&[0u8; 32])).unwrap();
        assert_eq!(&s[..], &h(&t["sigDeterministic"])[..]);
        k.verifying_key()
            .verify_ctx(&msg, &ctx, &h(&t["sigHedged"]))
            .unwrap();
        // the ctx is SUITE ‖ type ‖ label, as `sign` builds it
        assert_eq!(
            ctx,
            crate::sign::context(ObjectType::MLDSA_SIGNATURE, "HUMID-PQ2 interop").unwrap()
        );
        let sig = crate::sign::MlDsaSignature::from_raw(&h(&t["sigHedged"])).unwrap();
        k.verifying_key()
            .verify("HUMID-PQ2 interop", &msg, &sig)
            .unwrap();
    }
    for t in v["x25519"].as_array().unwrap() {
        let sa = x25519_dalek::StaticSecret::from(a::<32>(&t["a"]));
        let sb = x25519_dalek::StaticSecret::from(a::<32>(&t["b"]));
        assert_eq!(
            x25519_dalek::PublicKey::from(&sa).to_bytes(),
            a::<32>(&t["pubA"])
        );
        assert_eq!(
            sa.diffie_hellman(&x25519_dalek::PublicKey::from(&sb))
                .to_bytes(),
            a::<32>(&t["shared"])
        );
    }
    for t in v["slh"].as_array().unwrap() {
        let mut seed = a::<96>(&t["seed"]);
        let k = SlhSigningKey::from_seed(&Secret::new(&mut seed));
        assert_eq!(&k.verifying_key().raw()[..], &h(&t["pk"])[..]);
    }
}

#[test]
fn noble_humid_pq2_objects() {
    // HUMID-PQ2 computed independently in JS from docs/v5/PQ2.md.
    let v = vectors("noble-interop.json");
    let p = &v["pq2"];
    for t in p["kdf"].as_array().unwrap() {
        let key: Vec<Vec<u8>> = t["key"].as_array().unwrap().iter().map(h).collect();
        let ctx: Vec<Vec<u8>> = t["ctx"].as_array().unwrap().iter().map(h).collect();
        let want = h(&t["out"]);
        let mut out = vec![0u8; want.len()];
        let kr: Vec<&[u8]> = key.iter().map(Vec::as_slice).collect();
        let cr: Vec<&[u8]> = ctx.iter().map(Vec::as_slice).collect();
        kdf_into(t["label"].as_str().unwrap(), &kr, &cr, &mut out).unwrap();
        assert_eq!(out, want, "{t}");
    }
    let lh = &p["labelledHash"];
    let parts: Vec<Vec<u8>> = lh["parts"].as_array().unwrap().iter().map(h).collect();
    let pr: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    assert_eq!(
        labelled_hash(lh["label"].as_str().unwrap(), &pr).unwrap()[..],
        h(&lh["out"])[..]
    );

    let k = &p["hybridKem"];
    let mut seed = a::<96>(&k["seed"]);
    let sk = KemSecretKey::from_seed(&Secret::new(&mut seed));
    assert_eq!(&sk.public_key().to_bytes()[..], &h(&k["publicKey"])[..]);
    assert_eq!(sk.public_key().key_id()[..], h(&k["keyId"])[..]);
    assert_eq!(key_id(sk.public_key().to_bytes())[..], h(&k["keyId"])[..]);
    let (ct, ss) = sk
        .public_key()
        .encapsulate_derand(&a(&k["m"]), &a(&k["eph"]))
        .unwrap();
    assert_eq!(&ct.to_bytes()[..], &h(&k["ciphertext"])[..]);
    assert_eq!(&ss.expose()[..], &h(&k["sharedSecret"])[..]);
    let ct2 = KemCiphertext::from_bytes(&h(&k["ciphertext"])).unwrap();
    assert!(sk.decapsulate(&ct2).unwrap().ct_eq(&ss));

    let sb = &p["sealedBox"];
    let t = ObjectType(sb["type"].as_u64().unwrap() as u16);
    let aad: Vec<Vec<u8>> = sb["aad"].as_array().unwrap().iter().map(h).collect();
    let ar: Vec<&[u8]> = aad.iter().map(Vec::as_slice).collect();
    let boxed = seal_to_with(sk.public_key(), &ct, &ss, t, &ar, &h(&sb["plaintext"])).unwrap();
    assert_eq!(boxed, h(&sb["boxed"]));
    assert_eq!(
        &open_sealed(&sk, t, &ar, &boxed).unwrap()[..],
        &h(&sb["plaintext"])[..]
    );

    let ar_ = &p["atRest"];
    let t = ObjectType(ar_["type"].as_u64().unwrap() as u16);
    let mut kk = a::<32>(&ar_["key"]);
    let key = Secret32::new(&mut kk);
    let aad: Vec<Vec<u8>> = ar_["aad"].as_array().unwrap().iter().map(h).collect();
    let ar: Vec<&[u8]> = aad.iter().map(Vec::as_slice).collect();
    let boxed =
        seal_at_rest_with_nonce(&key, t, &ar, &h(&ar_["plaintext"]), &a(&ar_["nonce"])).unwrap();
    assert_eq!(boxed, h(&ar_["boxed"]));
    assert_eq!(
        &open_at_rest(&key, t, &ar, &boxed).unwrap()[..],
        &h(&ar_["plaintext"])[..]
    );
}

#[test]
fn self_test_constants_are_nist_vectors() {
    // The power-on self-test's constants are ACVP tcId 51 of ML-KEM / ML-DSA keyGen.
    let k = acvp("acvp", "ML-KEM-keyGen-FIPS203");
    let (_, t) = cases(&k, |g| g["parameterSet"] == "ML-KEM-1024")
        .next()
        .unwrap();
    assert_eq!(t["d"], crate::selftest::MLKEM_D);
    assert_eq!(t["z"], crate::selftest::MLKEM_Z);
    assert_eq!(
        hex::encode_upper(sha3_512(&h(&t["ek"]))),
        crate::selftest::MLKEM_EK_SHA3
    );
    let d = acvp("acvp", "ML-DSA-keyGen-FIPS204");
    let (_, t) = cases(&d, |g| g["parameterSet"] == "ML-DSA-87")
        .next()
        .unwrap();
    assert_eq!(t["seed"], crate::selftest::MLDSA_SEED);
    assert_eq!(
        hex::encode_upper(sha3_512(&h(&t["pk"]))),
        crate::selftest::MLDSA_PK_SHA3
    );
    let _ = FixedRng(&[]);
}
