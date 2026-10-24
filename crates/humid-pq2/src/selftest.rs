//! Power-on self-test (V5.md: "Every backend passes NIST known-answer tests and
//! cross-checks (including randomness) before use"). humid-core and the server call
//! [`self_test`] once at start and refuse to run if it fails. The full ACVP suites run in
//! CI (`cargo test`); this checks one known answer per primitive in tens of milliseconds:
//!
//! | Primitive | Check |
//! | --- | --- |
//! | randomness | continuous tests on 1 KiB: repetition count, adaptive proportion, no repeated block |
//! | SHA3-512, SHAKE256 | FIPS 202 examples |
//! | KMAC256 | SP 800-185 sample 4 |
//! | AES-256-GCM-SIV | RFC 8452 C.2 vector; at-rest box round trip |
//! | AES-256-GCM | NIST CAVS gcmEncryptExtIV256 vector |
//! | X25519 | RFC 7748 §5.2 vector 1, §6.1 public key |
//! | ML-KEM-1024 | ACVP keyGen (ek hash), encapsulation (c, k), decapsulation, implicit rejection |
//! | ML-DSA-87 | ACVP keyGen (pk hash); NIST's deterministic signature verifies, a 1-bit change doesn't; pairwise hedged sign/verify |
//! | SLH-DSA-SHA2-256s | ACVP sigVer: valid accepted, 1-bit change refused |
//! | hybrid KEM | pairwise |
//!
//! Signature answers are checked by verification only: production builds contain no
//! deterministic signer (it exists only under `cfg(test)`).
//!
//! The large answers live in `selftest.bin`, made by `tools/pq2-selftest-vectors.mjs` from the
//! repo's ACVP fixtures; the KATs in `kat.rs` re-check every constant against the fixtures.

use crate::aead::{gcm_cipher, gcm_seal, open_at_rest, seal_at_rest, siv_seal};
use crate::encoding::{HEADER_LEN, ObjectType, Reader};
use crate::hash::{sha3_512, shake256};
use crate::kdf::kmac256;
use crate::kem::{KemSecretKey, mlkem_encaps_raw};
use crate::rng;
use crate::secret::{Secret, Secret32, ct_eq};
use crate::sign::{MlDsaSigningKey, MlDsaVerifyingKey, SlhVerifyingKey};
use crate::{Error, Result};

/// `lp(field)…`: ML-KEM ek, m, c, k; ML-DSA pk, msg, ctx, sig; implicit-rejection
/// (ss, ss_bad) on the keyGen key; SLH-DSA pk, msg, ctx, sig.
static VECTORS: &[u8] = include_bytes!("selftest.bin");

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16).unwrap_or(0);
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16).unwrap_or(0);
        *o = (hi * 16 + lo) as u8;
    }
    out
}

fn check(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::Verify) }
}

/// SHA3-512 of the ML-KEM-1024 encapsulation key for NIST ACVP ML-KEM-keyGen-FIPS203
/// tcId 51 (d, z below), and of the ML-DSA-87 public key for ML-DSA-keyGen-FIPS204
/// tcId 51 (seed below). The KATs in `kat.rs` check these constants against the vectors.
pub(crate) const MLKEM_D: &str = "F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009";
pub(crate) const MLKEM_Z: &str = "35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275";
pub(crate) const MLKEM_EK_SHA3: &str = "7EF1D49A3843BCF701BA27EF796F7169091EC3A70D6DCE10A8F1320590B1E086100505A5FAE89DE6555957ED3409759591D9C87855557F60D2C6172FA18853C7";
pub(crate) const MLDSA_SEED: &str =
    "A16F5B0796703E2D1A0140A35CBF36EFABE70E752BA59B6A9A0E9C4B05302F73";
pub(crate) const MLDSA_PK_SHA3: &str = "787961957AFABFB1F4E5EE3C1F42C43C3260923F0135274B53939E24AEF63BAC68FE2470DDD1040679F66990E0AC4BB68762D00409B58AF21D17F107D66A9EFA";

/// Continuous health tests on `n` bytes from the platform CSPRNG, after SP 800-90B §4.4
/// (repetition count, adaptive proportion; cutoffs for H = 7 bits/byte at α = 2⁻⁴⁰ and
/// window 512), plus "no 16-byte block repeats". These catch a stuck or badly broken
/// generator; they don't certify a good one.
pub(crate) fn rng_health(sample: &[u8]) -> Result<()> {
    // Repetition count: cutoff C = 1 + ceil(40 / 7) = 7 identical bytes in a row.
    let mut run = 1;
    for w in sample.windows(2) {
        run = if w[0] == w[1] { run + 1 } else { 1 };
        if run >= 7 {
            return Err(Error::Rng);
        }
    }
    // Adaptive proportion: in each 512-byte window, the first byte's value at most 41 times.
    for win in sample.chunks(512).filter(|w| w.len() == 512) {
        if win
            .iter()
            .fold(0usize, |n, &b| n + usize::from(b == win[0]))
            > 41
        {
            return Err(Error::Rng);
        }
    }
    // No repeated 16-byte block.
    let mut blocks: Vec<&[u8]> = sample.chunks_exact(16).collect();
    blocks.sort_unstable();
    if blocks.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::Rng);
    }
    Ok(())
}

/// Run the known-answer and pairwise-consistency checks.
///
/// # Errors
/// [`Error::Verify`] if any check fails; [`Error::Rng`] if the generator fails or looks
/// stuck. Never returns secret data.
pub fn self_test() -> Result<()> {
    let mut sample = zeroize::Zeroizing::new([0u8; 1024]);
    rng::fill(&mut sample[..])?;
    rng_health(&sample[..])?;
    hashes()?;
    aeads()?;
    x25519()?;
    let mut r = Reader::new(VECTORS);
    ml_kem(&mut r)?;
    ml_dsa(&mut r)?;
    slh_dsa(&mut r)?;
    pairwise()
}

fn hashes() -> Result<()> {
    // SHA3-512("abc") and SHAKE256("", 32): FIPS 202 examples.
    check(
        sha3_512(b"abc")[..]
            == unhex::<64>(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            )[..],
    )?;
    let mut xof = [0u8; 32];
    shake256(b"", &mut xof);
    check(xof == unhex::<32>("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"))?;
    // KMAC256: NIST SP 800-185 sample #4.
    let key: Vec<u8> = (0x40u8..=0x5f).collect();
    let mut mac = [0u8; 64];
    kmac256(
        &key,
        &[0, 1, 2, 3],
        b"My Tagged Application",
        &mut mac,
        false,
    )?;
    check(
        mac[..]
            == unhex::<64>(
                "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
            )[..],
    )
}

fn aeads() -> Result<()> {
    // AES-256-GCM-SIV: RFC 8452 Appendix C.2, the 8-byte plaintext vector.
    let mut kb = unhex::<32>("0100000000000000000000000000000000000000000000000000000000000000");
    let key = Secret32::new(&mut kb);
    let ct = siv_seal(
        &key,
        &unhex::<12>("030000000000000000000000"),
        b"",
        &unhex::<8>("0100000000000000"),
    )?;
    check(ct[..] == unhex::<24>("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28")[..])?;
    let boxed = seal_at_rest(&key, ObjectType::AT_REST_BOX, &[b"self-test"], b"x")?;
    check(&open_at_rest(&key, ObjectType::AT_REST_BOX, &[b"self-test"], &boxed)?[..] == b"x")?;
    // AES-256-GCM: NIST CAVS gcmEncryptExtIV256 (96-bit IV, 128-bit AAD and plaintext).
    let mut gk = unhex::<32>("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b");
    let gcm = gcm_cipher(&Secret32::new(&mut gk));
    let ct = gcm_seal(
        &gcm,
        &unhex::<12>("ac93a1a6145299bde902f21a"),
        &unhex::<16>("1e0889016f67601c8ebea4943bc23ad6"),
        &unhex::<16>("2d71bcfa914e4ac045b2aa60955fad24"),
    )?;
    check(
        ct[..]
            == unhex::<32>("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab")[..],
    )
}

fn x25519() -> Result<()> {
    // RFC 7748 §5.2 vector 1 and the §6.1 public key.
    check(
        x25519_dalek::x25519(
            unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        ) == unhex::<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    )?;
    let alice = x25519_dalek::StaticSecret::from(unhex::<32>(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    check(
        x25519_dalek::PublicKey::from(&alice).to_bytes()
            == unhex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    )
}

fn ml_kem(r: &mut Reader<'_>) -> Result<()> {
    let (ek, m, c, kk) = (r.lp(MAX)?, r.lp(MAX)?, r.lp(MAX)?, r.lp(MAX)?);
    // keyGen (ACVP tcId 51)
    let mut seed = [0u8; 96];
    seed[..32].copy_from_slice(&unhex::<32>(MLKEM_D));
    seed[32..64].copy_from_slice(&unhex::<32>(MLKEM_Z));
    let kem = KemSecretKey::from_seed(&Secret::new(&mut seed));
    let own_ek = &kem.public_key().to_bytes()[HEADER_LEN..HEADER_LEN + 1568];
    check(ct_eq(&sha3_512(own_ek), &unhex::<64>(MLKEM_EK_SHA3)))?;
    // encapsulation (ACVP tcId 51): (ek, m) → (c, k)
    let mut mm = [0u8; 32];
    mm.copy_from_slice(m);
    let (c2, k2) = mlkem_encaps_raw(ek, &mm)?;
    check(ct_eq(&c2, c) && ct_eq(&k2[..], kk))
}

fn ml_dsa(r: &mut Reader<'_>) -> Result<()> {
    let (dpk, dmsg, dctx, dsig) = (r.lp(MAX)?, r.lp(MAX)?, r.lp(MAX)?, r.lp(MAX)?);
    // (selftest.bin keeps the ML-KEM decapsulation answers after the ML-DSA fields)
    let (ss_ok, ss_bad) = (r.lp(MAX)?, r.lp(MAX)?);
    // ML-KEM decapsulation + implicit rejection on the keyGen key (answers from noble)
    let mut seed = [0u8; 96];
    seed[..32].copy_from_slice(&unhex::<32>(MLKEM_D));
    seed[32..64].copy_from_slice(&unhex::<32>(MLKEM_Z));
    let kem = KemSecretKey::from_seed(&Secret::new(&mut seed));
    let own_ek = kem.public_key().to_bytes()[HEADER_LEN..HEADER_LEN + 1568].to_vec();
    let (ct_k, k_k) = mlkem_encaps_raw(&own_ek, &[0xa5; 32])?;
    check(ct_eq(&k_k[..], ss_ok))?;
    check(ct_eq(&kem.mlkem_decaps_raw(&ct_k)?[..], ss_ok))?;
    let mut bad = ct_k;
    bad[0] ^= 1;
    check(ct_eq(&kem.mlkem_decaps_raw(&bad)?[..], ss_bad))?;
    // ML-DSA-87 keyGen (ACVP tcId 51); NIST's deterministic signature (sigGen tcId 61)
    // verifies, and a 1-bit change doesn't.
    let mut xi = unhex::<32>(MLDSA_SEED);
    let dsa = MlDsaSigningKey::from_seed(&Secret32::new(&mut xi));
    check(ct_eq(
        &sha3_512(dsa.verifying_key().raw()),
        &unhex::<64>(MLDSA_PK_SHA3),
    ))?;
    let nist = MlDsaVerifyingKey::from_raw(dpk)?;
    nist.verify_ctx(dmsg, dctx, dsig)?;
    let mut flipped = dsig.to_vec();
    flipped[10] ^= 1;
    check(nist.verify_ctx(dmsg, dctx, &flipped).is_err())
}

fn slh_dsa(r: &mut Reader<'_>) -> Result<()> {
    let (spk, smsg, sctx, ssig) = (r.lp(MAX)?, r.lp(MAX)?, r.lp(MAX)?, r.lp(MAX)?);
    // ACVP sigVer, valid case: verifies; a 1-bit change doesn't.
    let slh = SlhVerifyingKey::from_raw(spk)?;
    slh.verify_ctx(smsg, sctx, ssig)?;
    let mut flipped = ssig.to_vec();
    flipped[40] ^= 1;
    check(slh.verify_ctx(smsg, sctx, &flipped).is_err())
}

fn pairwise() -> Result<()> {
    let kem = KemSecretKey::generate()?;
    let (c, ss) = kem.public_key().encapsulate()?;
    check(kem.decapsulate(&c)?.ct_eq(&ss))?;
    let dsa = MlDsaSigningKey::generate()?;
    let sig = dsa.sign("HUMID-PQ2 self-test", b"m")?;
    dsa.verifying_key()
        .verify("HUMID-PQ2 self-test", b"m", &sig)?;
    check(
        dsa.verifying_key()
            .verify("HUMID-PQ2 self-test", b"n", &sig)
            .is_err(),
    )
}

const MAX: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes() {
        self_test().unwrap();
    }

    /// Review M5: a stuck or repeating generator is caught.
    #[test]
    fn rng_health_catches_bad_generators() {
        let mut good = [0u8; 1024];
        rng::fill(&mut good).unwrap();
        rng_health(&good).unwrap();
        assert_eq!(rng_health(&[0u8; 1024]), Err(Error::Rng), "stuck");
        let mut rep = good;
        rep[500..507].fill(9);
        assert_eq!(rng_health(&rep), Err(Error::Rng), "a run of 7");
        let mut cyc = good;
        let (a, b) = cyc.split_at_mut(512);
        b.copy_from_slice(a);
        assert_eq!(rng_health(&cyc), Err(Error::Rng), "repeating output");
        let biased: Vec<u8> = (0..1024u32)
            .map(|i| {
                if i % 8 == 0 {
                    0x55
                } else {
                    (i * 37 % 251) as u8
                }
            })
            .collect();
        assert_eq!(rng_health(&biased), Err(Error::Rng), "biased");
    }
}
