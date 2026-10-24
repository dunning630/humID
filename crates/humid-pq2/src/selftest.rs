//! Power-on self-test (V5.md: "Every backend passes NIST known-answer tests and
//! cross-checks (including randomness) before use"). humid-core and the server call
//! [`self_test`] once at start and refuse to run if it fails. It takes a few milliseconds:
//! the full ACVP suites run in CI (`cargo test`).

use crate::aead::{open_at_rest, seal_at_rest, siv_seal};
use crate::encoding::ObjectType;
use crate::hash::{sha3_512, shake256};
use crate::kdf::kmac256;
use crate::kem::KemSecretKey;
use crate::secret::{Secret, Secret32, ct_eq};
use crate::sign::MlDsaSigningKey;
use crate::{Error, Result};

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

/// Run the known-answer and pairwise-consistency checks.
///
/// # Errors
/// [`Error::Verify`] if any check fails; [`Error::Rng`] if the generator fails or looks
/// stuck. Never returns secret data.
pub fn self_test() -> Result<()> {
    // Randomness health: two 32-byte draws differ and neither is all zero.
    let draw1 = Secret32::random()?;
    let draw2 = Secret32::random()?;
    if draw1.ct_eq(&draw2) || draw1.expose().iter().all(|&x| x == 0) {
        return Err(Error::Rng);
    }

    // SHA3-512("abc") and SHAKE256("", 32): FIPS 202 examples.
    check(
        sha3_512(b"abc")[..]
            == unhex::<64>(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            )[..],
    )?;
    let mut s = [0u8; 32];
    shake256(b"", &mut s);
    check(s == unhex::<32>("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"))?;

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
    )?;

    // AES-256-GCM-SIV: RFC 8452 Appendix C.2, the 8-byte plaintext vector.
    let mut k = unhex::<32>("0100000000000000000000000000000000000000000000000000000000000000");
    let k = Secret32::new(&mut k);
    let ct = siv_seal(
        &k,
        &unhex::<12>("030000000000000000000000"),
        b"",
        &unhex::<8>("0100000000000000"),
    )?;
    check(ct[..] == unhex::<24>("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28")[..])?;
    let boxed = seal_at_rest(&k, ObjectType::AT_REST_BOX, &[b"self-test"], b"x")?;
    check(&open_at_rest(&k, ObjectType::AT_REST_BOX, &[b"self-test"], &boxed)?[..] == b"x")?;

    // ML-KEM-1024 and ML-DSA-87 key generation from NIST seeds.
    let mut seed = [0u8; 96];
    seed[..32].copy_from_slice(&unhex::<32>(MLKEM_D));
    seed[32..64].copy_from_slice(&unhex::<32>(MLKEM_Z));
    let kem = KemSecretKey::from_seed(&Secret::new(&mut seed));
    let ek = &kem.public_key().to_bytes()
        [crate::encoding::HEADER_LEN..crate::encoding::HEADER_LEN + 1568];
    check(ct_eq(&sha3_512(ek), &unhex::<64>(MLKEM_EK_SHA3)))?;
    let mut xi = unhex::<32>(MLDSA_SEED);
    let dsa = MlDsaSigningKey::from_seed(&Secret32::new(&mut xi));
    check(ct_eq(
        &sha3_512(dsa.verifying_key().raw()),
        &unhex::<64>(MLDSA_PK_SHA3),
    ))?;

    // Pairwise consistency with fresh keys.
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
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn passes() {
        super::self_test().unwrap();
    }
}
