//! Randomness: the platform CSPRNG only (V5.md, "Randomness").

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};

use crate::{Error, Result};

/// Fill `buf` from the platform CSPRNG (getrandom: `getentropy`/`SecRandomCopyBytes`/
/// `getrandom(2)`).
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// The platform CSPRNG as a `rand_core` generator, for the RustCrypto signers.
pub(crate) struct OsRng;

impl TryRng for OsRng {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

impl TryCryptoRng for OsRng {}

/// A generator that hands out the given bytes once, then zeros. Lets the hedged ML-DSA
/// signer take an explicit `rnd` (FIPS 204 §3.4) for known-answer tests and the
/// randomness cross-check; production signing draws `rnd` from [`fill`].
pub(crate) struct FixedRng<'a>(pub(crate) &'a [u8]);

impl TryRng for FixedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        let n = dst.len().min(self.0.len());
        dst[..n].copy_from_slice(&self.0[..n]);
        dst[n..].fill(0);
        self.0 = &self.0[n..];
        Ok(())
    }
}

impl TryCryptoRng for FixedRng<'_> {}
