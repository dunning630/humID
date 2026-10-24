//! Secret bytes: wiped on drop, compared in constant time, never printed.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{Result, rng};

/// `N` secret bytes on the heap, zeroed when dropped.
///
/// Deliberately has no `Debug`, `Display`, `Serialize` or `PartialEq`: compare with
/// [`Secret::ct_eq`], read with [`Secret::expose`].
pub struct Secret<const N: usize>(Box<Zeroizing<[u8; N]>>);

/// 32 secret bytes: shared secrets, KDF outputs, AEAD keys.
pub type Secret32 = Secret<32>;

impl<const N: usize> Secret<N> {
    /// Take ownership of `bytes`; the caller's copy is wiped.
    #[must_use]
    pub fn new(bytes: &mut [u8; N]) -> Self {
        let mut s = Self::zero();
        s.0.copy_from_slice(bytes);
        bytes.zeroize();
        s
    }

    /// Copy from a slice of exactly `N` bytes.
    ///
    /// # Errors
    /// [`crate::Error::Length`] for any other length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(crate::Error::Length);
        }
        let mut s = Self::zero();
        s.0.copy_from_slice(bytes);
        Ok(s)
    }

    /// `N` bytes from the platform CSPRNG.
    ///
    /// # Errors
    /// [`crate::Error::Rng`] if the platform generator fails.
    pub fn random() -> Result<Self> {
        let mut s = Self::zero();
        rng::fill(&mut s.0[..])?;
        Ok(s)
    }

    pub(crate) fn zero() -> Self {
        Self(Box::new(Zeroizing::new([0u8; N])))
    }

    pub(crate) fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// The bytes. Keep the borrow short; never copy them into anything that isn't wiped.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0[..].ct_eq(&other.0[..]).into()
    }

    /// A second, independently wiped copy.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        let mut s = Self::zero();
        s.0.copy_from_slice(&self.0[..]);
        s
    }
}

/// Constant-time equality of two byte strings (lengths are public).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
