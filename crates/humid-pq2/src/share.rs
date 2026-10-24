//! Document key shares, sealed in both directions (V5.md "Split shares sealed
//! phone-to-key-service in both directions"; audit H1 / verify #1).
//!
//! * **Upload** (phone → key service): the phone seals the 32-byte `share_ks` to the key
//!   service's pinned hybrid KEM key. The gateway in between sees ciphertext only.
//! * **Release** (key service → phone): the key service seals it to a one-time hybrid KEM
//!   key the phone made for this one open and named in the request its live check signed.
//!
//! Both bind the account id, the document id and a caller-chosen `binding` (for a release:
//! the hash of the signed request; for an upload: the manifest hash), as associated data.

use zeroize::Zeroizing;

use crate::aead::{open_sealed, seal_to};
use crate::encoding::ObjectType;
use crate::kem::{KemPublicKey, KemSecretKey};
use crate::secret::Secret32;
use crate::{Error, Result};

/// Size of a sealed share: 13 + 1600 + 32 + 16 = 1661 bytes.
pub const SEALED_SHARE_LEN: usize = crate::aead::SEALED_OVERHEAD + 32;

/// Which way a share travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareDirection {
    /// Phone → key service.
    Upload,
    /// Key service → phone.
    Release,
}

impl ShareDirection {
    fn object_type(self) -> ObjectType {
        match self {
            ShareDirection::Upload => ObjectType::SHARE_UPLOAD,
            ShareDirection::Release => ObjectType::SHARE_RELEASE,
        }
    }
}

/// Seal `share` to `recipient` (the key service's key for an upload, the phone's one-time
/// key for a release).
///
/// # Errors
/// [`Error::Rng`], [`Error::KeyAgreement`].
pub fn seal_share(
    dir: ShareDirection,
    recipient: &KemPublicKey,
    account: &[u8],
    doc_id: &[u8],
    binding: &[u8],
    share: &Secret32,
) -> Result<Vec<u8>> {
    seal_to(
        recipient,
        dir.object_type(),
        &[account, doc_id, binding],
        share.expose(),
    )
}

/// Open a sealed share.
///
/// # Errors
/// [`Error::Encoding`] for the wrong direction or size; [`Error::Decrypt`] if it wasn't
/// sealed to this key for this account, document and binding.
pub fn open_share(
    dir: ShareDirection,
    sk: &KemSecretKey,
    account: &[u8],
    doc_id: &[u8],
    binding: &[u8],
    sealed: &[u8],
) -> Result<Secret32> {
    if sealed.len() != SEALED_SHARE_LEN {
        return Err(Error::Encoding);
    }
    let pt: Zeroizing<Vec<u8>> =
        open_sealed(sk, dir.object_type(), &[account, doc_id, binding], sealed)?;
    Secret32::from_slice(&pt).map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_directions() {
        let ks = KemSecretKey::generate().unwrap();
        let phone_once = KemSecretKey::generate().unwrap();
        let share = Secret32::random().unwrap();
        let up = seal_share(
            ShareDirection::Upload,
            ks.public_key(),
            b"hid_1",
            b"doc_1",
            b"m",
            &share,
        )
        .unwrap();
        assert_eq!(up.len(), SEALED_SHARE_LEN);
        let got = open_share(ShareDirection::Upload, &ks, b"hid_1", b"doc_1", b"m", &up).unwrap();
        assert!(got.ct_eq(&share));
        // An upload can't be replayed as a release, or moved to another document.
        assert!(open_share(ShareDirection::Release, &ks, b"hid_1", b"doc_1", b"m", &up).is_err());
        assert!(open_share(ShareDirection::Upload, &ks, b"hid_1", b"doc_2", b"m", &up).is_err());
        let rel = seal_share(
            ShareDirection::Release,
            phone_once.public_key(),
            b"hid_1",
            b"doc_1",
            b"req",
            &got,
        )
        .unwrap();
        let back = open_share(
            ShareDirection::Release,
            &phone_once,
            b"hid_1",
            b"doc_1",
            b"req",
            &rel,
        )
        .unwrap();
        assert!(back.ct_eq(&share));
        assert!(
            open_share(
                ShareDirection::Release,
                &phone_once,
                b"hid_1",
                b"doc_1",
                b"req2",
                &rel
            )
            .is_err()
        );
    }
}
