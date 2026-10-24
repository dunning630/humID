use core::fmt;

/// Everything that can go wrong in HUMID-PQ2. No variant carries secret data, and
/// decryption and verification failures say nothing about *why* they failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A length (input, output or field) outside what the format allows.
    Length,
    /// Bytes that are not a valid encoding: wrong suite, version or type, a bad key,
    /// a wrong size or trailing data.
    Encoding,
    /// Authentication failed: the ciphertext, the associated data or the key is wrong.
    Decrypt,
    /// A signature did not verify.
    Verify,
    /// Key agreement gave an unusable result (an X25519 low-order point).
    KeyAgreement,
    /// The platform random number generator failed.
    Rng,
    /// A nonce counter ran out, or a transit record was replayed or reordered.
    Counter,
    /// A label or signature context is too long.
    Label,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Length => "length out of range",
            Error::Encoding => "invalid encoding",
            Error::Decrypt => "authentication failed",
            Error::Verify => "signature did not verify",
            Error::KeyAgreement => "key agreement failed",
            Error::Rng => "random number generator failed",
            Error::Counter => "nonce counter exhausted or record replayed",
            Error::Label => "label or context too long",
        })
    }
}

impl std::error::Error for Error {}

/// `Result` with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
