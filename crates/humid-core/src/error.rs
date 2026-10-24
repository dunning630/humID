use core::fmt;

use crate::gate::GateError;
use crate::store::StoreError;

/// What the core reports to the UI. No variant carries key material or plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// The core is locked: unlock first.
    Locked,
    /// This device has no wrap yet.
    NotEnrolled,
    /// This device is already enrolled.
    AlreadyEnrolled,
    /// The hardware gate refused or was cancelled.
    Gate(GateError),
    /// A cryptographic operation failed.
    Crypto(humid_pq2::Error),
    /// Device storage failed.
    Store(StoreError),
    /// A wrap or record older than one this device has already seen (rollback).
    Rollback,
    /// No device wrap opens with this device's hardware.
    WrapUnusable,
    /// Malformed bytes.
    Format,
    /// A document not signed by this account's pinned key.
    WrongSigner,
    /// A document's contents failed authentication or were cut short.
    Tampered,
    /// The bytes are for another document, device or request.
    WrongDocument,
    /// The plaintext's length differs from the size declared for it.
    SizeMismatch,
    /// Unknown, used or expired handle.
    BadHandle,
    /// Reading the input or writing the output failed.
    Io,
    /// Refused in a decoy session.
    Decoy,
    /// This device's hardware can't do the action in one prompt (CORE.md §5).
    Unsupported,
    /// The code the person typed doesn't match the other device's.
    CodeMismatch,
    /// This device's record revisions are missing, older than its counter or damaged:
    /// synced records can't be checked for rollback until [`crate::Core::reset_records`].
    RecordsUnavailable,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Gate(g) => write!(f, "hardware gate: {g:?}"),
            CoreError::Crypto(e) => write!(f, "crypto: {e}"),
            CoreError::Store(e) => write!(f, "storage: {e:?}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<humid_pq2::Error> for CoreError {
    fn from(e: humid_pq2::Error) -> Self {
        match e {
            humid_pq2::Error::Encoding => CoreError::Format,
            other => CoreError::Crypto(other),
        }
    }
}

impl From<GateError> for CoreError {
    fn from(e: GateError) -> Self {
        CoreError::Gate(e)
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self {
        CoreError::Store(e)
    }
}

/// `Result` with [`CoreError`].
pub type Result<T> = core::result::Result<T, CoreError>;
