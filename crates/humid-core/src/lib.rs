//! # humid-core
//!
//! The HumID 5.0 core (docs/v5/CORE.md): the one place that holds keys. The UI calls
//! [`Core`] with opaque handles and receives results only: public identity, live proofs,
//! sealed blobs to upload, and a document's bytes streamed into the viewer the caller passes.
//!
//! * [`gate::HardwareGate`]: the per-platform hardware operation (iOS 26 Secure Enclave
//!   ML-KEM + P-256 in one biometric context; Android StrongBox HMAC), one prompt per action.
//! * [`ratchet`]: the device wrap `W_n` and its per-unlock ratchet `W_n → W_{n+1}`, with a
//!   rollback floor.
//! * [`envelope`]: three-key documents (`K_doc` from `ss_acct`, `HW_doc`, `share_ks`), one
//!   layer of streaming, chunked AES-256-GCM-SIV; device and pending slots; share requests.
//! * [`records`]: typed, versioned local records.
//! * [`Core::lock`] drops and wipes every secret.
//!
//! No platform code: [`soft_gate::SoftGate`] (feature `software-gate`, and in tests) stands
//! in for the hardware.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::similar_names
)]

mod core;
pub mod envelope;
mod error;
pub mod gate;
mod keys;
pub mod ratchet;
pub mod records;
#[cfg(any(test, feature = "software-gate"))]
pub mod soft_gate;
pub mod store;

pub use crate::core::{
    Core, Grant, JoinRequest, OpenHandle, OpenStarted, Opened, SealReceipt, Unlocked,
};
pub use envelope::DocMeta;
pub use error::{CoreError, Result};
pub use keys::PublicIdentity;
