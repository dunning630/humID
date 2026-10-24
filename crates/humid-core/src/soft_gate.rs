//! A software [`HardwareGate`] for tests and the simulator. It models the three ways a
//! platform can make the per-unlock hardware factor (CORE.md §4) and counts prompts, so
//! tests can prove each action costs exactly one.
//!
//! **Not secure**: its "hardware" keys are ordinary memory. Its platform reports
//! [`Platform::Software`], which no production server accepts.

use std::collections::BTreeMap;

use humid_pq2::{Secret32, kdf, random_bytes};

use crate::gate::{
    GateError, GateInfo, HardwareGate, HwOp, HwOutput, HwTarget, LiveAlg, LiveProof, LiveSig,
    Platform, Prompt, TargetKind,
};

/// How targets behave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftMode {
    /// iOS 26 model: each target is a fresh encapsulation to a hardware public key, so its
    /// value is known at once and retiring it deletes the key (old inputs then fail).
    PublicTarget,
    /// Android proposal A (CORE.md §5): each wrap target imports a fresh per-use HMAC key,
    /// value known at once, retiring deletes the key. Document targets use one fixed key and
    /// need the hardware (value `None`).
    ImportedKey,
    /// Android with one fixed per-use HMAC key: every value must be computed inside an
    /// authorization, and retiring an input can't revoke it (only the rollback floor can).
    SymmetricInput,
}

/// The software gate.
pub struct SoftGate {
    mode: SoftMode,
    max_ops: usize,
    /// input id → key. "Hardware" keys; removing one models deleting the hardware key.
    keys: BTreeMap<Vec<u8>, Secret32>,
    fixed: Secret32,
    live: Secret32,
    /// Prompts shown so far.
    pub prompts: usize,
    /// Ops run in the largest single prompt so far.
    pub max_ops_seen: usize,
    /// When set, the next prompt is cancelled.
    pub cancel_next: bool,
    /// When set, every key is gone (a new fingerprint was enrolled).
    pub invalidated: bool,
}

impl SoftGate {
    /// A gate in `mode`, allowing `max_ops` operations per prompt.
    ///
    /// # Panics
    /// If the platform generator fails (tests only).
    #[must_use]
    pub fn new(mode: SoftMode, max_ops: usize) -> Self {
        Self {
            mode,
            max_ops,
            keys: BTreeMap::new(),
            fixed: Secret32::random().expect("rng"),
            live: Secret32::random().expect("rng"),
            prompts: 0,
            max_ops_seen: 0,
            cancel_next: false,
            invalidated: false,
        }
    }

    fn hw(&self, input: &[u8]) -> Result<Secret32, GateError> {
        if self.invalidated {
            return Err(GateError::KeyInvalidated);
        }
        let (tag, id) = input.split_first().ok_or(GateError::UnknownInput)?;
        let key = match *tag {
            b'K' => self.keys.get(id).ok_or(GateError::UnknownInput)?,
            b'F' => &self.fixed,
            _ => return Err(GateError::UnknownInput),
        };
        kdf::<32>("HUMID-PQ2 soft-gate", &[key.expose()], &[input]).map_err(|_| GateError::Platform)
    }

    /// The number of live hardware keys (retired ones are gone).
    #[must_use]
    pub fn live_keys(&self) -> usize {
        self.keys.len()
    }
}

impl HardwareGate for SoftGate {
    fn info(&self) -> GateInfo {
        GateInfo {
            platform: Platform::Software,
            max_ops: self.max_ops,
        }
    }

    fn target(&mut self, kind: TargetKind) -> Result<HwTarget, GateError> {
        let mut nonce = [0u8; 16];
        random_bytes(&mut nonce).map_err(|_| GateError::Platform)?;
        let per_key = match (self.mode, kind) {
            (SoftMode::PublicTarget, _) | (SoftMode::ImportedKey, TargetKind::Wrap) => true,
            (SoftMode::ImportedKey | SoftMode::SymmetricInput, _) => false,
        };
        if per_key {
            let mut input = vec![b'K'];
            input.extend_from_slice(&nonce);
            self.keys.insert(
                nonce.to_vec(),
                Secret32::random().map_err(|_| GateError::Platform)?,
            );
            let value = self.hw(&input)?;
            Ok(HwTarget {
                input,
                value: Some(value),
            })
        } else {
            let mut input = vec![b'F'];
            input.extend_from_slice(&nonce);
            Ok(HwTarget { input, value: None })
        }
    }

    fn authorize(&mut self, _prompt: &Prompt, ops: &[HwOp]) -> Result<Vec<HwOutput>, GateError> {
        self.prompts += 1;
        self.max_ops_seen = self.max_ops_seen.max(ops.len());
        if ops.len() > self.max_ops {
            return Err(GateError::TooManyOps);
        }
        if std::mem::take(&mut self.cancel_next) {
            return Err(GateError::Cancelled);
        }
        ops.iter()
            .map(|op| match op {
                HwOp::Derive(input) => self.hw(input).map(HwOutput::Derived),
                HwOp::SignLive(challenge) => {
                    // A stand-in "signature": a MAC the test can recompute. Real adapters
                    // return ECDSA P-256 (+ ML-DSA-87) signatures.
                    let t = kdf::<32>("HUMID-PQ2 soft-live", &[self.live.expose()], &[challenge])
                        .map_err(|_| GateError::Platform)?;
                    Ok(HwOutput::Live(LiveProof {
                        sigs: vec![LiveSig {
                            alg: LiveAlg::EcdsaP256,
                            bytes: t.expose().to_vec(),
                        }],
                    }))
                }
            })
            .collect()
    }

    fn retire(&mut self, input: &[u8]) {
        if let Some((b'K', id)) = input.split_first() {
            self.keys.remove(id);
        }
    }
}
