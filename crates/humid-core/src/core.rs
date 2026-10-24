//! The core: the only API the UI may call (CORE.md §1). Opaque handles in, results out;
//! never key bytes, and no plaintext except a document's bytes streamed to the viewer sink
//! the caller passes in.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use humid_pq2::{
    KemPublicKey, KemSecretKey, MlDsaVerifyingKey, ObjectType, Secret32, ShareDirection,
    labelled_hash, open_sealed, open_share, seal_share, seal_to,
};

use crate::envelope::{
    AnySlot, CHUNK_SIZE, DeviceSlot, DocMeta, PendingSlot, PreparedDoc, ShareRequest,
    account_secret, open_stream, read_head, seal_stream,
};
use crate::error::{CoreError, Result};
use crate::gate::{GateError, HardwareGate, HwOp, HwOutput, LiveProof, Prompt, TargetKind};
use crate::keys::{PublicIdentity, Seeds, SessionKeys};
use crate::ratchet::{SLOTS, Wrap, plan};
use crate::records::{Revisions, open_index, open_setting, seal_index, seal_setting};
use crate::store::DeviceStore;

const REVS_FILE: &str = "revs";

/// An opaque handle to an open in progress. Single use; gone at lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenHandle(u64);

/// What an unlock tells the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unlocked {
    /// Public keys and ids.
    pub identity: PublicIdentity,
    /// The live proof over the caller's challenge.
    pub live: LiveProof,
    /// The wrap counter now in use.
    pub wrap_counter: u64,
    /// Whether the ratchet step completed (`W_{n+1}` written, floor raised, `W_n` retired).
    /// False after a storage failure; the next unlock finishes or retries the step.
    pub advanced: bool,
}

/// What sealing a document returns: all public, to upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealReceipt {
    /// The new document's id.
    pub doc_id: [u8; 32],
    /// Its manifest hash.
    pub manifest_hash: [u8; 64],
    /// SHA3-512 of the whole envelope (what the live proof names).
    pub envelope_hash: [u8; 64],
    /// Plaintext size.
    pub size: u64,
    /// This device's slot for the document.
    pub slot: Vec<u8>,
    /// The share, sealed to the key-share service.
    pub share_upload: Vec<u8>,
    /// The live proof.
    pub live: LiveProof,
}

/// The first half of an open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenStarted {
    /// Pass to [`Core::finish_open`].
    pub handle: OpenHandle,
    /// The share request to send (live-signed) to the key-share service.
    pub share_request: Vec<u8>,
    /// The live proof.
    pub live: LiveProof,
    /// When the slot was a pending one: this device's new hardware slot, to upload in its
    /// place.
    pub adopted_slot: Option<Vec<u8>>,
}

/// The result of an open: what the screen shows. The bytes went to the viewer sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// Name and type.
    pub meta: DocMeta,
    /// Bytes written to the viewer.
    pub size: u64,
}

/// What a joining device publishes (all public), for an existing device to approve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    /// Its ML-DSA-87 device key.
    pub device_dsa: MlDsaVerifyingKey,
    /// Its hybrid KEM key: the account seed and pending slots are sealed to it.
    pub device_kem: KemPublicKey,
}

impl JoinRequest {
    /// The device id.
    #[must_use]
    pub fn device_id(&self) -> [u8; 32] {
        self.device_dsa.key_id()
    }
}

/// What approving a new device returns (all public).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The account seed sealed to the new device.
    pub join_seed: Vec<u8>,
    /// One pending slot per document, for the new device.
    pub pending: Vec<Vec<u8>>,
    /// The live proof (from the first prompt).
    pub live: LiveProof,
    /// How many prompts it took (1 unless more documents than one authorization can carry).
    pub prompts: usize,
}

struct Session {
    keys: SessionKeys,
    public: PublicIdentity,
    account_id: [u8; 32],
    device_id: [u8; 32],
    revs: Revisions,
    decoy: bool,
}

struct OpenTicket {
    doc_id: [u8; 32],
    manifest_hash: [u8; 64],
    r_doc: Secret32,
    one_time: KemSecretKey,
    binding: [u8; 64],
}

/// The core. One per process; owns the gate and the store.
pub struct Core<G: HardwareGate, S: DeviceStore> {
    gate: G,
    store: S,
    session: Option<Session>,
    tickets: BTreeMap<OpenHandle, OpenTicket>,
    joining: Option<Seeds>,
}

/// The message a liveness key signs: `H(label, [parts…])` (64 bytes), so a proof made for
/// one action never stands for another.
fn live_msg(label: &str, parts: &[&[u8]]) -> Result<Vec<u8>> {
    Ok(labelled_hash(label, parts)?.to_vec())
}

impl<G: HardwareGate, S: DeviceStore> Core<G, S> {
    /// A locked core. Runs the suite's power-on self-test first.
    ///
    /// # Errors
    /// [`CoreError::Crypto`] if the self-test fails: refuse to run.
    pub fn new(gate: G, store: S) -> Result<Self> {
        humid_pq2::self_test()?;
        Ok(Self {
            gate,
            store,
            session: None,
            tickets: BTreeMap::new(),
            joining: None,
        })
    }

    /// The gate (tests inspect prompt counts).
    pub fn gate(&self) -> &G {
        &self.gate
    }

    /// The gate, mutably (tests set failures).
    pub fn gate_mut(&mut self) -> &mut G {
        &mut self.gate
    }

    /// The store (tests snapshot it).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The store, mutably (tests restore snapshots).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Whether unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// How many secret-holding things the core holds: the session, open tickets, a join in
    /// progress. Zero after [`Core::lock`].
    #[must_use]
    pub fn held_secrets(&self) -> usize {
        usize::from(self.session.is_some())
            + self.tickets.len()
            + usize::from(self.joining.is_some())
    }

    /// Lock: every session key, open ticket and join in progress is dropped and wiped.
    pub fn lock(&mut self) {
        self.session = None;
        self.tickets.clear();
        self.joining = None;
    }

    fn session(&self) -> Result<&Session> {
        self.session.as_ref().ok_or(CoreError::Locked)
    }

    fn writable(&self) -> Result<&Session> {
        let s = self.session()?;
        if s.decoy {
            Err(CoreError::Decoy)
        } else {
            Ok(s)
        }
    }

    fn read_slots(&self) -> Result<Vec<Option<Wrap>>> {
        SLOTS
            .iter()
            .map(|n| match self.store.read(n)? {
                Some(b) => Wrap::decode(&b).map(Some),
                None => Ok(None),
            })
            .collect()
    }

    /// Run one prompt; map outputs back to the derives and the live proof.
    fn authorize(
        &mut self,
        prompt: &Prompt,
        derive: &[&[u8]],
        live: Option<Vec<u8>>,
    ) -> Result<(Vec<Secret32>, LiveProof)> {
        let mut ops: Vec<HwOp> = derive.iter().map(|i| HwOp::Derive(i.to_vec())).collect();
        let want_live = live.is_some();
        if let Some(m) = live {
            ops.push(HwOp::SignLive(m));
        }
        if ops.len() > self.gate.info().max_ops {
            return Err(GateError::TooManyOps.into());
        }
        let outs = self.gate.authorize(prompt, &ops)?;
        if outs.len() != ops.len() {
            return Err(GateError::Platform.into());
        }
        let mut hws = Vec::with_capacity(derive.len());
        let mut proof = LiveProof::default();
        for (op, out) in ops.iter().zip(outs) {
            match (op, out) {
                (HwOp::Derive(_), HwOutput::Derived(s)) => hws.push(s),
                (HwOp::SignLive(_), HwOutput::Live(p)) => proof = p,
                _ => return Err(GateError::Platform.into()),
            }
        }
        if want_live && proof.sigs.is_empty() {
            // fail closed: no release without the liveness signature (audit L1)
            return Err(GateError::Platform.into());
        }
        Ok((hws, proof))
    }

    /* ------------------------------ enrolment ------------------------------ */

    fn write_first_wrap(
        &mut self,
        prompt: &Prompt,
        seeds: &Seeds,
        challenge: &[u8],
    ) -> Result<Unlocked> {
        if self.read_slots()?.iter().any(Option::is_some) {
            return Err(CoreError::AlreadyEnrolled);
        }
        let keys = SessionKeys::derive(seeds)?;
        let public = keys.public();
        let (account_id, device_id) = (public.account_id(), public.device_id());
        let t = self.gate.target(TargetKind::Wrap)?;
        let msg = live_msg(
            "HUMID-PQ2 live-enroll",
            &[challenge, &account_id, &device_id],
        )?;
        let (mut hws, live) = match &t.value {
            Some(_) => self.authorize(prompt, &[], Some(msg))?,
            None => self.authorize(prompt, &[&t.input], Some(msg))?,
        };
        let hw = match t.value {
            Some(v) => v,
            None => hws.pop().ok_or(CoreError::Gate(GateError::Platform))?,
        };
        let floor = self.store.floor()?;
        let w = Wrap::seal(&hw, floor, account_id, device_id, t.input, seeds)?;
        self.store.write(w.slot(), &w.encode())?;
        self.store.raise_floor(floor)?;
        self.session = Some(Session {
            keys,
            public: public.clone(),
            account_id,
            device_id,
            revs: Revisions::default(),
            decoy: false,
        });
        Ok(Unlocked {
            identity: public,
            live,
            wrap_counter: floor,
            advanced: true,
        })
    }

    /// Set up this device as the first device of a new account. One prompt.
    ///
    /// # Errors
    /// [`CoreError::AlreadyEnrolled`]; gate and store errors.
    pub fn enroll(&mut self, prompt: &Prompt, challenge: &[u8]) -> Result<Unlocked> {
        let seeds = Seeds::new(None)?;
        self.write_first_wrap(prompt, &seeds, challenge)
    }

    /* ------------------------------- unlock -------------------------------- */

    /// Unlock: one prompt computes `HW_n` (and `HW_{n+1}` when the platform needs it), opens
    /// `W_n`, writes `W_{n+1}` and retires `W_n` (CORE.md §4).
    ///
    /// # Errors
    /// [`CoreError::NotEnrolled`], [`CoreError::Rollback`], [`CoreError::WrapUnusable`];
    /// gate and store errors. On any error the core stays locked.
    pub fn unlock(&mut self, prompt: &Prompt, challenge: &[u8]) -> Result<Unlocked> {
        self.lock();
        let floor = self.store.floor()?;
        let slots = self.read_slots()?;
        let cur = plan(&slots, floor)?;
        // Older wraps left by an interrupted step (or below the floor): retired once this
        // unlock completes its own step.
        let stale: Vec<Vec<u8>> = slots
            .iter()
            .flatten()
            .filter(|w| w.n < cur.n)
            .map(|w| w.hw_input.clone())
            .collect();
        let next = self.gate.target(TargetKind::Wrap)?;
        let msg = live_msg(
            "HUMID-PQ2 live-unlock",
            &[
                challenge,
                &cur.account_id,
                &cur.device_id,
                &cur.n.to_be_bytes(),
            ],
        )?;
        let derive: Vec<&[u8]> = match &next.value {
            Some(_) => vec![&cur.hw_input],
            None => vec![&cur.hw_input, &next.input],
        };
        let res = self.authorize(prompt, &derive, Some(msg));
        let (mut hws, live) = match res {
            Ok(x) => x,
            Err(e) => {
                self.gate.retire(&next.input);
                return Err(e);
            }
        };
        let hw_next = match next.value {
            Some(v) => v,
            None => hws.pop().ok_or(CoreError::Gate(GateError::Platform))?,
        };
        let hw_cur = hws.pop().ok_or(CoreError::Gate(GateError::Platform))?;
        let seeds = match cur.open(&hw_cur) {
            Ok(s) => s,
            Err(e) => {
                self.gate.retire(&next.input);
                return Err(e);
            }
        };
        let keys = SessionKeys::derive(&seeds)?;
        let public = keys.public();
        if public.account_id() != cur.account_id || public.device_id() != cur.device_id {
            self.gate.retire(&next.input);
            return Err(CoreError::WrapUnusable);
        }

        // Ratchet: write W_{n+1} into the other slot, raise the floor, retire W_n.
        let n1 = cur.n.checked_add(1).ok_or(CoreError::Format)?;
        let mut advanced = false;
        let mut counter = cur.n;
        let w1 = Wrap::seal(
            &hw_next,
            n1,
            cur.account_id,
            cur.device_id,
            next.input.clone(),
            &seeds,
        )?;
        if self.store.write(w1.slot(), &w1.encode()).is_ok() {
            // From here W_{n+1} is durable; a crash before the floor rises leaves both, and the
            // next unlock picks n+1.
            if self.store.raise_floor(n1).is_ok() {
                self.gate.retire(&cur.hw_input);
                for input in &stale {
                    self.gate.retire(input);
                }
                let _ = self.store.delete(cur.slot());
                advanced = true;
            }
            counter = n1;
        } else {
            self.gate.retire(&next.input);
        }

        let revs = match self.store.read(REVS_FILE)? {
            Some(b) => Revisions::open(&keys.device_records_key, &cur.device_id, &b)?,
            None => Revisions::default(),
        };
        self.session = Some(Session {
            keys,
            public: public.clone(),
            account_id: cur.account_id,
            device_id: cur.device_id,
            revs,
            decoy: false,
        });
        Ok(Unlocked {
            identity: public,
            live,
            wrap_counter: counter,
            advanced,
        })
    }

    /// Switch this session to decoy (duress) mode until lock: nothing is written, sealed,
    /// granted or sent. One way.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn enter_decoy(&mut self) -> Result<()> {
        self.session.as_mut().ok_or(CoreError::Locked)?.decoy = true;
        Ok(())
    }

    /// The public identity.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn identity(&self) -> Result<PublicIdentity> {
        Ok(self.session()?.public.clone())
    }

    /* ------------------------------ documents ------------------------------ */

    /// Seal a document: streams `input` into an envelope on `out`, then one prompt for the
    /// live proof (and `HW_doc` where the platform must compute it). If this returns an
    /// error, discard what was written to `out`.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], I/O, gate and crypto errors.
    pub fn seal_document(
        &mut self,
        prompt: &Prompt,
        meta: &DocMeta,
        input: &mut dyn Read,
        out: &mut dyn Write,
        key_service: &KemPublicKey,
        challenge: &[u8],
    ) -> Result<SealReceipt> {
        let s = self.writable()?;
        let prep = PreparedDoc::new(&s.public.account_kem, s.account_id, CHUNK_SIZE)?;
        let (envelope_hash, size) = seal_stream(&prep, &s.keys.account_dsa, meta, input, out)?;
        let (account_id, device_id) = (s.account_id, s.device_id);
        let t = self.gate.target(TargetKind::Document)?;
        let msg = live_msg(
            "HUMID-PQ2 live-seal",
            &[
                challenge,
                &prep.manifest.doc_id,
                &prep.manifest_hash,
                &envelope_hash,
            ],
        )?;
        let (mut hws, live) = match &t.value {
            Some(_) => self.authorize(prompt, &[], Some(msg))?,
            None => self.authorize(prompt, &[&t.input], Some(msg))?,
        };
        let hw = match t.value {
            Some(v) => v,
            None => hws.pop().ok_or(CoreError::Gate(GateError::Platform))?,
        };
        let slot = DeviceSlot::seal(
            &hw,
            prep.manifest.doc_id,
            device_id,
            prep.manifest_hash,
            t.input,
            &prep.r_doc,
        )?;
        let share_upload = seal_share(
            ShareDirection::Upload,
            key_service,
            &account_id,
            &prep.manifest.doc_id,
            &prep.manifest_hash,
            &prep.share,
        )?;
        Ok(SealReceipt {
            doc_id: prep.manifest.doc_id,
            manifest_hash: prep.manifest_hash,
            envelope_hash,
            size,
            slot: slot.encode(),
            share_upload,
            live,
        })
    }

    /// Start opening a document from this device's slot: one prompt computes `HW_doc` and
    /// signs the share request. Send `share_request` with the live proof; pass the sealed
    /// share the key service returns to [`Core::finish_open`].
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::WrongDocument`] for another device's slot; gate
    /// errors.
    pub fn begin_open(
        &mut self,
        prompt: &Prompt,
        slot: &[u8],
        challenge: &[u8],
    ) -> Result<OpenStarted> {
        let s = self.session()?;
        let slot = AnySlot::decode(slot)?;
        let (doc_id, slot_device, manifest_hash) = slot.ids();
        if slot_device != s.device_id {
            return Err(CoreError::WrongDocument);
        }
        let account_id = s.account_id;
        let one_time = KemSecretKey::generate()?;
        let req = ShareRequest {
            account_id,
            doc_id,
            manifest_hash,
            one_time: one_time.public_key().clone(),
        };
        let binding = req.binding()?;
        let msg = live_msg("HUMID-PQ2 live-open", &[challenge, &binding])?;
        let (r_doc, live, adopted_slot) = match slot {
            AnySlot::Device(d) => {
                let (mut hws, live) = self.authorize(prompt, &[&d.hw_input], Some(msg))?;
                let hw = hws.pop().ok_or(CoreError::Gate(GateError::Platform))?;
                (d.open(&hw)?, live, None)
            }
            AnySlot::Pending(p) => {
                // Adopt: open with the device KEM key, re-wrap under this device's hardware.
                let r_doc = p.open(&self.session()?.keys.device_kem)?;
                let t = self.gate.target(TargetKind::Document)?;
                let (mut hws, live) = match &t.value {
                    Some(_) => self.authorize(prompt, &[], Some(msg))?,
                    None => self.authorize(prompt, &[&t.input], Some(msg))?,
                };
                let hw = match t.value {
                    Some(v) => v,
                    None => hws.pop().ok_or(CoreError::Gate(GateError::Platform))?,
                };
                let dev =
                    DeviceSlot::seal(&hw, doc_id, slot_device, manifest_hash, t.input, &r_doc)?;
                (r_doc, live, Some(dev.encode()))
            }
        };
        let mut h = [0u8; 8];
        humid_pq2::random_bytes(&mut h)?;
        let handle = OpenHandle(u64::from_be_bytes(h));
        self.tickets.insert(
            handle,
            OpenTicket {
                doc_id,
                manifest_hash,
                r_doc,
                one_time,
                binding,
            },
        );
        Ok(OpenStarted {
            handle,
            share_request: req.encode(),
            live,
            adopted_slot,
        })
    }

    /// Finish an open: unseal the share, check the envelope is this account's and this
    /// document's, and stream the plaintext into `viewer`. The handle is used up either way.
    /// If this returns an error, discard what was written to `viewer`.
    ///
    /// # Errors
    /// [`CoreError::BadHandle`], [`CoreError::WrongSigner`], [`CoreError::WrongDocument`],
    /// [`CoreError::Tampered`], I/O.
    pub fn finish_open(
        &mut self,
        handle: OpenHandle,
        sealed_share: &[u8],
        envelope: &mut dyn Read,
        viewer: &mut dyn Write,
    ) -> Result<Opened> {
        let t = self.tickets.remove(&handle).ok_or(CoreError::BadHandle)?;
        let s = self.session()?;
        let share = open_share(
            ShareDirection::Release,
            &t.one_time,
            &s.account_id,
            &t.doc_id,
            &t.binding,
            sealed_share,
        )
        .map_err(|_| CoreError::WrongDocument)?;
        let head = read_head(envelope, &s.public.account_dsa)?;
        if head.manifest.doc_id != t.doc_id || head.manifest_hash != t.manifest_hash {
            return Err(CoreError::WrongDocument);
        }
        let ss = account_secret(&head, &s.keys.account_kem)?;
        let (meta, size) = open_stream(&head, &ss, &t.r_doc, &share, envelope, viewer)?;
        Ok(Opened { meta, size })
    }

    /* ---------------------------- adding a device --------------------------- */

    /// On the new device, before it has any wrap: make its device seed (held in memory until
    /// [`Core::finish_join`] or lock) and return the public keys to show and send.
    ///
    /// # Errors
    /// [`CoreError::AlreadyEnrolled`].
    pub fn begin_join(&mut self) -> Result<JoinRequest> {
        if self.read_slots()?.iter().any(Option::is_some) {
            return Err(CoreError::AlreadyEnrolled);
        }
        let seeds = Seeds::new(None)?;
        let keys = SessionKeys::derive(&seeds)?;
        let req = JoinRequest {
            device_dsa: keys.device_dsa.verifying_key().clone(),
            device_kem: keys.device_kem.public_key().clone(),
        };
        self.joining = Some(seeds);
        Ok(req)
    }

    /// On an existing, unlocked device: approve `joiner`. Seals the account seed to it and
    /// re-wraps each of this device's `slots` as a pending slot for it. The `HW_doc` of each
    /// document needs a hardware operation, so this takes `ceil((N + 1) / max_ops)` prompts
    /// for N documents (CORE.md §5.3, open question 2).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], [`CoreError::WrongDocument`] for a slot
    /// that isn't this device's; gate errors (nothing is returned then).
    pub fn grant_device(
        &mut self,
        prompt: &Prompt,
        joiner: &JoinRequest,
        slots: &[Vec<u8>],
        challenge: &[u8],
    ) -> Result<Grant> {
        let s = self.writable()?;
        let (account_id, device_id) = (s.account_id, s.device_id);
        let mut mine = Vec::with_capacity(slots.len());
        for b in slots {
            match AnySlot::decode(b)? {
                AnySlot::Device(d) if d.device_id == device_id => mine.push(d),
                _ => return Err(CoreError::WrongDocument),
            }
        }
        let joiner_id = joiner.device_id();
        let msg = live_msg(
            "HUMID-PQ2 live-grant",
            &[
                challenge,
                &account_id,
                &joiner_id,
                &joiner.device_kem.key_id(),
            ],
        )?;
        let per = self.gate.info().max_ops.saturating_sub(1).max(1);
        let mut pending = Vec::with_capacity(mine.len());
        let mut live = LiveProof::default();
        let mut prompts = 0;
        let mut first = true;
        let mut rest: &[DeviceSlot] = &mine;
        while first || !rest.is_empty() {
            let take = rest.len().min(if first { per } else { per + 1 });
            let (batch, tail) = rest.split_at(take);
            let inputs: Vec<&[u8]> = batch.iter().map(|d| d.hw_input.as_slice()).collect();
            let (hws, l) = self.authorize(
                prompt,
                &inputs,
                if first { Some(msg.clone()) } else { None },
            )?;
            prompts += 1;
            if first {
                live = l;
            }
            for (d, hw) in batch.iter().zip(hws) {
                let r_doc = d.open(&hw)?;
                pending.push(
                    PendingSlot::seal(
                        &joiner.device_kem,
                        d.doc_id,
                        joiner_id,
                        d.manifest_hash,
                        &r_doc,
                    )?
                    .encode(),
                );
            }
            rest = tail;
            first = false;
        }
        let s = self.session()?;
        let join_seed = seal_to(
            &joiner.device_kem,
            ObjectType::JOIN_SEED,
            &[&account_id, &joiner_id],
            s.keys.account_seed.expose(),
        )?;
        Ok(Grant {
            join_seed,
            pending,
            live,
            prompts,
        })
    }

    /// On the new device: open the account seed sealed to it, check it is `expected_account`
    /// (from the key code the person compared), and write this device's first wrap. One
    /// prompt.
    ///
    /// # Errors
    /// [`CoreError::BadHandle`] with no join in progress; [`CoreError::WrongDocument`] if
    /// the seed isn't for this device or account; gate and store errors.
    pub fn finish_join(
        &mut self,
        prompt: &Prompt,
        join_seed: &[u8],
        expected_account: &[u8; 32],
        challenge: &[u8],
    ) -> Result<Unlocked> {
        let mine = self.joining.take().ok_or(CoreError::BadHandle)?;
        let k = SessionKeys::derive(&mine)?;
        let device_id = k.device_dsa.verifying_key().key_id();
        let pt = open_sealed(
            &k.device_kem,
            ObjectType::JOIN_SEED,
            &[expected_account, &device_id],
            join_seed,
        )
        .map_err(|_| CoreError::WrongDocument)?;
        let account = Secret32::from_slice(&pt).map_err(|_| CoreError::WrongDocument)?;
        let mut both = [0u8; crate::keys::SEEDS_LEN];
        both[..32].copy_from_slice(account.expose());
        both[32..].copy_from_slice(mine.device());
        let seeds = Seeds(humid_pq2::Secret::new(&mut both));
        if SessionKeys::derive(&seeds)?.public().account_id() != *expected_account {
            return Err(CoreError::WrongDocument);
        }
        self.write_first_wrap(prompt, &seeds, challenge)
    }

    /* ---------------------------- local records ---------------------------- */

    /// Seal an index entry for `item_id` at the next revision.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], store errors.
    pub fn seal_index_entry(&mut self, item_id: &[u8], entry: &[u8]) -> Result<Vec<u8>> {
        self.writable()?;
        let s = self.session.as_mut().ok_or(CoreError::Locked)?;
        let rev = s.revs.next(item_id)?;
        let blob = seal_index(&s.keys.index_key, &s.account_id, item_id, rev, entry)?;
        s.revs.accept(item_id, rev)?;
        let revs = s.revs.seal(&s.keys.device_records_key, &s.device_id)?;
        self.store.write(REVS_FILE, &revs)?;
        Ok(blob)
    }

    /// Open `item_id`'s index entry; refuses one older than this device has seen.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::WrongDocument`], [`CoreError::Rollback`].
    pub fn open_index_entry(&mut self, item_id: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        let s = self.session.as_mut().ok_or(CoreError::Locked)?;
        let (rev, entry) = open_index(&s.keys.index_key, &s.account_id, item_id, blob)?;
        s.revs.accept(item_id, rev)?;
        if !s.decoy {
            let revs = s.revs.seal(&s.keys.device_records_key, &s.device_id)?;
            self.store.write(REVS_FILE, &revs)?;
        }
        Ok(entry.to_vec())
    }

    /// Store a device-only setting.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], store errors.
    pub fn set_setting(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let s = self.writable()?;
        let b = seal_setting(&s.keys.device_records_key, &s.device_id, name, value)?;
        self.store.write(&format!("setting-{name}"), &b)?;
        Ok(())
    }

    /// Read a device-only setting.
    ///
    /// # Errors
    /// [`CoreError::Locked`], crypto and store errors.
    pub fn setting(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let s = self.session()?;
        match self.store.read(&format!("setting-{name}"))? {
            Some(b) => Ok(Some(
                open_setting(&s.keys.device_records_key, &s.device_id, name, &b)?.to_vec(),
            )),
            None => Ok(None),
        }
    }
}
