//! The core: the only API the UI may call (CORE.md §1). Opaque handles in, results out;
//! never key bytes, and no plaintext except a document's bytes streamed to the viewer sink
//! the caller passes in, and the index entries and settings the screen shows.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use humid_pq2::{
    KemPublicKey, KemSecretKey, ObjectType, Secret32, ShareDirection, labelled_hash, open_sealed,
    open_share, seal_share, seal_to,
};
use zeroize::Zeroizing;

use crate::codes;
use crate::envelope::{
    AnySlot, CHUNK_SIZE, DeviceSlot, DocMeta, PendingSlot, PreparedDoc, ShareRequest,
    account_secret, open_stream, read_head, seal_stream,
};
use crate::error::{CoreError, Result};
use crate::gate::{
    GateError, HardwareGate, HwOp, HwOutput, HwTarget, LiveProof, Prompt, TargetKind,
};
use crate::join::{JoinGrantBody, JoinKey, JoinRequest};
use crate::keys::{PublicIdentity, Seeds, SessionKeys, device_dsa};
use crate::ratchet::{SLOTS, Wrap, plan};
use crate::records::{
    Revisions, Version, check_name, open_index, open_setting, seal_index, seal_setting,
};
use crate::store::{DeviceStore, REVS_COUNTER};

const REVS_FILE: &str = "revs";
const JOIN_KEY_FILE: &str = "join-key";

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
    /// Whether the ratchet step completed (`W_{n+1}` written and read back, floor raised,
    /// `W_n` retired). False after a storage failure; the next unlock finishes or retries.
    pub advanced: bool,
    /// Whether synced records can be checked for rollback. False if this device's record
    /// revisions are missing, rolled back or damaged: index entries then refuse to open
    /// until [`Core::reset_records`] (CORE.md §7).
    pub records_ok: bool,
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
    /// place (never in a decoy session).
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

/// What a joining device shows and sends (all public).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinStarted {
    /// The self-signed request, to send to the approving device.
    pub request: Vec<u8>,
    /// The code to show on this screen; the person types it on the approving device.
    pub code: String,
}

/// What approving a new device returns (all public).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The account seed and granted document list, sealed to the request's join key.
    pub join_seed: Vec<u8>,
    /// One pending slot per document, for the new device.
    pub pending: Vec<Vec<u8>>,
    /// What the live proof names: `H("HUMID-PQ2 join-binding", [request body])`.
    pub binding: [u8; 64],
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
    /// `None`: revisions unavailable (missing, rolled back or damaged).
    revs: Option<Revisions>,
    decoy: bool,
}

struct OpenTicket {
    doc_id: [u8; 32],
    manifest_hash: [u8; 64],
    r_doc: Secret32,
    one_time: KemSecretKey,
    binding: [u8; 64],
}

struct Joining {
    seeds: Seeds,
    join_kem: KemSecretKey,
    request: JoinRequest,
}

/// The core. One per process; owns the gate and the store, and hands neither out
/// (review M1): the UI layer only ever sees the result types above.
pub struct Core<G: HardwareGate, S: DeviceStore> {
    gate: G,
    store: S,
    session: Option<Session>,
    tickets: BTreeMap<OpenHandle, OpenTicket>,
    joining: Option<Joining>,
}

/// The message a liveness key signs: `H(label, [parts…])` (64 bytes), so a proof made for
/// one action never stands for another.
fn live_msg(label: &str, parts: &[&[u8]]) -> Result<Vec<u8>> {
    Ok(labelled_hash(label, parts)?.to_vec())
}

/// The session mode carried in every live proof made inside a session: `0x00` normal,
/// `0x01` duress (decoy). Only the servers that verify the proof can tell (review M4).
fn mode(decoy: bool) -> [u8; 1] {
    [u8::from(decoy)]
}

/// The ops one unlock needs at least: `HW_n`, the live signature, and `HW_{n+1}` when the
/// platform can't know it without the hardware. Fallback derives ride along if they fit.
fn unlock_ops(symmetric_next: bool) -> usize {
    2 + usize::from(symmetric_next)
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

    /// The gate (tests and the simulator only: whoever holds the gate can compute `HW_n`).
    #[cfg(any(test, feature = "software-gate"))]
    pub fn gate(&self) -> &G {
        &self.gate
    }

    /// The gate, mutably (tests and the simulator only).
    #[cfg(any(test, feature = "software-gate"))]
    pub fn gate_mut(&mut self) -> &mut G {
        &mut self.gate
    }

    /// The store (tests and the simulator only).
    #[cfg(any(test, feature = "software-gate"))]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The store, mutably (tests and the simulator only).
    #[cfg(any(test, feature = "software-gate"))]
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
                // An undecodable slot is ignored, not fatal: the other may still open.
                Some(b) => Ok(Wrap::decode(&b).ok()),
                None => Ok(None),
            })
            .collect()
    }

    fn any_wrap(&self) -> Result<bool> {
        Ok(SLOTS
            .iter()
            .map(|n| self.store.read(n))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .any(Option::is_some))
    }

    /// Run one prompt. Returns one entry per derive (`None` = the hardware doesn't know
    /// that input) and the live proof.
    fn authorize(
        &mut self,
        prompt: &Prompt,
        derive: &[&[u8]],
        live: Option<Vec<u8>>,
    ) -> Result<(Vec<Option<Secret32>>, LiveProof)> {
        let mut ops: Vec<HwOp> = derive.iter().map(|i| HwOp::Derive(i.to_vec())).collect();
        let want_live = live.is_some();
        if let Some(m) = live {
            ops.push(HwOp::SignLive(m));
        }
        if ops.len() > self.gate.info().max_ops {
            return Err(CoreError::Unsupported);
        }
        let outs = self.gate.authorize(prompt, &ops)?;
        if outs.len() != ops.len() {
            return Err(GateError::Platform.into());
        }
        let mut hws = Vec::with_capacity(derive.len());
        let mut proof = LiveProof::default();
        for (op, out) in ops.iter().zip(outs) {
            match (op, out) {
                (HwOp::Derive(_), HwOutput::Derived(s)) => hws.push(Some(s)),
                (HwOp::Derive(_), HwOutput::Unavailable) => hws.push(None),
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

    /// One prompt for a fresh target: its value, made by the hardware if the platform
    /// can't know it yet, and the live proof.
    fn authorize_target(
        &mut self,
        prompt: &Prompt,
        t: &HwTarget,
        live: Vec<u8>,
    ) -> Result<(Secret32, LiveProof)> {
        if let Some(v) = &t.value {
            let (_, l) = self.authorize(prompt, &[], Some(live))?;
            return Ok((v.duplicate(), l));
        }
        let (mut hws, l) = self.authorize(prompt, &[&t.input], Some(live))?;
        let hw = hws.pop().flatten().ok_or(GateError::UnknownInput)?;
        Ok((hw, l))
    }

    /* --------------------------- record revisions --------------------------- */

    /// Load this device's revisions, checked against the store's counter (review M2).
    fn load_revs(&mut self, key: &Secret32, device_id: &[u8; 32]) -> Result<Option<Revisions>> {
        let counter = self.store.counter(REVS_COUNTER)?;
        match self.store.read(REVS_FILE)? {
            None if counter == 0 => Ok(Some(Revisions::default())),
            None => Ok(None),
            Some(b) => match Revisions::open(key, device_id, &b) {
                Ok((r, c)) if c == counter => Ok(Some(r)),
                Ok((r, c)) if c > counter => {
                    // written, then the counter raise was lost: catch the counter up
                    self.store.raise_counter(REVS_COUNTER, c)?;
                    Ok(Some(r))
                }
                _ => Ok(None),
            },
        }
    }

    fn save_revs(&mut self) -> Result<()> {
        let s = self.session.as_ref().ok_or(CoreError::Locked)?;
        let revs = s.revs.as_ref().ok_or(CoreError::RecordsUnavailable)?;
        let c = self
            .store
            .counter(REVS_COUNTER)?
            .checked_add(1)
            .ok_or(CoreError::Format)?;
        let blob = revs.seal(&s.keys.device_records_key, &s.device_id, c)?;
        self.store.write(REVS_FILE, &blob)?;
        self.store.raise_counter(REVS_COUNTER, c)?;
        Ok(())
    }

    /// Start this device's record revisions afresh, after the UI has told the person their
    /// synced records' rollback check is restarting (they were missing or damaged).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], store errors.
    pub fn reset_records(&mut self) -> Result<()> {
        self.writable()?;
        if let Some(s) = self.session.as_mut() {
            s.revs = Some(Revisions::default());
        }
        self.save_revs()
    }

    /* ------------------------------ enrolment ------------------------------ */

    fn write_first_wrap(
        &mut self,
        prompt: &Prompt,
        seeds: &Seeds,
        challenge: &[u8],
    ) -> Result<Unlocked> {
        if self.any_wrap()? {
            return Err(CoreError::AlreadyEnrolled);
        }
        let keys = SessionKeys::derive(seeds)?;
        let public = keys.public();
        let (account_id, device_id) = (public.account_id(), public.device_id());
        let t = self.gate.target(TargetKind::Wrap)?;
        // Refuse a gate that couldn't unlock in one prompt later (review M3).
        if self.gate.info().max_ops < unlock_ops(t.value.is_none()) {
            self.gate.retire(&t.input);
            return Err(CoreError::Unsupported);
        }
        let msg = live_msg(
            "HUMID-PQ2 live-enroll",
            &[challenge, &account_id, &device_id],
        )?;
        let (hw, live) = match self.authorize_target(prompt, &t, msg) {
            Ok(x) => x,
            Err(e) => {
                self.gate.retire(&t.input);
                return Err(e);
            }
        };
        let floor = self.store.floor()?;
        let w = Wrap::seal(&hw, floor, account_id, device_id, t.input.clone(), seeds)?;
        let enc = w.encode();
        let wrote = self.store.write(w.slot(), &enc);
        if wrote.is_err() && self.store.read(w.slot()).ok().flatten().as_deref() != Some(&enc[..]) {
            self.gate.retire(&t.input);
            return Err(CoreError::Store(crate::store::StoreError::Io));
        }
        self.store.raise_floor(floor)?;
        // A fresh device starts its revisions now.
        let revs = self.load_revs(&keys.device_records_key, &device_id)?;
        self.session = Some(Session {
            keys,
            public: public.clone(),
            account_id,
            device_id,
            revs,
            decoy: false,
        });
        let records_ok = self.session.as_ref().is_some_and(|s| s.revs.is_some());
        Ok(Unlocked {
            identity: public,
            live,
            wrap_counter: floor,
            advanced: true,
            records_ok,
        })
    }

    /// Set up this device as the first device of a new account. One prompt.
    ///
    /// # Errors
    /// [`CoreError::AlreadyEnrolled`]; [`CoreError::Unsupported`] if this device's hardware
    /// can't unlock in one prompt; gate and store errors.
    pub fn enroll(&mut self, prompt: &Prompt, challenge: &[u8]) -> Result<Unlocked> {
        let seeds = Seeds::new()?;
        self.write_first_wrap(prompt, &seeds, challenge)
    }

    /* ------------------------------- unlock -------------------------------- */

    /// Unlock: one prompt computes `HW` for the wraps on disk (highest first) and, when the
    /// platform needs it, `HW_{n+1}`; the highest wrap that opens is `W_n`. Then `W_{n+1}`
    /// is written, read back and opened in software, and only then is the floor raised and
    /// `W_n` retired (CORE.md §4).
    ///
    /// # Errors
    /// [`CoreError::NotEnrolled`], [`CoreError::Rollback`], [`CoreError::WrapUnusable`];
    /// gate and store errors. On any error the core stays locked.
    pub fn unlock(&mut self, prompt: &Prompt, challenge: &[u8]) -> Result<Unlocked> {
        self.lock();
        let floor = self.store.floor()?;
        let slots = self.read_slots()?;
        let cands = match plan(&slots, floor) {
            Ok(c) => c,
            Err(CoreError::NotEnrolled) if self.any_wrap()? => return Err(CoreError::WrapUnusable),
            Err(e) => return Err(e),
        };
        let next = self.gate.target(TargetKind::Wrap)?;
        match self.unlock_with(prompt, challenge, &cands, &slots, &next) {
            Ok(u) => Ok(u),
            Err(e) => {
                // W_{n+1} was never written: its target is safe to retire (review L7).
                self.gate.retire(&next.input);
                Err(e)
            }
        }
    }

    fn unlock_with(
        &mut self,
        prompt: &Prompt,
        challenge: &[u8],
        cands: &[Wrap],
        slots: &[Option<Wrap>],
        next: &HwTarget,
    ) -> Result<Unlocked> {
        let max = self.gate.info().max_ops;
        let need_next = next.value.is_none();
        if max < unlock_ops(need_next) {
            return Err(CoreError::Unsupported);
        }
        // Candidates, highest first, as many as fit beside HW_{n+1} and the live signature.
        let room = max - usize::from(need_next) - 1;
        let tried: Vec<&Wrap> = cands.iter().take(room).collect();
        let top = tried[0];
        let msg = live_msg(
            "HUMID-PQ2 live-unlock",
            &[
                challenge,
                &top.account_id,
                &top.device_id,
                &top.n.to_be_bytes(),
            ],
        )?;
        let mut derive: Vec<&[u8]> = tried.iter().map(|w| w.hw_input.as_slice()).collect();
        if need_next {
            derive.push(&next.input);
        }
        let (mut hws, live) = self.authorize(prompt, &derive, Some(msg))?;
        let hw_next = match &next.value {
            Some(v) => v.duplicate(),
            None => hws.pop().flatten().ok_or(GateError::UnknownInput)?,
        };
        // The highest candidate that opens and names the keys it opens to.
        let mut opened = None;
        let mut any_hw = false;
        for (w, hw) in tried.iter().zip(&hws) {
            let Some(hw) = hw else { continue };
            any_hw = true;
            let Ok(seeds) = w.open(hw) else { continue };
            let Ok(keys) = SessionKeys::derive(&seeds) else {
                continue;
            };
            let p = keys.public();
            if p.account_id() == w.account_id && p.device_id() == w.device_id {
                opened = Some(((*w).clone(), seeds, keys));
                break;
            }
        }
        let Some((cur, seeds, keys)) = opened else {
            return Err(if any_hw {
                CoreError::WrapUnusable
            } else {
                GateError::UnknownInput.into()
            });
        };
        let public = keys.public();
        let (counter, advanced) = self.ratchet_step(&cur, &seeds, slots, next, &hw_next)?;

        let revs = self.load_revs(&keys.device_records_key, &cur.device_id)?;
        let records_ok = revs.is_some();
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
            records_ok,
        })
    }

    /// Write `W_{n+1}`, read it back and open it in software, and only then retire what it
    /// supersedes and raise the floor (review H2). Returns the wrap counter now in use and
    /// whether the step completed.
    fn ratchet_step(
        &mut self,
        cur: &Wrap,
        seeds: &Seeds,
        slots: &[Option<Wrap>],
        next: &HwTarget,
        hw_next: &Secret32,
    ) -> Result<(u64, bool)> {
        let n1 = cur.n.checked_add(1).ok_or(CoreError::Format)?;
        let w1 = Wrap::seal(
            hw_next,
            n1,
            cur.account_id,
            cur.device_id,
            next.input.clone(),
            seeds,
        )?;
        let enc = w1.encode();
        let _ = self.store.write(w1.slot(), &enc);
        let back = self.store.read(w1.slot());
        let durable = matches!(&back, Ok(Some(b)) if *b == enc)
            && Wrap::decode(&enc)
                .and_then(|w| w.open(hw_next))
                .is_ok_and(|s| s.0.ct_eq(&seeds.0));
        if !durable {
            // W_{n+1} isn't usable on disk. Retire its target only if it is certainly not
            // there (the read succeeded and shows other bytes); an unknown outcome keeps it.
            if matches!(&back, Ok(b) if b.as_deref() != Some(&enc[..])) {
                self.gate.retire(&next.input);
            }
            return Ok((cur.n, false));
        }
        // Lower wraps are superseded now that cur opened. Never retire cur's own input
        // through another wrap (a planted copy can carry it).
        for w in slots.iter().flatten() {
            if w.n < cur.n && w.hw_input != cur.hw_input && w.hw_input != next.input {
                self.gate.retire(&w.hw_input);
            }
        }
        if self.store.raise_floor(n1).is_ok() {
            self.gate.retire(&cur.hw_input);
            let _ = self.store.delete(cur.slot());
            Ok((n1, true))
        } else {
            // Both stay; the next unlock opens W_{n+1} first and finishes the step.
            Ok((n1, false))
        }
    }

    /// Switch this session to decoy (duress) mode until lock: nothing is written, sealed,
    /// granted or adopted, and every live proof made from now on carries the duress mode, so
    /// the key-share service can refuse or answer with a decoy (CORE.md §8). One way.
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
                &mode(false),
            ],
        )?;
        let (hw, live) = match self.authorize_target(prompt, &t, msg) {
            Ok(x) => x,
            Err(e) => {
                self.gate.retire(&t.input);
                return Err(e);
            }
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
    /// A pending slot (from a join) is opened with this device's join key and, outside a
    /// decoy session, adopted into a hardware slot in the same prompt.
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
        let decoy = s.decoy;
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
        let msg = live_msg("HUMID-PQ2 live-open", &[challenge, &binding, &mode(decoy)])?;
        let (r_doc, live, adopted_slot) = match slot {
            AnySlot::Device(d) => {
                let (mut hws, live) = self.authorize(prompt, &[&d.hw_input], Some(msg))?;
                let hw = hws.pop().flatten().ok_or(GateError::UnknownInput)?;
                (d.open(&hw)?, live, None)
            }
            AnySlot::Pending(p) => {
                let jk = self.join_key()?.ok_or(CoreError::WrongDocument)?;
                let r_doc = p.open(&jk.kem())?;
                if decoy {
                    // Duress: no new hardware key, nothing to upload (review M4).
                    let (_, live) = self.authorize(prompt, &[], Some(msg))?;
                    (r_doc, live, None)
                } else {
                    let t = self.gate.target(TargetKind::Document)?;
                    let (hw, live) = match self.authorize_target(prompt, &t, msg) {
                        Ok(x) => x,
                        Err(e) => {
                            self.gate.retire(&t.input);
                            return Err(e);
                        }
                    };
                    let dev =
                        DeviceSlot::seal(&hw, doc_id, slot_device, manifest_hash, t.input, &r_doc)?;
                    self.adopted(jk, &doc_id)?;
                    (r_doc, live, Some(dev.encode()))
                }
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

    /// On the new device, before it has any wrap: make its device seed and a one-time join
    /// key (held in memory until [`Core::finish_join`] or lock), and return the self-signed
    /// request and the code to show. `account_id` is the account to join, as the server
    /// named it; the grant must match it.
    ///
    /// # Errors
    /// [`CoreError::AlreadyEnrolled`].
    pub fn begin_join(&mut self, account_id: [u8; 32]) -> Result<JoinStarted> {
        if self.any_wrap()? {
            return Err(CoreError::AlreadyEnrolled);
        }
        let seeds = Seeds::new()?;
        let join_kem = KemSecretKey::generate()?;
        let request = JoinRequest::sign(account_id, &device_dsa(&seeds)?, join_kem.public_key())?;
        let out = JoinStarted {
            request: request.encode(),
            code: request.code()?,
        };
        self.joining = Some(Joining {
            seeds,
            join_kem,
            request,
        });
        Ok(out)
    }

    /// On an existing, unlocked device: approve the device whose `request` this is, after
    /// the person typed the code the new device shows (`typed_code`). Refuses unless the
    /// request is self-signed, names this account, and the code matches (review H1). Seals
    /// the account seed to the request's join key and re-wraps each of this device's
    /// `slots` as a pending slot for it.
    ///
    /// The first prompt carries the live signature and as many `HW_doc` derives as fit; each
    /// further prompt carries `max_ops` derives (CORE.md §5.3).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], [`CoreError::WrongSigner`] for a forged
    /// request, [`CoreError::CodeMismatch`], [`CoreError::WrongDocument`] for another
    /// account or a slot that isn't this device's; gate errors (nothing is returned then).
    pub fn grant_device(
        &mut self,
        prompt: &Prompt,
        request: &[u8],
        typed_code: &str,
        slots: &[Vec<u8>],
        challenge: &[u8],
    ) -> Result<Grant> {
        let s = self.writable()?;
        let (account_id, device_id) = (s.account_id, s.device_id);
        let req = JoinRequest::decode(request)?;
        if req.account_id != account_id {
            return Err(CoreError::WrongDocument);
        }
        if !codes::matches(typed_code, &req.code()?) {
            return Err(CoreError::CodeMismatch);
        }
        let mut mine = Vec::with_capacity(slots.len());
        for b in slots {
            match AnySlot::decode(b)? {
                AnySlot::Device(d) if d.device_id == device_id => mine.push(d),
                _ => return Err(CoreError::WrongDocument),
            }
        }
        let joiner_id = req.device_id();
        let binding = req.binding()?;
        let msg = live_msg("HUMID-PQ2 live-grant", &[challenge, &account_id, &binding])?;
        let max = self.gate.info().max_ops;
        if max == 0 {
            return Err(CoreError::Unsupported);
        }
        let mut pending = Vec::with_capacity(mine.len());
        let mut live = LiveProof::default();
        let mut prompts = 0;
        let mut first = true;
        let mut rest: &[DeviceSlot] = &mine;
        while first || !rest.is_empty() {
            let take = rest.len().min(if first { max - 1 } else { max });
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
                let hw = hw.ok_or(GateError::UnknownInput)?;
                let r_doc = d.open(&hw)?;
                pending.push(
                    PendingSlot::seal(&req.join_kem, d.doc_id, joiner_id, d.manifest_hash, &r_doc)?
                        .encode(),
                );
            }
            rest = tail;
            first = false;
        }
        let s = self.session()?;
        let body = JoinGrantBody {
            account_seed: s.keys.account_seed.duplicate(),
            doc_ids: mine.iter().map(|d| d.doc_id).collect(),
        };
        let join_seed = seal_to(
            &req.join_kem,
            ObjectType::JOIN_SEED,
            &[&account_id, &joiner_id, &binding],
            &body.encode()?,
        )?;
        Ok(Grant {
            join_seed,
            pending,
            binding,
            live,
            prompts,
        })
    }

    /// On the new device: open the grant with this join's key, check it is for the account
    /// the request named, and write this device's first wrap. One prompt. The join key is
    /// kept (sealed) only while granted documents still wait to be adopted.
    ///
    /// # Errors
    /// [`CoreError::BadHandle`] with no join in progress; [`CoreError::WrongDocument`] if
    /// the grant isn't for this join or account; gate and store errors.
    pub fn finish_join(
        &mut self,
        prompt: &Prompt,
        join_seed: &[u8],
        challenge: &[u8],
    ) -> Result<Unlocked> {
        let j = self.joining.take().ok_or(CoreError::BadHandle)?;
        let device_id = j.request.device_id();
        let binding = j.request.binding()?;
        let pt = open_sealed(
            &j.join_kem,
            ObjectType::JOIN_SEED,
            &[&j.request.account_id, &device_id, &binding],
            join_seed,
        )
        .map_err(|_| CoreError::WrongDocument)?;
        let body = JoinGrantBody::decode(&pt).map_err(|_| CoreError::WrongDocument)?;
        let seeds = Seeds::join(&body.account_seed, j.seeds.device());
        if SessionKeys::derive(&seeds)?.public().account_id() != j.request.account_id {
            return Err(CoreError::WrongDocument);
        }
        let u = self.write_first_wrap(prompt, &seeds, challenge)?;
        if !body.doc_ids.is_empty() {
            self.save_join_key(&JoinKey {
                seed: j.join_kem.seed().duplicate(),
                pending: body.doc_ids,
            })?;
        }
        Ok(u)
    }

    fn join_key(&self) -> Result<Option<JoinKey>> {
        let s = self.session()?;
        match self.store.read(JOIN_KEY_FILE)? {
            None => Ok(None),
            Some(b) => {
                let pt = humid_pq2::open_at_rest(
                    &s.keys.device_records_key,
                    ObjectType::JOIN_KEY,
                    &[&s.device_id],
                    &b,
                )?;
                Ok(Some(JoinKey::decode(&pt)?))
            }
        }
    }

    fn save_join_key(&mut self, k: &JoinKey) -> Result<()> {
        let s = self.session()?;
        let b = humid_pq2::seal_at_rest(
            &s.keys.device_records_key,
            ObjectType::JOIN_KEY,
            &[&s.device_id],
            &k.encode()?,
        )?;
        self.store.write(JOIN_KEY_FILE, &b)?;
        Ok(())
    }

    /// One granted document now has a hardware slot: once none are left, the join key is
    /// destroyed, so a captured pending slot no longer opens with anything on this device.
    fn adopted(&mut self, mut k: JoinKey, doc_id: &[u8; 32]) -> Result<()> {
        k.pending.retain(|d| d != doc_id);
        if k.pending.is_empty() {
            self.store.delete(JOIN_KEY_FILE)?;
            Ok(())
        } else {
            self.save_join_key(&k)
        }
    }

    /// How many granted documents still wait for their first open on this device.
    ///
    /// # Errors
    /// [`CoreError::Locked`], store errors.
    pub fn pending_adoptions(&self) -> Result<usize> {
        Ok(self.join_key()?.map_or(0, |k| k.pending.len()))
    }

    /* ---------------------------- local records ---------------------------- */

    /// Seal an index entry for `item_id`. Pass the entry the vault holds for it now
    /// (`current`), if any: the new revision is above both it and anything this device has
    /// seen, and carries this device's id, so two devices' writes are totally ordered
    /// (review M7).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], [`CoreError::RecordsUnavailable`],
    /// [`CoreError::WrongDocument`] / [`CoreError::Rollback`] for a bad `current`; store
    /// errors.
    pub fn seal_index_entry(
        &mut self,
        item_id: &[u8],
        current: Option<&[u8]>,
        entry: &[u8],
    ) -> Result<Vec<u8>> {
        self.writable()?;
        let s = self.session.as_mut().ok_or(CoreError::Locked)?;
        let revs = s.revs.as_mut().ok_or(CoreError::RecordsUnavailable)?;
        if let Some(cur) = current {
            let (v, _) = open_index(&s.keys.index_key, &s.account_id, item_id, cur)?;
            revs.accept(item_id, v)?;
        }
        let seen = revs.seen(item_id).map_or(0, |(r, _)| r);
        let v: Version = (seen.checked_add(1).ok_or(CoreError::Format)?, s.device_id);
        let blob = seal_index(&s.keys.index_key, &s.account_id, item_id, v, entry)?;
        revs.accept(item_id, v)?;
        self.save_revs()?;
        Ok(blob)
    }

    /// Open `item_id`'s index entry; refuses one older than this device has seen.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::RecordsUnavailable`],
    /// [`CoreError::WrongDocument`], [`CoreError::Rollback`].
    pub fn open_index_entry(&mut self, item_id: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let s = self.session.as_mut().ok_or(CoreError::Locked)?;
        let revs = s.revs.as_mut().ok_or(CoreError::RecordsUnavailable)?;
        let (v, entry) = open_index(&s.keys.index_key, &s.account_id, item_id, blob)?;
        let before = revs.seen(item_id);
        revs.accept(item_id, v)?;
        if !s.decoy && before != Some(v) {
            self.save_revs()?;
        }
        Ok(entry)
    }

    /// Store a device-only setting. Names are `[a-z0-9-]{1,64}`.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Decoy`], [`CoreError::Format`] for a bad name,
    /// store errors.
    pub fn set_setting(&mut self, name: &str, value: &[u8]) -> Result<()> {
        check_name(name)?;
        let s = self.writable()?;
        let b = seal_setting(&s.keys.device_records_key, &s.device_id, name, value)?;
        self.store.write(&format!("setting-{name}"), &b)?;
        Ok(())
    }

    /// Read a device-only setting.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Format`] for a bad name, crypto and store errors.
    pub fn setting(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        check_name(name)?;
        let s = self.session()?;
        match self.store.read(&format!("setting-{name}"))? {
            Some(b) => Ok(Some(open_setting(
                &s.keys.device_records_key,
                &s.device_id,
                name,
                &b,
            )?)),
            None => Ok(None),
        }
    }
}
