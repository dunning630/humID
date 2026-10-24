//! Three-key documents: one layer of chunked, streaming AES-256-GCM-SIV (CORE.md §6).
//!
//! ```text
//! K_doc = KDF("HUMID-PQ2 doc", key = [ss_acct, hw_doc, share_ks],
//!             context = [doc_id, manifest_hash], 32)
//!
//!   ss_acct   hybrid KEM secret, encapsulated to the account key (ct in the manifest)
//!   hw_doc    r_doc: 32 random bytes, reachable only through a device slot, i.e. a hardware
//!             operation on this device inside a live check (one slot per enrolled device)
//!   share_ks  32 random bytes held by the key-share service, sealed both directions
//!
//! envelope  = manifest ‖ signature ‖ lp(meta box) ‖ chunk_0 ‖ chunk_1 ‖ … ‖ chunk_last
//! manifest  = header(0x0101) ‖ doc_id (32) ‖ account_id (32) ‖ kem_ct (1600) ‖ u32 chunk_size
//! manifest_hash = H("HUMID-PQ2 manifest", [manifest])
//! signature = ML-DSA-87 by the account key, ctx = SUITE ‖ u16 0x0103 ‖ "HUMID-PQ2 doc",
//!             msg = manifest                                          (raw 4627 bytes)
//! meta box  = AES-256-GCM-SIV(KDF("HUMID-PQ2 doc-meta", [K_doc], [], 32), nonce 0¹²,
//!             header(0x0107) ‖ lp(manifest_hash), pad64(lp(meta)))
//! chunk_i   = u32(len | last << 31) ‖ AES-256-GCM-SIV(K_doc, u64 i ‖ u32 last,
//!             header(0x0102) ‖ lp(manifest_hash, u64 i), plaintext_i)
//! ```
//!
//! Each chunk carries at most `chunk_size` plaintext bytes (64 KiB by default); every chunk
//! but the last is full; the last has the flag and may be empty. K_doc is fresh per
//! document (fresh `ss_acct`, `r_doc`, `share_ks`), so the counter nonce never repeats under
//! a key. Truncation, reordering, dropping, duplicating or moving a chunk to another
//! document all fail authentication. The signature covers the manifest, which fixes every
//! K_doc input but the secrets; it is checked against the account's pinned key before
//! anything is decrypted.

use std::io::{Read, Write};

use humid_pq2::encoding::{HEADER_LEN, Reader, aad, header, lp};
use humid_pq2::{
    KemCiphertext, KemPublicKey, KemSecretKey, MLDSA_SIG_LEN, MlDsaSignature, MlDsaSigningKey,
    MlDsaVerifyingKey, NONCE_LEN, ObjectType, Secret32, Sha3_512Stream, TAG_LEN, kdf,
    labelled_hash, siv_open, siv_seal,
};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Default plaintext bytes per chunk.
pub const CHUNK_SIZE: u32 = 64 * 1024;
/// Largest chunk size a reader accepts (bounds memory per chunk).
pub const MAX_CHUNK_SIZE: u32 = 1 << 20;
/// Largest metadata a document carries.
pub const MAX_META: usize = 16 * 1024;
const LAST: u32 = 1 << 31;
const KEM_RAW: usize = humid_pq2::KEM_CIPHERTEXT_LEN - HEADER_LEN;
/// Manifest bytes.
pub const MANIFEST_LEN: usize = HEADER_LEN + 32 + 32 + KEM_RAW + 4;

/// The fixed part of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Random document id.
    pub doc_id: [u8; 32],
    /// `key_id` of the account ML-DSA key that must have signed it.
    pub account_id: [u8; 32],
    kem_ct: KemCiphertext,
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
}

impl Manifest {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = header(ObjectType::DOC_MANIFEST).to_vec();
        v.extend_from_slice(&self.doc_id);
        v.extend_from_slice(&self.account_id);
        v.extend_from_slice(&self.kem_ct.to_bytes()[HEADER_LEN..]);
        v.extend_from_slice(&self.chunk_size.to_be_bytes());
        v
    }

    /// Decode.
    ///
    /// # Errors
    /// [`CoreError::Format`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::DOC_MANIFEST)?;
        let doc_id = r.array()?;
        let account_id = r.array()?;
        let mut ct = header(ObjectType::KEM_CIPHERTEXT).to_vec();
        ct.extend_from_slice(r.take(KEM_RAW)?);
        let chunk_size = r.u32()?;
        r.finish()?;
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(CoreError::Format);
        }
        Ok(Self {
            doc_id,
            account_id,
            kem_ct: KemCiphertext::from_bytes(&ct)?,
            chunk_size,
        })
    }

    /// `H("HUMID-PQ2 manifest", [manifest])`: what slots, shares and live proofs bind to.
    ///
    /// # Errors
    /// Never in practice (fixed label and size).
    pub fn hash(&self) -> Result<[u8; 64]> {
        Ok(labelled_hash("HUMID-PQ2 manifest", &[&self.encode()])?)
    }
}

/// What the screen may show about a document (sealed inside it; the vault never sees it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocMeta {
    /// File name.
    pub name: String,
    /// Media type.
    pub media_type: String,
}

impl DocMeta {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let body = Zeroizing::new(lp(&[self.name.as_bytes(), self.media_type.as_bytes()])?);
        if body.len() > MAX_META {
            return Err(CoreError::Format);
        }
        // pad to 64 bytes so the box size says little about the name
        let mut v = Zeroizing::new(lp(&[&body])?);
        let padded = v.len().div_ceil(64) * 64;
        v.resize(padded, 0);
        Ok(v)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let body = r.lp(MAX_META)?;
        if r.rest().iter().any(|&b| b != 0) {
            return Err(CoreError::Format);
        }
        let mut b = Reader::new(body);
        let name = String::from_utf8(b.lp(MAX_META)?.to_vec()).map_err(|_| CoreError::Format)?;
        let media_type =
            String::from_utf8(b.lp(MAX_META)?.to_vec()).map_err(|_| CoreError::Format)?;
        b.finish()?;
        Ok(Self { name, media_type })
    }
}

fn doc_key(
    ss_acct: &Secret32,
    hw_doc: &Secret32,
    share: &Secret32,
    m: &Manifest,
    mh: &[u8; 64],
) -> Result<Secret32> {
    Ok(kdf::<32>(
        "HUMID-PQ2 doc",
        &[ss_acct.expose(), hw_doc.expose(), share.expose()],
        &[&m.doc_id, mh],
    )?)
}

fn chunk_nonce(i: u64, last: bool) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(&i.to_be_bytes());
    n[8..].copy_from_slice(&u32::from(last).to_be_bytes());
    n
}

fn chunk_aad(mh: &[u8; 64], i: u64) -> Result<Vec<u8>> {
    Ok(aad(ObjectType::DOC_CHUNK, &[mh, &i.to_be_bytes()])?)
}

fn meta_key(k: &Secret32) -> Result<Secret32> {
    Ok(kdf::<32>("HUMID-PQ2 doc-meta", &[k.expose()], &[])?)
}

/// Everything a new document needs before its bytes stream through: computed before the
/// prompt, so the live proof can name `manifest_hash`.
pub(crate) struct PreparedDoc {
    pub manifest: Manifest,
    pub manifest_hash: [u8; 64],
    pub ss_acct: Secret32,
    pub r_doc: Secret32,
    pub share: Secret32,
}

impl PreparedDoc {
    pub(crate) fn new(
        account_kem: &KemPublicKey,
        account_id: [u8; 32],
        chunk_size: u32,
    ) -> Result<Self> {
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(CoreError::Format);
        }
        let mut doc_id = [0u8; 32];
        humid_pq2::random_bytes(&mut doc_id)?;
        let (kem_ct, ss_acct) = account_kem.encapsulate()?;
        let manifest = Manifest {
            doc_id,
            account_id,
            kem_ct,
            chunk_size,
        };
        let manifest_hash = manifest.hash()?;
        Ok(Self {
            manifest,
            manifest_hash,
            ss_acct,
            r_doc: Secret32::random()?,
            share: Secret32::random()?,
        })
    }
}

/// Stream `input` into a sealed envelope on `out`. Returns the ciphertext's SHA3-512 (over
/// the whole envelope) and the plaintext length.
pub(crate) fn seal_stream(
    prep: &PreparedDoc,
    signer: &MlDsaSigningKey,
    meta: &DocMeta,
    input: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<([u8; 64], u64)> {
    let k = doc_key(
        &prep.ss_acct,
        &prep.r_doc,
        &prep.share,
        &prep.manifest,
        &prep.manifest_hash,
    )?;
    let mut hash = Sha3_512Stream::new();
    let mut emit = |b: &[u8], hash: &mut Sha3_512Stream| -> Result<()> {
        hash.update(b);
        out.write_all(b).map_err(|_| CoreError::Io)
    };
    let m = prep.manifest.encode();
    emit(&m, &mut hash)?;
    let sig = signer.sign_typed(ObjectType::DOC_SIGNED, "HUMID-PQ2 doc", &m)?;
    emit(sig.raw(), &mut hash)?;
    let meta_ct = siv_seal(
        &meta_key(&k)?,
        &[0u8; NONCE_LEN],
        &aad(ObjectType::DOC_META, &[&prep.manifest_hash])?,
        &meta.encode()?,
    )?;
    emit(&lp(&[&meta_ct])?, &mut hash)?;

    let size = prep.manifest.chunk_size as usize;
    let mut cur = Zeroizing::new(vec![0u8; size]);
    let mut next = Zeroizing::new(vec![0u8; size]);
    let mut cur_len = read_full(input, &mut cur)?;
    let mut i: u64 = 0;
    let mut total: u64 = 0;
    loop {
        // Look ahead one chunk so the last one is flagged even when the input is an exact
        // multiple of the chunk size.
        let next_len = if cur_len == size {
            read_full(input, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let ct = siv_seal(
            &k,
            &chunk_nonce(i, last),
            &chunk_aad(&prep.manifest_hash, i)?,
            &cur[..cur_len],
        )?;
        let tag =
            u32::try_from(ct.len()).map_err(|_| CoreError::Format)? | if last { LAST } else { 0 };
        emit(&tag.to_be_bytes(), &mut hash)?;
        emit(&ct, &mut hash)?;
        total += cur_len as u64;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        i = i.checked_add(1).ok_or(CoreError::Format)?;
    }
    out.flush().map_err(|_| CoreError::Io)?;
    Ok((hash.finish(), total))
}

fn read_full(input: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match input.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(CoreError::Io),
        }
    }
    Ok(n)
}

fn read_exact(input: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
    if read_full(input, buf)? == buf.len() {
        Ok(())
    } else {
        Err(CoreError::Tampered)
    }
}

/// The head of an envelope, read and signature-checked before anything is decrypted.
pub(crate) struct EnvelopeHead {
    pub manifest: Manifest,
    pub manifest_hash: [u8; 64],
    meta_ct: Vec<u8>,
}

/// Read the manifest, signature and meta box from `input`, and check the signature against
/// the pinned account key.
pub(crate) fn read_head(input: &mut dyn Read, pinned: &MlDsaVerifyingKey) -> Result<EnvelopeHead> {
    let mut m = vec![0u8; MANIFEST_LEN];
    read_exact(input, &mut m).map_err(|_| CoreError::Format)?;
    let manifest = Manifest::decode(&m)?;
    let mut sig = vec![0u8; MLDSA_SIG_LEN];
    read_exact(input, &mut sig).map_err(|_| CoreError::Format)?;
    if manifest.account_id != pinned.key_id() {
        return Err(CoreError::WrongSigner);
    }
    let sig = MlDsaSignature::from_raw(&sig)?;
    pinned
        .verify_typed(ObjectType::DOC_SIGNED, "HUMID-PQ2 doc", &m, &sig)
        .map_err(|_| CoreError::WrongSigner)?;
    let mut l = [0u8; 4];
    read_exact(input, &mut l).map_err(|_| CoreError::Format)?;
    let n = u32::from_be_bytes(l) as usize;
    if n > MAX_META + 64 + 4 + TAG_LEN {
        return Err(CoreError::Format);
    }
    let mut meta_ct = vec![0u8; n];
    read_exact(input, &mut meta_ct).map_err(|_| CoreError::Format)?;
    let manifest_hash = manifest.hash()?;
    Ok(EnvelopeHead {
        manifest,
        manifest_hash,
        meta_ct,
    })
}

/// Decapsulate the account secret for a head.
pub(crate) fn account_secret(head: &EnvelopeHead, account_kem: &KemSecretKey) -> Result<Secret32> {
    Ok(account_kem.decapsulate(&head.manifest.kem_ct)?)
}

/// Decrypt the rest of the stream into `out`. Nothing is written for a chunk until it has
/// authenticated; a stream cut short or extended after the last chunk is an error. The
/// caller must discard what was written if this returns an error.
pub(crate) fn open_stream(
    head: &EnvelopeHead,
    ss_acct: &Secret32,
    hw_doc: &Secret32,
    share: &Secret32,
    input: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<(DocMeta, u64)> {
    let k = doc_key(ss_acct, hw_doc, share, &head.manifest, &head.manifest_hash)?;
    let meta_pt = siv_open(
        &meta_key(&k)?,
        &[0u8; NONCE_LEN],
        &aad(ObjectType::DOC_META, &[&head.manifest_hash])?,
        &head.meta_ct,
    )
    .map_err(|_| CoreError::Tampered)?;
    let meta = DocMeta::decode(&meta_pt)?;
    let max = head.manifest.chunk_size as usize + TAG_LEN;
    let mut buf = vec![0u8; max];
    let mut i: u64 = 0;
    let mut total = 0u64;
    loop {
        let mut t = [0u8; 4];
        read_exact(input, &mut t)?;
        let tag = u32::from_be_bytes(t);
        let last = tag & LAST != 0;
        let len = (tag & !LAST) as usize;
        if !(TAG_LEN..=max).contains(&len) {
            return Err(CoreError::Tampered);
        }
        read_exact(input, &mut buf[..len])?;
        let pt = siv_open(
            &k,
            &chunk_nonce(i, last),
            &chunk_aad(&head.manifest_hash, i)?,
            &buf[..len],
        )
        .map_err(|_| CoreError::Tampered)?;
        if !last && pt.len() != head.manifest.chunk_size as usize {
            return Err(CoreError::Tampered);
        }
        out.write_all(&pt).map_err(|_| CoreError::Io)?;
        total += pt.len() as u64;
        if last {
            break;
        }
        i = i.checked_add(1).ok_or(CoreError::Tampered)?;
    }
    let mut extra = [0u8; 1];
    if read_full(input, &mut extra)? != 0 {
        return Err(CoreError::Tampered);
    }
    out.flush().map_err(|_| CoreError::Io)?;
    Ok((meta, total))
}

/* ------------------------------ device slots ------------------------------ */

/// A document's `r_doc` for one device, under that device's hardware (CORE.md §6.2):
///
/// ```text
/// slot = header(0x0104) ‖ doc_id (32) ‖ device_id (32) ‖ manifest_hash (64) ‖ lp(hw_input)
///        ‖ AES-256-GCM-SIV(k, 0¹², A, r_doc) ‖ tag           (k is used once)
/// k    = KDF("HUMID-PQ2 doc-slot", [HW(hw_input)], [doc_id, device_id, manifest_hash, hw_input], 32)
/// A    = header(0x0104) ‖ lp(doc_id, device_id, manifest_hash, hw_input)
/// ```
///
/// The manifest hash travels in the clear so the slot can be opened before the envelope
/// arrives; opening then checks the envelope's manifest against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSlot {
    /// The document.
    pub doc_id: [u8; 32],
    /// The device it opens on.
    pub device_id: [u8; 32],
    /// The document's manifest hash.
    pub manifest_hash: [u8; 64],
    /// The hardware input.
    pub hw_input: Vec<u8>,
    ct: Vec<u8>,
}

impl DeviceSlot {
    fn key(&self, hw: &Secret32) -> Result<Secret32> {
        Ok(kdf::<32>(
            "HUMID-PQ2 doc-slot",
            &[hw.expose()],
            &[
                &self.doc_id,
                &self.device_id,
                &self.manifest_hash,
                &self.hw_input,
            ],
        )?)
    }

    fn aad(&self) -> Result<Vec<u8>> {
        Ok(aad(
            ObjectType::DEVICE_SLOT,
            &[
                &self.doc_id,
                &self.device_id,
                &self.manifest_hash,
                &self.hw_input,
            ],
        )?)
    }

    pub(crate) fn seal(
        hw: &Secret32,
        doc_id: [u8; 32],
        device_id: [u8; 32],
        manifest_hash: [u8; 64],
        hw_input: Vec<u8>,
        r_doc: &Secret32,
    ) -> Result<Self> {
        if hw_input.len() > crate::gate::MAX_INPUT {
            return Err(CoreError::Format);
        }
        let mut s = Self {
            doc_id,
            device_id,
            manifest_hash,
            hw_input,
            ct: Vec::new(),
        };
        s.ct = siv_seal(&s.key(hw)?, &[0u8; NONCE_LEN], &s.aad()?, r_doc.expose())?;
        Ok(s)
    }

    pub(crate) fn open(&self, hw: &Secret32) -> Result<Secret32> {
        let pt = siv_open(&self.key(hw)?, &[0u8; NONCE_LEN], &self.aad()?, &self.ct)
            .map_err(|_| CoreError::WrongDocument)?;
        Secret32::from_slice(&pt).map_err(|_| CoreError::WrongDocument)
    }

    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = header(ObjectType::DEVICE_SLOT).to_vec();
        v.extend_from_slice(&self.doc_id);
        v.extend_from_slice(&self.device_id);
        v.extend_from_slice(&self.manifest_hash);
        // hw_input ≤ MAX_INPUT, so the prefix can't fail
        let _ = humid_pq2::encoding::lp_push(&mut v, &self.hw_input);
        v.extend_from_slice(&self.ct);
        v
    }

    /// Decode.
    ///
    /// # Errors
    /// [`CoreError::Format`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::DEVICE_SLOT)?;
        let doc_id = r.array()?;
        let device_id = r.array()?;
        let manifest_hash = r.array()?;
        let hw_input = r.lp(crate::gate::MAX_INPUT)?.to_vec();
        let ct = r.take(32 + TAG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
            doc_id,
            device_id,
            manifest_hash,
            hw_input,
            ct,
        })
    }
}

/* ------------------------- pending slots (joining) ------------------------ */

/// A document's `r_doc` sealed in software to a joining device's one-time join KEM key,
/// until that device turns it into its own hardware [`DeviceSlot`] on first open
/// (CORE.md §5.3, §6.4):
///
/// ```text
/// pending = header(0x0105) ‖ doc_id (32) ‖ device_id (32) ‖ manifest_hash (64)
///           ‖ seal_to(join KEM key, 0x0105, [doc_id, device_id, manifest_hash], r_doc)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSlot {
    /// The document.
    pub doc_id: [u8; 32],
    /// The joining device.
    pub device_id: [u8; 32],
    /// The document's manifest hash.
    pub manifest_hash: [u8; 64],
    sealed: Vec<u8>,
}

impl PendingSlot {
    pub(crate) fn seal(
        to: &KemPublicKey,
        doc_id: [u8; 32],
        device_id: [u8; 32],
        manifest_hash: [u8; 64],
        r_doc: &Secret32,
    ) -> Result<Self> {
        let sealed = humid_pq2::seal_to(
            to,
            ObjectType::PENDING_SLOT,
            &[&doc_id, &device_id, &manifest_hash],
            r_doc.expose(),
        )?;
        Ok(Self {
            doc_id,
            device_id,
            manifest_hash,
            sealed,
        })
    }

    pub(crate) fn open(&self, join_kem: &KemSecretKey) -> Result<Secret32> {
        let pt = humid_pq2::open_sealed(
            join_kem,
            ObjectType::PENDING_SLOT,
            &[&self.doc_id, &self.device_id, &self.manifest_hash],
            &self.sealed,
        )
        .map_err(|_| CoreError::WrongDocument)?;
        Secret32::from_slice(&pt).map_err(|_| CoreError::WrongDocument)
    }

    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = header(ObjectType::PENDING_SLOT).to_vec();
        v.extend_from_slice(&self.doc_id);
        v.extend_from_slice(&self.device_id);
        v.extend_from_slice(&self.manifest_hash);
        v.extend_from_slice(&self.sealed);
        v
    }

    /// Decode.
    ///
    /// # Errors
    /// [`CoreError::Format`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::PENDING_SLOT)?;
        let doc_id = r.array()?;
        let device_id = r.array()?;
        let manifest_hash = r.array()?;
        let sealed = r.take(humid_pq2::SEALED_OVERHEAD + 32)?.to_vec();
        r.finish()?;
        if sealed[..HEADER_LEN] != header(ObjectType::PENDING_SLOT) {
            return Err(CoreError::Format);
        }
        Ok(Self {
            doc_id,
            device_id,
            manifest_hash,
            sealed,
        })
    }
}

/// Either kind of slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnySlot {
    /// Hardware-bound.
    Device(DeviceSlot),
    /// Software-sealed to a joining device; adopted on first open.
    Pending(PendingSlot),
}

impl AnySlot {
    /// Decode a slot of either kind.
    ///
    /// # Errors
    /// [`CoreError::Format`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() >= HEADER_LEN && bytes[..HEADER_LEN] == header(ObjectType::PENDING_SLOT) {
            Ok(Self::Pending(PendingSlot::decode(bytes)?))
        } else {
            Ok(Self::Device(DeviceSlot::decode(bytes)?))
        }
    }

    pub(crate) fn ids(&self) -> ([u8; 32], [u8; 32], [u8; 64]) {
        match self {
            AnySlot::Device(s) => (s.doc_id, s.device_id, s.manifest_hash),
            AnySlot::Pending(s) => (s.doc_id, s.device_id, s.manifest_hash),
        }
    }
}

/* ----------------------------- share requests ----------------------------- */

/// What the phone asks the key-share service for, inside a live-checked request
/// (CORE.md §6.3). The service seals the share to `one_time` with
/// `binding = H("HUMID-PQ2 share-request", [encoding])`.
///
/// ```text
/// request = header(0x0012) ‖ account_id (32) ‖ doc_id (32) ‖ manifest_hash (64) ‖ one_time (1613)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRequest {
    /// The account.
    pub account_id: [u8; 32],
    /// The document.
    pub doc_id: [u8; 32],
    /// Its manifest hash.
    pub manifest_hash: [u8; 64],
    /// The one-time hybrid KEM key the share must be sealed to.
    pub one_time: KemPublicKey,
}

impl ShareRequest {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = header(ObjectType::SHARE_REQUEST).to_vec();
        v.extend_from_slice(&self.account_id);
        v.extend_from_slice(&self.doc_id);
        v.extend_from_slice(&self.manifest_hash);
        v.extend_from_slice(self.one_time.to_bytes());
        v
    }

    /// Decode.
    ///
    /// # Errors
    /// [`CoreError::Format`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::SHARE_REQUEST)?;
        let account_id = r.array()?;
        let doc_id = r.array()?;
        let manifest_hash = r.array()?;
        let one_time = KemPublicKey::from_bytes(r.take(humid_pq2::KEM_PUBLIC_KEY_LEN)?)?;
        r.finish()?;
        Ok(Self {
            account_id,
            doc_id,
            manifest_hash,
            one_time,
        })
    }

    /// The binding the release is sealed under.
    ///
    /// # Errors
    /// Never in practice.
    pub fn binding(&self) -> Result<[u8; 64]> {
        Ok(labelled_hash("HUMID-PQ2 share-request", &[&self.encode()])?)
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    struct Fx {
        acct_kem: KemSecretKey,
        acct_dsa: MlDsaSigningKey,
    }

    fn fx() -> Fx {
        Fx {
            acct_kem: KemSecretKey::generate().unwrap(),
            acct_dsa: MlDsaSigningKey::generate().unwrap(),
        }
    }

    fn seal(f: &Fx, data: &[u8], chunk: u32) -> (PreparedDoc, Vec<u8>) {
        let prep = PreparedDoc::new(
            f.acct_kem.public_key(),
            f.acct_dsa.verifying_key().key_id(),
            chunk,
        )
        .unwrap();
        let mut out = Vec::new();
        let meta = DocMeta {
            name: "passport.pdf".into(),
            media_type: "application/pdf".into(),
        };
        let (_, n) = seal_stream(&prep, &f.acct_dsa, &meta, &mut &data[..], &mut out).unwrap();
        assert_eq!(n, data.len() as u64);
        (prep, out)
    }

    fn open(f: &Fx, prep: &PreparedDoc, env: &[u8]) -> Result<(DocMeta, Vec<u8>)> {
        let mut r = env;
        let head = read_head(&mut r, f.acct_dsa.verifying_key())?;
        let ss = account_secret(&head, &f.acct_kem)?;
        let mut out = Vec::new();
        let (meta, n) = open_stream(&head, &ss, &prep.r_doc, &prep.share, &mut r, &mut out)?;
        assert_eq!(n, out.len() as u64);
        Ok((meta, out))
    }

    #[test]
    fn round_trip_at_chunk_boundaries() {
        let f = fx();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let (prep, env) = seal(&f, &data, 16);
            let (meta, back) = open(&f, &prep, &env).unwrap();
            assert_eq!(back, data, "len {len}");
            assert_eq!(meta.name, "passport.pdf");
        }
    }

    #[test]
    fn every_key_is_needed() {
        let f = fx();
        let (prep, env) = seal(&f, b"three keys", 16);
        let mut r = &env[..];
        let head = read_head(&mut r, f.acct_dsa.verifying_key()).unwrap();
        let ss = account_secret(&head, &f.acct_kem).unwrap();
        let other = Secret32::random().unwrap();
        for (a, b, c) in [
            (&other, &prep.r_doc, &prep.share),
            (&ss, &other, &prep.share),
            (&ss, &prep.r_doc, &other),
        ] {
            let mut rr = r;
            assert_eq!(
                open_stream(&head, a, b, c, &mut rr, &mut Vec::new()).unwrap_err(),
                CoreError::Tampered
            );
        }
        // the wrong account KEM key gives the wrong ss_acct
        let wrong = account_secret(&head, &KemSecretKey::generate().unwrap()).unwrap();
        let mut rr = r;
        assert!(
            open_stream(
                &head,
                &wrong,
                &prep.r_doc,
                &prep.share,
                &mut rr,
                &mut Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_signer_refused_before_decrypting() {
        let f = fx();
        let (_, env) = seal(&f, b"x", 16);
        let other = MlDsaSigningKey::generate().unwrap();
        let mut r = &env[..];
        assert!(matches!(
            read_head(&mut r, other.verifying_key()),
            Err(CoreError::WrongSigner)
        ));
        // a document made by someone with the account's public keys but not its signing key
        let forger = Fx {
            acct_kem: KemSecretKey::from_seed(f.acct_kem.seed()),
            acct_dsa: other,
        };
        let prep = PreparedDoc::new(
            f.acct_kem.public_key(),
            f.acct_dsa.verifying_key().key_id(),
            16,
        )
        .unwrap();
        let mut out = Vec::new();
        let meta = DocMeta {
            name: "a".into(),
            media_type: "b".into(),
        };
        seal_stream(&prep, &forger.acct_dsa, &meta, &mut &b"evil"[..], &mut out).unwrap();
        let mut r = &out[..];
        assert!(matches!(
            read_head(&mut r, f.acct_dsa.verifying_key()),
            Err(CoreError::WrongSigner)
        ));
    }

    #[test]
    fn truncation_extension_reordering_fail() {
        let f = fx();
        let data = vec![7u8; 16 * 3 + 5];
        let (prep, env) = seal(&f, &data, 16);
        let body = MANIFEST_LEN + MLDSA_SIG_LEN;
        // cut anywhere after the head
        for cut in [env.len() - 1, env.len() - 21, env.len() - 25, body + 200] {
            assert!(open(&f, &prep, &env[..cut]).is_err(), "cut {cut}");
        }
        // trailing junk
        let mut e = env.clone();
        e.push(0);
        assert_eq!(open(&f, &prep, &e).unwrap_err(), CoreError::Tampered);
        // drop the last chunk and mark the previous one last: fails (nonce has the flag)
        let chunk = 4 + 16 + TAG_LEN;
        let last_start = env.len() - (4 + 5 + TAG_LEN);
        let mut e = env[..last_start].to_vec();
        let prev = last_start - chunk;
        e[prev] |= 0x80;
        assert_eq!(open(&f, &prep, &e).unwrap_err(), CoreError::Tampered);
        // swap two full chunks
        let mut e = env.clone();
        let c0 = last_start - 3 * chunk;
        let (a, b) = (
            e[c0..c0 + chunk].to_vec(),
            e[c0 + chunk..c0 + 2 * chunk].to_vec(),
        );
        e[c0..c0 + chunk].copy_from_slice(&b);
        e[c0 + chunk..c0 + 2 * chunk].copy_from_slice(&a);
        assert_eq!(open(&f, &prep, &e).unwrap_err(), CoreError::Tampered);
    }

    #[test]
    fn chunks_cannot_move_between_documents() {
        let f = fx();
        let (p1, e1) = seal(&f, &[1u8; 40], 16);
        let (_, e2) = seal(&f, &[2u8; 40], 16);
        let body1 = e1.len() - (4 + 16 + TAG_LEN) * 2 - (4 + 8 + TAG_LEN);
        let body2 = e2.len() - (4 + 16 + TAG_LEN) * 2 - (4 + 8 + TAG_LEN);
        let mut mixed = e1[..body1].to_vec();
        mixed.extend_from_slice(&e2[body2..]);
        assert_eq!(open(&f, &p1, &mixed).unwrap_err(), CoreError::Tampered);
    }

    #[test]
    fn slots() {
        let hw = Secret32::random().unwrap();
        let r = Secret32::random().unwrap();
        let s = DeviceSlot::seal(&hw, [1; 32], [2; 32], [5u8; 64], b"in".to_vec(), &r).unwrap();
        let back = DeviceSlot::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert!(back.open(&hw).unwrap().ct_eq(&r));
        assert_eq!(
            back.open(&Secret32::random().unwrap()).err(),
            Some(CoreError::WrongDocument)
        );
        // any public field changed: refused
        for f in 0..3 {
            let mut m = s.clone();
            match f {
                0 => m.doc_id = [9; 32],
                1 => m.device_id = [9; 32],
                _ => m.manifest_hash = [9; 64],
            }
            assert!(m.open(&hw).is_err());
        }
    }

    #[test]
    fn decoders_never_panic() {
        for n in 0..300 {
            let junk = vec![0x5a; n];
            let _ = Manifest::decode(&junk);
            let _ = DeviceSlot::decode(&junk);
            let _ = DocMeta::decode(&junk);
            let mut r = &junk[..];
            let _ = read_head(&mut r, MlDsaSigningKey::generate().unwrap().verifying_key());
        }
    }
}
