//! The server end (HTP2.md §4, §5, §7): sans-io. The embedding unit feeds it the bytes of
//! one call and gets back frames to answer with plus the requests that are complete; it
//! dispatches those to its own router and hands each answer back to [`Server::respond`].
//!
//! Bounded everywhere (review #97): sessions in all and per client network (a hello never
//! evicts a session that has authenticated a record), remembered hello nonces and used
//! tickets (expired in time order, never by a full scan), requests dispatched per call,
//! requests being assembled per session and their bytes (per session, before sign-in, in
//! all), stalled assemblies, answers kept for pulls, and what one call makes the server
//! emit. Answers are sealed in the class that fits them; cover padding is capped.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use humid_pq2::encoding::Reader;
use humid_pq2::{
    KemSecretKey, ObjectType, Role, Secret32, open_at_rest, random_bytes, seal_at_rest, sha3_512,
};
use zeroize::Zeroizing;

use crate::frame::{self, Frame, Kind};
use crate::handshake::{self, HELLO_SKEW_MS, Hello, Keys, Reply, Resume};
use crate::msg::{Dir, Msg, RequestHead, ResponseHead, chunk_fits};
use crate::{CHUNK, Code, Result, SID_LEN, TH_LEN, Unit, label, n_chunks, types};

/// Limits and lifetimes.
#[derive(Clone, Debug)]
pub struct Config {
    /// The unit this endpoint is.
    pub unit: Unit,
    /// Live sessions at most. Past that a hello replaces a session that never authenticated
    /// a record, or is refused `busy`; it never evicts one that did.
    pub max_sessions: usize,
    /// Live sessions per client network (the embedding unit says which network a call came
    /// from, [`Server::receive_from`]).
    pub max_sessions_per_net: usize,
    /// A session ends this long after its last record (ms).
    pub idle_ms: u64,
    /// A chain of sessions (a full handshake and its resumptions) ends this long after the
    /// full handshake (ms).
    pub max_age_ms: u64,
    /// A resumption ticket lasts at most this long (ms).
    pub ticket_ms: u64,
    /// Requests being assembled at once in one session.
    pub max_in_flight: usize,
    /// Request bytes buffered across all sessions.
    pub max_buffered: usize,
    /// Request bytes one signed-in session may have buffered (one largest body).
    pub max_session_buffered: usize,
    /// Request bytes a session that hasn't signed in may have buffered.
    pub max_unauth_buffered: usize,
    /// Request bytes buffered for all sessions of one client network.
    pub max_net_buffered: usize,
    /// An assembly that gets no new chunk for this long is dropped (ms).
    pub assembly_idle_ms: u64,
    /// Answers a session keeps for pulls.
    pub keep_answers: usize,
    /// How long an answer is kept (ms).
    pub answer_ms: u64,
}

impl Config {
    /// The defaults HTP2.md §7 names, for `unit`.
    #[must_use]
    pub fn new(unit: Unit) -> Self {
        Self {
            unit,
            max_sessions: 50_000,
            max_sessions_per_net: 64,
            idle_ms: 15 * 60_000,
            max_age_ms: 8 * 3_600_000,
            ticket_ms: 8 * 3_600_000,
            max_in_flight: 4,
            max_buffered: 512 << 20,
            max_session_buffered: usize::try_from(crate::MAX_BODY).unwrap_or(usize::MAX),
            // anon's sessions never sign in, and a relay deposit is up to 4 MiB of ciphertext
            max_unauth_buffered: match unit {
                Unit::Core => 1 << 20,
                Unit::Anon => 8 << 20,
            },
            max_net_buffered: 2 * usize::try_from(crate::MAX_BODY).unwrap_or(usize::MAX),
            assembly_idle_ms: 2 * 60_000,
            keep_answers: 8,
            answer_ms: 60_000,
        }
    }
}

/// An assembly must complete within this long of its first chunk (ms), however it trickles.
pub const MAX_ASSEMBLY_MS: u64 = 10 * 60_000;
/// Requests one call may complete; the rest are refused `too_many_in_flight`.
pub const MAX_READY_PER_CALL: usize = 16;
/// Answer bytes (kept answers re-sent by pulls or repeated heads) one call may draw out;
/// past it the server answers `in_progress` and the client pulls again in its next call.
pub const ANSWER_BUDGET: usize = 8 << 20;
pub use crate::frame::COVER_MAX_CLASS;
/// Most answer bytes one session keeps for pulls (four full chunks).
pub const MAX_KEPT_BYTES: usize = 4 << 20;
/// Most remembered hello nonces and used tickets (each).
pub const MAX_REMEMBERED: usize = 200_000;
/// Hello nonces and used tickets remembered per client network at once.
pub const MAX_REMEMBERED_PER_NET: usize = 4096;
/// A new session that hasn't sent an authenticated record may be replaced (when the
/// endpoint is full) only after this long (ms): time enough to send its first request.
pub const UNPROVEN_GRACE_MS: u64 = 30_000;

/// Decides, from a request's head alone, whether a request may be assembled at all and how
/// big its body may be: `Ok(max body bytes)`, or the code to refuse it with. The second
/// argument says whether the session has signed in (the embedding unit says so with
/// [`Server::mark_signed_in`]). Runs before any of the body is buffered (review #97 M-2).
pub type Admission = Box<dyn Fn(&RequestHead, bool) -> Result<u64> + Send + Sync>;

/// A complete request, authenticated and assembled, for the unit to act on.
pub struct Ready {
    /// The session.
    pub sid: [u8; SID_LEN],
    /// The transcript sign-ins and live proofs name (the chain's full handshake).
    pub th: [u8; TH_LEN],
    /// The sequence number a live proof for this request names: `u64(generation) << 32 | rid`.
    /// The embedding unit hands it to the code that checks the proof.
    pub seq: u64,
    /// The head.
    pub head: RequestHead,
    /// The body (its hash matched the head).
    pub body: Zeroizing<Vec<u8>>,
}

/// What one call produced.
pub struct Received {
    /// Frames to send back now (handshake reply, ticket, acks, errors). Answers to `ready`
    /// follow them, from [`Server::respond`].
    pub frames: Vec<u8>,
    /// Requests to dispatch, in order (at most [`MAX_READY_PER_CALL`]).
    pub ready: Vec<Ready>,
    /// The session the call was in (zero for a refused hello).
    pub sid: [u8; SID_LEN],
}

struct Assembly {
    head: RequestHead,
    chunks: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
    first: u64,
    last: u64,
}

impl Drop for Assembly {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for c in self.chunks.values_mut() {
            c.zeroize();
        }
    }
}

struct Answer {
    /// SHA3-512 of the request's head: only the same request gets this answer again.
    req: [u8; 64],
    head: ResponseHead,
    body: Zeroizing<Vec<u8>>,
    class: u8,
    at: u64,
}

/// Request ids a session has used: everything at or below `floor`, and a bitmap of the
/// [`Rids::WINDOW`] ids above it (2 KiB, allocated on first use). The window moves only when
/// an id beyond it arrives, so an id reserved before a burst of up to `WINDOW` newer requests
/// (a long biometric prompt during a background sync) still works (review #97 L-5).
#[derive(Default)]
struct Rids {
    floor: u32,
    bits: Vec<u64>,
}

impl Rids {
    const WINDOW: u32 = 16_384;

    fn bit(rid: u32) -> (usize, u64) {
        let i = (rid % Self::WINDOW) as usize;
        (i / 64, 1u64 << (i % 64))
    }

    fn take(&mut self, rid: u32) -> bool {
        if rid == 0 || rid <= self.floor {
            return false;
        }
        if self.bits.is_empty() {
            self.bits = vec![0; (Self::WINDOW / 64) as usize];
        }
        let top = self.floor.saturating_add(Self::WINDOW);
        if rid > top {
            // slide: everything up to the new floor counts as used, its bits are recycled
            let new_floor = rid - Self::WINDOW;
            if new_floor - self.floor >= Self::WINDOW {
                self.bits.iter_mut().for_each(|w| *w = 0);
            } else {
                for r in self.floor + 1..=new_floor {
                    let (w, m) = Self::bit(r);
                    self.bits[w] &= !m;
                }
            }
            self.floor = new_floor;
        }
        let (w, m) = Self::bit(rid);
        if self.bits[w] & m != 0 {
            return false;
        }
        self.bits[w] |= m;
        true
    }
}

struct Sess {
    chain_th: [u8; TH_LEN],
    generation: u32,
    chain_start: u64,
    last_used: u64,
    net: String,
    /// It has authenticated at least one record (it is someone's working session).
    proven: bool,
    /// The embedding unit says a sign-in happened in it (or in an earlier session of its
    /// chain, as the ticket it resumed from says).
    signed_in: bool,
    /// The secret the next ticket carries (kept to re-mint the ticket on sign-in).
    resumption: Secret32,
    tx: humid_pq2::TransitSealer,
    rx: humid_pq2::TransitOpener,
    rids: Rids,
    assembling: BTreeMap<u32, Assembly>,
    /// Requests handed to the unit and not yet answered: the class to answer in, and their
    /// head's hash.
    dispatched: BTreeMap<u32, (u8, [u8; 64])>,
    answers: BTreeMap<u32, Answer>,
}

impl Sess {
    fn buffered(&self) -> usize {
        self.assembling.values().map(|a| a.bytes).sum()
    }
}

/// A KEM key waiting for its certificate signature.
pub struct PendingKey {
    key: KemSecretKey,
    not_before: u64,
    not_after: u64,
}

impl PendingKey {
    /// The bytes the unit's statement key must sign ([`crate::cert::Cert::to_be_signed`]).
    #[must_use]
    pub fn to_be_signed(&self, unit: Unit) -> Vec<u8> {
        crate::cert::Cert::to_be_signed(
            unit,
            self.not_before,
            self.not_after,
            self.key.public_key(),
        )
    }
}

struct Installed {
    key: KemSecretKey,
    kid: [u8; 32],
    cert: Vec<u8>,
    not_after: u64,
}

/// A table of single-use ids that expire, bounded in all and per network, expired in time
/// order (entries go in with a constant lifetime, so arrival order is expiry order).
#[derive(Default)]
struct Remembered {
    ids: HashMap<[u8; 32], String>,
    order: VecDeque<(u64, [u8; 32])>,
    per_net: HashMap<String, usize>,
}

impl Remembered {
    fn expire(&mut self, now: u64) {
        while let Some((exp, id)) = self.order.front().copied() {
            if exp > now {
                break;
            }
            self.order.pop_front();
            if let Some(net) = self.ids.remove(&id)
                && let Some(n) = self.per_net.get_mut(&net)
            {
                *n -= 1;
                if *n == 0 {
                    self.per_net.remove(&net);
                }
            }
        }
    }

    fn insert(&mut self, id: [u8; 32], net: &str, exp: u64, now: u64) -> Result<()> {
        self.expire(now);
        if self.ids.contains_key(&id) {
            return Err(Code::Replay);
        }
        if self.ids.len() >= MAX_REMEMBERED
            || (!net.is_empty()
                && self
                    .per_net
                    .get(net)
                    .is_some_and(|n| *n >= MAX_REMEMBERED_PER_NET))
        {
            return Err(Code::Busy);
        }
        self.ids.insert(id, net.to_string());
        *self.per_net.entry(net.to_string()).or_default() += 1;
        self.order.push_back((exp, id));
        Ok(())
    }

    fn len(&self) -> usize {
        self.ids.len()
    }
}

/// One unit's HTP/2 endpoint.
pub struct Server {
    cfg: Config,
    keys: Vec<Installed>,
    ticket_key: Secret32,
    sessions: HashMap<[u8; SID_LEN], Sess>,
    per_net: HashMap<String, usize>,
    /// Session ids by when they were last used (expiry and replacement without full scans).
    by_use: BTreeSet<(u64, [u8; SID_LEN])>,
    hello_nonces: Remembered,
    used_tickets: Remembered,
    admission: Option<Admission>,
    buffered: usize,
    /// Request bytes buffered per client network.
    net_buffered: HashMap<String, usize>,
    /// Sessions with an assembly in progress (each holds at least one full chunk, so there
    /// are at most `max_buffered / CHUNK` of them: sweeping them is cheap).
    assembling: BTreeSet<[u8; SID_LEN]>,
    kept: usize,
}

fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    random_bytes(&mut b).map_err(|_| Code::Internal)?;
    Ok(b)
}

const TICKET_PLAIN: usize = 1 + 1 + 4 + 8 + 8 + TH_LEN + 32;
/// The network a call is from when the embedding unit doesn't say.
const NO_NET: &str = "";

fn head_hash(h: &RequestHead) -> [u8; 64] {
    sha3_512(&Msg::Request(h.clone(), vec![]).encode())
}

/// The class a message is sealed in: the smallest that fits it, raised to the request's
/// cover class, which is capped at [`COVER_MAX_CLASS`].
fn cover(class: u8) -> u8 {
    class.min(COVER_MAX_CLASS)
}

impl Server {
    /// An endpoint with no KEM key yet (install one with [`Server::prepare_key`] and
    /// [`Server::install_key`] before hellos can succeed).
    ///
    /// # Errors
    /// The generator failed.
    pub fn new(cfg: Config) -> Result<Self> {
        Ok(Self {
            cfg,
            keys: vec![],
            ticket_key: Secret32::random().map_err(|_| Code::Internal)?,
            sessions: HashMap::new(),
            per_net: HashMap::new(),
            by_use: BTreeSet::new(),
            hello_nonces: Remembered::default(),
            used_tickets: Remembered::default(),
            admission: None,
            buffered: 0,
            net_buffered: HashMap::new(),
            assembling: BTreeSet::new(),
            kept: 0,
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Set the head-time admission check (the unit's route allow-list and body limits).
    /// Without one, every head is admitted up to [`crate::MAX_BODY`].
    pub fn set_admission(&mut self, a: Admission) {
        self.admission = Some(a);
    }

    /// The unit saw a sign-in (or a request its session token authorised) in session `sid`:
    /// its requests may now carry large bodies. The first time, this returns a record with a
    /// new resumption ticket that says so, for the client to keep instead of the one it has,
    /// so the next session of the chain starts signed in too (empty otherwise).
    ///
    /// # Errors
    /// `session_unknown`.
    pub fn mark_signed_in(&mut self, sid: &[u8; SID_LEN], now: u64) -> Result<Vec<u8>> {
        let s = self.sessions.get(sid).ok_or(Code::SessionUnknown)?;
        if s.signed_in {
            return Ok(vec![]);
        }
        let expires = (s.chain_start + self.cfg.max_age_ms).min(now + self.cfg.ticket_ms);
        let next = s.generation.checked_add(1).ok_or(Code::TicketUnknown)?;
        let ticket = self.seal_ticket(
            &s.chain_th,
            s.chain_start,
            next,
            true,
            &s.resumption,
            expires,
        )?;
        let unit = self.cfg.unit;
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        s.signed_in = true;
        frame::seal_record(
            &mut s.tx,
            unit,
            *sid,
            &Msg::Ticket {
                expires_at: expires,
                ticket,
            }
            .encode(),
            0,
        )
    }

    /// A fresh KEM key valid `[not_before, not_after]`, to be certified.
    ///
    /// # Errors
    /// The generator failed.
    pub fn prepare_key(not_before: u64, not_after: u64) -> Result<PendingKey> {
        Ok(PendingKey {
            key: KemSecretKey::generate().map_err(|_| Code::Internal)?,
            not_before,
            not_after,
        })
    }

    /// Install a certified key as the current one; the previous one stays (in-flight hellos),
    /// older ones are dropped. Returns the certificate.
    ///
    /// # Errors
    /// `bad_cert` for a signature that isn't an ML-DSA-87 encoding.
    pub fn install_key(&mut self, k: PendingKey, sig: &[u8]) -> Result<Vec<u8>> {
        let cert = crate::cert::Cert::assemble(
            self.cfg.unit,
            k.not_before,
            k.not_after,
            k.key.public_key(),
            sig,
        )?;
        let kid = k.key.public_key().key_id();
        self.keys.insert(
            0,
            Installed {
                key: k.key,
                kid,
                cert: cert.clone(),
                not_after: k.not_after,
            },
        );
        self.keys.truncate(2);
        Ok(cert)
    }

    /// The current certificate and when it stops being valid.
    #[must_use]
    pub fn current_cert(&self) -> Option<(&[u8], u64)> {
        self.keys.first().map(|k| (k.cert.as_slice(), k.not_after))
    }

    /// Live sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Remembered hello nonces (tests, metrics).
    #[must_use]
    pub fn remembered_hellos(&self) -> usize {
        self.hello_nonces.len()
    }

    /// Bytes buffered for requests being assembled.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// End a session at once (its keys are wiped).
    pub fn close(&mut self, sid: &[u8; SID_LEN]) {
        if let Some(s) = self.sessions.remove(sid) {
            self.unbuffer(&s.net, s.buffered());
            self.assembling.remove(sid);
            self.kept = self.kept.saturating_sub(kept_bytes(&s));
            self.by_use.remove(&(s.last_used, *sid));
            if let Some(n) = self.per_net.get_mut(&s.net) {
                *n -= 1;
                if *n == 0 {
                    self.per_net.remove(&s.net);
                }
            }
        }
    }

    fn unbuffer(&mut self, net: &str, n: usize) {
        self.buffered = self.buffered.saturating_sub(n);
        if let Some(b) = self.net_buffered.get_mut(net) {
            *b = b.saturating_sub(n);
            if *b == 0 {
                self.net_buffered.remove(net);
            }
        }
    }

    fn rebuffer(&mut self, net: &str, n: usize) {
        self.buffered += n;
        *self.net_buffered.entry(net.to_string()).or_default() += n;
    }

    /// Answer bytes kept for pulls, across all sessions.
    #[must_use]
    pub fn kept(&self) -> usize {
        self.kept
    }

    fn touch(&mut self, sid: &[u8; SID_LEN], now: u64) {
        if let Some(s) = self.sessions.get_mut(sid)
            && s.last_used != now
        {
            self.by_use.remove(&(s.last_used, *sid));
            s.last_used = now;
            self.by_use.insert((now, *sid));
        }
    }

    /// Drop idle sessions (oldest first, stopping at the first live one), sessions past their
    /// chain's age as they are met, and expired nonces and tickets.
    pub fn tick(&mut self, now: u64) {
        let idle = self.cfg.idle_ms;
        while let Some(&(used, sid)) = self.by_use.first() {
            if now <= used.saturating_add(idle) {
                break;
            }
            self.close(&sid);
        }
        let busy: Vec<[u8; SID_LEN]> = self.assembling.iter().copied().collect();
        for sid in busy {
            self.drop_stalled(&sid, now);
        }
        self.hello_nonces.expire(now);
        self.used_tickets.expire(now);
    }

    /// Take the bytes of one call, from an unknown network.
    #[must_use]
    pub fn receive(&mut self, call: &[u8], now: u64) -> Received {
        self.receive_from(call, NO_NET, now)
    }

    /// Take the bytes of one call that came from client network `net` (front's report; used
    /// only for per-network caps on sessions and remembered hellos).
    #[must_use]
    pub fn receive_from(&mut self, call: &[u8], net: &str, now: u64) -> Received {
        let unit = self.cfg.unit;
        let refuse = |sid: [u8; SID_LEN], c: Code| Received {
            frames: frame::error(unit, sid, c),
            ready: vec![],
            sid,
        };
        let frames = match frame::split(call) {
            Ok(f) => f,
            Err(c) => return refuse([0; SID_LEN], c),
        };
        if frames.iter().any(|f| f.header.unit != unit) {
            return refuse([0; SID_LEN], Code::UnitUnknown);
        }
        let first = frames[0];
        match first.header.kind {
            Kind::Hello | Kind::Resume if frames.len() == 1 => {
                self.tick(now);
                match self.handshake(&first, net, now) {
                    Ok((sid, out)) => Received {
                        frames: out,
                        ready: vec![],
                        sid,
                    },
                    Err(c) => refuse([0; SID_LEN], c),
                }
            }
            Kind::Record
                if frames
                    .iter()
                    .all(|f| f.header.kind == Kind::Record && f.header.sid == first.header.sid) =>
            {
                self.records(&frames, now)
            }
            _ => refuse([0; SID_LEN], Code::BadFrame),
        }
    }

    /// Room for one more session from `net`: refuse past the network's cap; past the global
    /// cap, replace the least recently used session that never authenticated a record and
    /// has had [`UNPROVEN_GRACE_MS`] to do so (a hello that went nowhere), or refuse `busy`.
    /// A session in use, or one just made, is never evicted (review #97 M-3).
    fn admit_session(&mut self, net: &str, now: u64) -> Result<()> {
        if !net.is_empty()
            && self
                .per_net
                .get(net)
                .is_some_and(|n| *n >= self.cfg.max_sessions_per_net)
        {
            return Err(Code::Busy);
        }
        if self.sessions.len() < self.cfg.max_sessions {
            return Ok(());
        }
        let idle = self
            .by_use
            .iter()
            .take_while(|(used, _)| now > used.saturating_add(UNPROVEN_GRACE_MS))
            .take(1024)
            .find(|(_, sid)| self.sessions.get(sid).is_some_and(|s| !s.proven))
            .map(|(_, sid)| *sid);
        match idle {
            Some(sid) => {
                self.close(&sid);
                Ok(())
            }
            None => Err(Code::Busy),
        }
    }

    fn handshake(
        &mut self,
        f: &Frame<'_>,
        net: &str,
        now: u64,
    ) -> Result<([u8; SID_LEN], Vec<u8>)> {
        let unit = self.cfg.unit;
        let body = f.clear_body()?;
        self.admit_session(net, now)?;
        let sid = rand::<SID_LEN>()?;
        let nonce_s = rand::<32>()?;
        let (keys, reply, chain) = match f.header.kind {
            Kind::Hello => {
                let h = Hello::decode(body)?;
                check_time(h.time_c, now)?;
                let k = self
                    .keys
                    .iter()
                    .find(|k| k.kid == h.kid)
                    .ok_or(Code::KeyUnknown)?;
                if now > k.not_after {
                    return Err(Code::KeyUnknown);
                }
                let ct_s = handshake::kem_ct(&h.ct_s)?;
                let ek_c = handshake::kem_pk(&h.ek_c)?;
                self.hello_nonces.insert(
                    h.nonce_c,
                    net,
                    now + 2 * u64::try_from(HELLO_SKEW_MS).unwrap_or(0),
                    now,
                )?;
                let ss_s = k
                    .key
                    .decapsulate(&ct_s)
                    .map_err(|_| Code::HandshakeFailed)?;
                let (ct_c, ss_e) = ek_c.encapsulate().map_err(|_| Code::HandshakeFailed)?;
                let mut reply = Reply {
                    mode: 0,
                    generation: 0,
                    ct_c: ct_c.to_bytes().to_vec(),
                    nonce_s,
                    time_s: now,
                    confirm: [0; 32],
                };
                let th = handshake::transcript(unit, &h, &sid, &reply)?;
                let keys = handshake::schedule(
                    label::MASTER,
                    [&ss_s, &ss_e],
                    th,
                    unit,
                    &sid,
                    Role::Responder,
                )?;
                reply.confirm = keys.confirm;
                (keys, reply, (th, now, 0, false))
            }
            Kind::Resume => {
                let r = Resume::decode(body)?;
                check_time(r.time_c, now)?;
                let ek_c = handshake::kem_pk(&r.ek_c)?;
                let (chain_th, chain_start, generation, signed_in, res) =
                    self.open_ticket(&r.ticket, net, now)?;
                let (ct_c, ss_e) = ek_c.encapsulate().map_err(|_| Code::HandshakeFailed)?;
                let mut reply = Reply {
                    mode: 1,
                    generation,
                    ct_c: ct_c.to_bytes().to_vec(),
                    nonce_s,
                    time_s: now,
                    confirm: [0; 32],
                };
                let th = handshake::transcript_resume(unit, body, &sid, &reply)?;
                let keys = handshake::schedule(
                    label::RESUME_MASTER,
                    [&res, &ss_e],
                    th,
                    unit,
                    &sid,
                    Role::Responder,
                )?;
                reply.confirm = keys.confirm;
                (keys, reply, (chain_th, chain_start, generation, signed_in))
            }
            _ => return Err(Code::BadFrame),
        };
        let Keys {
            mut tx,
            rx,
            resumption,
            ..
        } = keys;
        let (chain_th, chain_start, generation, signed_in) = chain;
        let next_generation = generation.checked_add(1).ok_or(Code::TicketUnknown)?;
        let mut out = frame::clear(Kind::Reply, unit, sid, &reply.encode(), 0)?;
        let expires = (chain_start + self.cfg.max_age_ms).min(now + self.cfg.ticket_ms);
        let ticket = self.seal_ticket(
            &chain_th,
            chain_start,
            next_generation,
            signed_in,
            &resumption,
            expires,
        )?;
        out.extend_from_slice(&frame::seal_record(
            &mut tx,
            unit,
            sid,
            &Msg::Ticket {
                expires_at: expires,
                ticket,
            }
            .encode(),
            0,
        )?);
        *self.per_net.entry(net.to_string()).or_default() += 1;
        self.by_use.insert((now, sid));
        self.sessions.insert(
            sid,
            Sess {
                chain_th,
                generation,
                chain_start,
                last_used: now,
                net: net.to_string(),
                proven: false,
                signed_in,
                resumption,
                tx,
                rx,
                rids: Rids::default(),
                assembling: BTreeMap::new(),
                dispatched: BTreeMap::new(),
                answers: BTreeMap::new(),
            },
        );
        Ok((sid, out))
    }

    fn ticket_aad(&self) -> [u8; 1] {
        [self.cfg.unit.to_u8()]
    }

    fn seal_ticket(
        &self,
        chain_th: &[u8; TH_LEN],
        chain_start: u64,
        generation: u32,
        signed_in: bool,
        res: &Secret32,
        expires: u64,
    ) -> Result<Vec<u8>> {
        let mut pt = Zeroizing::new(Vec::with_capacity(TICKET_PLAIN));
        pt.push(self.cfg.unit.to_u8());
        pt.push(u8::from(signed_in));
        pt.extend_from_slice(&generation.to_be_bytes());
        pt.extend_from_slice(&chain_start.to_be_bytes());
        pt.extend_from_slice(&expires.to_be_bytes());
        pt.extend_from_slice(chain_th);
        pt.extend_from_slice(res.expose());
        seal_at_rest(
            &self.ticket_key,
            ObjectType(types::TICKET.0),
            &[&self.ticket_aad()],
            &pt,
        )
        .map_err(|_| Code::Internal)
    }

    fn open_ticket(
        &mut self,
        t: &[u8],
        net: &str,
        now: u64,
    ) -> Result<([u8; TH_LEN], u64, u32, bool, Secret32)> {
        let pt = open_at_rest(
            &self.ticket_key,
            ObjectType(types::TICKET.0),
            &[&self.ticket_aad()],
            t,
        )
        .map_err(|_| Code::TicketUnknown)?;
        let mut r = Reader::new(&pt);
        let bad = |_| Code::TicketUnknown;
        let unit = r.array::<1>().map_err(bad)?[0];
        let flags = r.array::<1>().map_err(bad)?[0];
        let generation = r.u32().map_err(bad)?;
        let start = r.u64().map_err(bad)?;
        let expires = r.u64().map_err(bad)?;
        let th: [u8; TH_LEN] = r.array().map_err(bad)?;
        let res =
            Secret32::from_slice(r.take(32).map_err(bad)?).map_err(|_| Code::TicketUnknown)?;
        r.finish().map_err(bad)?;
        if unit != self.cfg.unit.to_u8()
            || flags > 1
            || now > expires
            || now > start + self.cfg.max_age_ms
        {
            return Err(Code::TicketUnknown);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&sha3_512(t)[..32]);
        // tickets live at most ticket_ms: remember a used one that long, in arrival order
        let keep = now
            .saturating_add(self.cfg.ticket_ms.min(self.cfg.max_age_ms))
            .saturating_add(1);
        self.used_tickets.insert(id, net, keep, now).map_err(|c| {
            if c == Code::Replay {
                Code::TicketUnknown
            } else {
                c
            }
        })?;
        Ok((th, start, generation, flags == 1, res))
    }

    fn records(&mut self, frames: &[Frame<'_>], now: u64) -> Received {
        let unit = self.cfg.unit;
        let sid = frames[0].header.sid;
        let mut out = vec![];
        let mut ready = vec![];
        let live = self.sessions.get(&sid).is_some_and(|s| {
            now <= s.last_used + self.cfg.idle_ms && now <= s.chain_start + self.cfg.max_age_ms
        });
        if !live {
            self.close(&sid);
            return Received {
                frames: frame::error(unit, sid, Code::SessionUnknown),
                ready,
                sid,
            };
        }
        let mut msgs = vec![];
        let mut first_err = None;
        if let Some(s) = self.sessions.get_mut(&sid) {
            for f in frames {
                match frame::open_record(&mut s.rx, f) {
                    Ok(m) => {
                        s.proven = true;
                        msgs.push((f.header.class, m));
                    }
                    Err(c) => {
                        first_err.get_or_insert(c);
                    }
                }
            }
        }
        if !msgs.is_empty() {
            self.touch(&sid, now);
        }
        self.drop_stalled(&sid, now);
        if let Some(c) = first_err {
            // unauthenticated: a forged or replayed record says nothing about the session
            out.extend_from_slice(&frame::error(unit, sid, c));
        }
        let mut call = CallState::default();
        for (class, m) in msgs {
            let reply = match Msg::decode(&m, Dir::Up) {
                Ok(msg) => self.on_msg(&sid, class, msg, &mut ready, &mut call, now),
                Err(c) => vec![(Msg::Error { rid: 0, code: c }, cover(class))],
            };
            for (r, c) in reply {
                if let Ok(b) = self.seal(&sid, &r.encode(), c) {
                    out.extend_from_slice(&b);
                }
            }
        }
        // acknowledge every request still being assembled that this call added to
        let acks: Vec<(Msg, u8)> = self.sessions.get(&sid).map_or(vec![], |s| {
            call.touched
                .iter()
                .filter_map(|(rid, class)| {
                    s.assembling.get(rid).map(|a| {
                        (
                            Msg::Ack {
                                rid: *rid,
                                next: first_missing(a),
                            },
                            *class,
                        )
                    })
                })
                .collect()
        });
        for (a, c) in acks {
            if let Ok(b) = self.seal(&sid, &a.encode(), c) {
                out.extend_from_slice(&b);
            }
        }
        Received {
            frames: out,
            ready,
            sid,
        }
    }

    /// Drop assemblies of `sid` that got no chunk for `assembly_idle_ms`, or that began more
    /// than [`MAX_ASSEMBLY_MS`] ago.
    fn drop_stalled(&mut self, sid: &[u8; SID_LEN], now: u64) {
        let idle = self.cfg.assembly_idle_ms;
        let mut freed = 0;
        let mut net = String::new();
        let mut empty = true;
        if let Some(s) = self.sessions.get_mut(sid) {
            let stale: Vec<u32> = s
                .assembling
                .iter()
                .filter(|(_, a)| {
                    now > a.last.saturating_add(idle)
                        || now > a.first.saturating_add(MAX_ASSEMBLY_MS)
                })
                .map(|(r, _)| *r)
                .collect();
            for r in stale {
                if let Some(a) = s.assembling.remove(&r) {
                    freed += a.bytes;
                    s.dispatched.remove(&r);
                }
            }
            net.clone_from(&s.net);
            empty = s.assembling.is_empty();
        }
        self.unbuffer(&net, freed);
        if empty {
            self.assembling.remove(sid);
        }
    }

    fn seal(&mut self, sid: &[u8; SID_LEN], msg: &[u8], class: u8) -> Result<Vec<u8>> {
        let unit = self.cfg.unit;
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        frame::seal_record(&mut s.tx, unit, *sid, msg, class)
    }

    /// May `extra` more bytes be buffered for session `s` (signed in or not)?
    fn room(&self, s: &Sess, extra: usize) -> bool {
        let cap = if s.signed_in {
            self.cfg.max_session_buffered
        } else {
            self.cfg.max_unauth_buffered
        };
        let net = self.net_buffered.get(&s.net).copied().unwrap_or(0);
        self.buffered + extra <= self.cfg.max_buffered
            && s.buffered() + extra <= cap
            && (s.net.is_empty() || net + extra <= self.cfg.max_net_buffered)
    }

    /// A kept answer, re-sent at most once per call and within the call's budget.
    fn replay_answer(
        call: &mut CallState,
        s: &Sess,
        rid: u32,
        from: u32,
    ) -> Option<Vec<(Msg, u8)>> {
        let a = s.answers.get(&rid)?;
        if !call.replayed.insert(rid) {
            return Some(vec![]); // pulled twice in one call: once is enough
        }
        let size = a
            .body
            .len()
            .saturating_sub(from as usize * CHUNK)
            .max(frame::CLASSES[usize::from(a.class)]);
        if call.budget < size {
            return Some(vec![(
                Msg::Error {
                    rid,
                    code: Code::InProgress,
                },
                cover(a.class),
            )]);
        }
        call.budget -= size;
        Some(
            answer_msgs(&a.head, &a.body, from)
                .into_iter()
                .map(|m| (m, a.class))
                .collect(),
        )
    }

    fn on_msg(
        &mut self,
        sid: &[u8; SID_LEN],
        class: u8,
        m: Msg,
        ready: &mut Vec<Ready>,
        call: &mut CallState,
        now: u64,
    ) -> Vec<(Msg, u8)> {
        let max_in_flight = self.cfg.max_in_flight;
        let answer_ms = self.cfg.answer_ms;
        let cls = cover(class);
        let err = |rid, code| vec![(Msg::Error { rid, code }, cls)];
        if !self.sessions.contains_key(sid) {
            return vec![];
        }
        self.expire_answers(sid, now, answer_ms);
        match m {
            Msg::Request(head, c0) => {
                let rid = head.rid;
                let hh = head_hash(&head);
                let Some(s) = self.sessions.get(sid) else {
                    return vec![];
                };
                // a head sent again after a cut call: the first copy stands, nothing runs twice
                if let Some(a) = s.assembling.get(&rid) {
                    if a.head == head {
                        call.touched.insert(rid, cls);
                        return vec![];
                    }
                    return err(rid, Code::RidReused);
                }
                if let Some(a) = s.answers.get(&rid) {
                    if !humid_pq2::ct_eq(&a.req, &hh) {
                        return err(rid, Code::RidReused);
                    }
                    return Self::replay_answer(call, s, rid, 0).unwrap_or_default();
                }
                if let Some((_, h)) = s.dispatched.get(&rid) {
                    if !humid_pq2::ct_eq(h, &hh) {
                        return err(rid, Code::RidReused);
                    }
                    return err(rid, Code::InProgress);
                }
                let signed_in = s.signed_in;
                let Some(sm) = self.sessions.get_mut(sid) else {
                    return vec![];
                };
                if !sm.rids.take(rid) {
                    return err(rid, Code::RidReused);
                }
                let Some(s) = self.sessions.get(sid) else {
                    return vec![];
                };
                if ready.len() >= MAX_READY_PER_CALL {
                    return err(rid, Code::TooManyInFlight);
                }
                let limit = match &self.admission {
                    Some(a) => match a(&head, signed_in) {
                        Ok(l) => l,
                        Err(c) => return err(rid, c),
                    },
                    None => crate::MAX_BODY,
                };
                if head.body_len > limit {
                    return err(rid, Code::TooLarge);
                }
                if s.assembling.len() >= max_in_flight {
                    return err(rid, Code::TooManyInFlight);
                }
                if !self.room(s, c0.len()) {
                    return err(rid, Code::Busy);
                }
                let net = s.net.clone();
                self.rebuffer(&net, c0.len());
                let Some(s) = self.sessions.get_mut(sid) else {
                    return vec![];
                };
                let mut a = Assembly {
                    bytes: c0.len(),
                    head,
                    chunks: BTreeMap::new(),
                    first: now,
                    last: now,
                };
                a.chunks.insert(0, c0);
                s.assembling.insert(rid, a);
                s.dispatched.insert(rid, (cls, hh));
                call.touched.insert(rid, cls);
                self.assembling.insert(*sid);
                self.finish_assembly(sid, rid, ready)
            }
            Msg::Body { rid, index, data } => {
                let Some(s) = self.sessions.get(sid) else {
                    return vec![];
                };
                let Some(a) = s.assembling.get(&rid) else {
                    return err(rid, Code::RidUnknown);
                };
                if !chunk_fits(a.head.body_len, index, &data) {
                    return err(rid, Code::BadFrame);
                }
                let acls = s.dispatched.get(&rid).map_or(cls, |d| d.0);
                call.touched.insert(rid, acls);
                if a.chunks.contains_key(&index) {
                    return vec![]; // a resent chunk: the first copy stands
                }
                if !self.room(s, data.len()) {
                    return vec![(
                        Msg::Error {
                            rid,
                            code: Code::Busy,
                        },
                        acls,
                    )];
                }
                let net = s.net.clone();
                self.rebuffer(&net, data.len());
                let Some(s) = self.sessions.get_mut(sid) else {
                    return vec![];
                };
                let Some(a) = s.assembling.get_mut(&rid) else {
                    return vec![];
                };
                a.bytes += data.len();
                a.last = now;
                a.chunks.insert(index, data);
                self.finish_assembly(sid, rid, ready)
            }
            Msg::Pull { rid, from } => {
                let Some(s) = self.sessions.get(sid) else {
                    return vec![];
                };
                if let Some(a) = s.assembling.get(&rid) {
                    let acls = s.dispatched.get(&rid).map_or(cls, |d| d.0);
                    return vec![(
                        Msg::Ack {
                            rid,
                            next: first_missing(a),
                        },
                        acls,
                    )];
                }
                if let Some(r) = Self::replay_answer(call, s, rid, from) {
                    return r;
                }
                if s.dispatched.contains_key(&rid) {
                    return err(rid, Code::InProgress);
                }
                err(rid, Code::RidUnknown)
            }
            _ => err(0, Code::BadFrame),
        }
    }

    fn expire_answers(&mut self, sid: &[u8; SID_LEN], now: u64, answer_ms: u64) {
        if let Some(s) = self.sessions.get_mut(sid) {
            let before = kept_bytes(s);
            s.answers
                .retain(|_, a| now <= a.at.saturating_add(answer_ms));
            self.kept = self.kept.saturating_sub(before - kept_bytes(s));
        }
    }

    /// If request `rid` of `sid` has all its chunks: release its bytes and hand it on.
    fn finish_assembly(
        &mut self,
        sid: &[u8; SID_LEN],
        rid: u32,
        ready: &mut Vec<Ready>,
    ) -> Vec<(Msg, u8)> {
        let Some(s) = self.sessions.get_mut(sid) else {
            return vec![];
        };
        let (out, freed) = Self::complete(s, rid, ready, sid);
        let net = s.net.clone();
        let empty = s.assembling.is_empty();
        self.unbuffer(&net, freed);
        if empty {
            self.assembling.remove(sid);
        }
        out
    }

    fn complete(
        s: &mut Sess,
        rid: u32,
        ready: &mut Vec<Ready>,
        sid: &[u8; SID_LEN],
    ) -> (Vec<(Msg, u8)>, usize) {
        let done = s
            .assembling
            .get(&rid)
            .is_some_and(|a| a.chunks.len() == n_chunks(a.head.body_len) as usize);
        if !done {
            return (vec![], 0);
        }
        let Some(mut a) = s.assembling.remove(&rid) else {
            return (vec![], 0);
        };
        let freed = a.bytes;
        let mut body = Zeroizing::new(Vec::with_capacity(a.bytes));
        for c in a.chunks.values() {
            body.extend_from_slice(c);
        }
        let head = std::mem::replace(
            &mut a.head,
            RequestHead {
                rid: 0,
                method: crate::msg::Method::Get,
                enc: crate::msg::Encoding::Raw,
                headers: vec![],
                path: String::new(),
                body_len: 0,
                body_hash: [0; 64],
            },
        );
        let cls = s.dispatched.get(&rid).map_or(0, |d| d.0);
        let seq = (u64::from(s.generation) << 32) | u64::from(rid);
        if !humid_pq2::ct_eq(&sha3_512(&body), &head.body_hash) {
            s.dispatched.remove(&rid);
            return (
                vec![(
                    Msg::Error {
                        rid,
                        code: Code::BodyMismatch,
                    },
                    cls,
                )],
                freed,
            );
        }
        if let Err(code) = check_proof(&head, &body, &s.chain_th, seq) {
            s.dispatched.remove(&rid);
            return (vec![(Msg::Error { rid, code }, cls)], freed);
        }
        ready.push(Ready {
            sid: *sid,
            th: s.chain_th,
            seq,
            head,
            body,
        });
        (vec![], freed)
    }

    /// The unit's answer to request `rid`: response frames (head and chunks), each in the
    /// class that fits it, raised to the request's cover class (capped at
    /// [`COVER_MAX_CLASS`]). The answer is kept for pulls.
    ///
    /// # Errors
    /// `session_unknown` if the session ended meanwhile; `too_large` over the response cap.
    pub fn respond(
        &mut self,
        sid: &[u8; SID_LEN],
        rid: u32,
        status: u16,
        ctype: u8,
        body: &[u8],
        now: u64,
    ) -> Result<Vec<u8>> {
        if body.len() as u64 > crate::MAX_RESPONSE {
            return Err(Code::TooLarge);
        }
        let keep = self.cfg.keep_answers;
        let max_kept = self.cfg.max_buffered / 4;
        let total = self.kept;
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        let before = kept_bytes(s);
        let (class, req) = s.dispatched.remove(&rid).unwrap_or((0, [0; 64]));
        let head = ResponseHead {
            rid,
            status,
            ctype,
            body_len: body.len() as u64,
            body_hash: sha3_512(body),
        };
        let msgs = answer_msgs(&head, body, 0);
        // keep the answer for pulls, unless it would push this session's kept answers past
        // MAX_KEPT_BYTES (a large one is then pulled by repeating the request's own
        // idempotent route, e.g. a chunk under its download ticket)
        if before + body.len() <= MAX_KEPT_BYTES && total + body.len() <= max_kept {
            s.answers.insert(
                rid,
                Answer {
                    req,
                    head,
                    body: Zeroizing::new(body.to_vec()),
                    class,
                    at: now,
                },
            );
        }
        while s.answers.len() > keep {
            s.answers.pop_first();
        }
        let after = kept_bytes(s);
        let unit = self.cfg.unit;
        let mut out = vec![];
        let mut sealed = Ok(());
        for m in msgs {
            match frame::seal_record(&mut s.tx, unit, *sid, &m.encode(), class) {
                Ok(b) => out.extend_from_slice(&b),
                Err(c) => {
                    sealed = Err(c);
                    break;
                }
            }
        }
        self.kept = (self.kept + after).saturating_sub(before);
        sealed.map(|()| out)
    }

    /// Refuse request `rid` with an authenticated error (the unit was unreachable, say), in
    /// the request's class.
    ///
    /// # Errors
    /// `session_unknown`.
    pub fn refuse(&mut self, sid: &[u8; SID_LEN], rid: u32, code: Code) -> Result<Vec<u8>> {
        let unit = self.cfg.unit;
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        let class = s.dispatched.remove(&rid).map_or(0, |d| d.0);
        frame::seal_record(
            &mut s.tx,
            unit,
            *sid,
            &Msg::Error { rid, code }.encode(),
            class,
        )
    }

    /// Seal arbitrary message bytes as a record of session `sid` (fuzzing the client's
    /// handling of what a genuine server could send).
    ///
    /// # Errors
    /// `session_unknown`, `too_large`.
    #[cfg(feature = "fuzz-hooks")]
    pub fn seal_raw(&mut self, sid: &[u8; SID_LEN], msg: &[u8]) -> Result<Vec<u8>> {
        self.seal(sid, msg, 0)
    }

    /// Whether `sid` names a live session (for tests and metrics).
    #[must_use]
    pub fn has_session(&self, sid: &[u8; SID_LEN]) -> bool {
        self.sessions.contains_key(sid)
    }

    /// How long a session may live, and its remaining idle time are policy; this keeps the
    /// answer cache's age in step with it.
    #[must_use]
    pub fn answer_ms(&self) -> u64 {
        self.cfg.answer_ms
    }
}

/// What one call has used so far.
struct CallState {
    /// Requests the call added to that are still being assembled, with their class.
    touched: BTreeMap<u32, u8>,
    /// Kept answers already re-sent in this call.
    replayed: BTreeSet<u32>,
    /// Answer bytes the call may still draw out of kept answers.
    budget: usize,
}

impl Default for CallState {
    fn default() -> Self {
        Self {
            touched: BTreeMap::new(),
            replayed: BTreeSet::new(),
            budget: ANSWER_BUDGET,
        }
    }
}

/// A typed body must parse; a proof made in this session must name this request's `seq`.
/// (A proof made in another session names another transcript, and core refuses it with
/// `session_changed`; the unit also checks `seq` against [`Ready::seq`] itself, so a proof
/// can't be routed around this check in another body shape.)
fn check_proof(head: &RequestHead, body: &[u8], th: &[u8; TH_LEN], seq: u64) -> Result<()> {
    if head.enc != crate::msg::Encoding::Parts {
        return Ok(());
    }
    let parts = crate::parts::decode(body)?;
    if let Some(p) = crate::parts::proof(&parts)
        && humid_pq2::ct_eq(&p.th, th)
        && p.seq != seq
    {
        return Err(Code::ProofMismatch);
    }
    Ok(())
}

fn kept_bytes(s: &Sess) -> usize {
    s.answers.values().map(|a| a.body.len()).sum()
}

fn check_time(t: u64, now: u64) -> Result<()> {
    let skew = u64::try_from(HELLO_SKEW_MS).unwrap_or(0);
    if t.abs_diff(now) > skew {
        return Err(Code::StaleHello);
    }
    Ok(())
}

fn first_missing(a: &Assembly) -> u32 {
    (0..n_chunks(a.head.body_len))
        .find(|i| !a.chunks.contains_key(i))
        .unwrap_or(0)
}

/// A response head with chunk 0, then the other chunks, from chunk `from` (a pull).
fn answer_msgs(head: &ResponseHead, body: &[u8], from: u32) -> Vec<Msg> {
    let n = n_chunks(head.body_len);
    let mut out = vec![];
    if from == 0 {
        out.push(Msg::Response(
            head.clone(),
            body[..body.len().min(CHUNK)].to_vec(),
        ));
    }
    for i in from.max(1)..n {
        let start = i as usize * CHUNK;
        out.push(Msg::Body {
            rid: head.rid,
            index: i,
            data: body[start..(start + CHUNK).min(body.len())].to_vec(),
        });
    }
    if from > 0 && from >= n {
        out.push(Msg::Error {
            rid: head.rid,
            code: Code::BadFrame,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Event, Handshake};
    use crate::msg::{Encoding, Method};
    use crate::parts::{self, Part, Proof};

    const NOW: u64 = 1_798_761_600_000;

    fn pair() -> (Server, crate::client::Session) {
        let st = humid_pq2::MlDsaSigningKey::generate().unwrap();
        let mut srv = Server::new(Config::new(Unit::Core)).unwrap();
        let pk = Server::prepare_key(NOW - 1, NOW + 1_000_000).unwrap();
        let sig = st
            .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
            .unwrap()
            .to_bytes();
        let cert = crate::cert::Cert::decode(&srv.install_key(pk, &sig).unwrap()).unwrap();
        let (hs, hello) = Handshake::full(Unit::Core, &cert, NOW).unwrap();
        let r = srv.receive(&hello, NOW);
        (srv, hs.finish(&r.frames).unwrap())
    }

    fn refused(s: &mut crate::client::Session, frames: &[u8]) -> Vec<Code> {
        s.receive(frames)
            .unwrap()
            .into_iter()
            .filter_map(|e| match e {
                Event::Refused { code, .. } => Some(code),
                _ => None,
            })
            .collect()
    }

    fn head(rid: u32, body: &[u8], enc: Encoding) -> RequestHead {
        RequestHead {
            rid,
            method: Method::Post,
            enc,
            headers: vec![],
            path: "/v1/objects".into(),
            body_len: body.len() as u64,
            body_hash: sha3_512(body),
        }
    }

    #[test]
    fn a_body_that_does_not_match_its_announced_hash_never_reaches_the_unit() {
        let (mut srv, mut s) = pair();
        let mut h = head(1, b"real", Encoding::Raw);
        h.body_hash = sha3_512(b"other");
        let call = s.raw(&Msg::Request(h, b"real".to_vec())).unwrap();
        let r = srv.receive(&call, NOW);
        assert!(r.ready.is_empty());
        assert_eq!(refused(&mut s, &r.frames), [Code::BodyMismatch]);
    }

    fn proof(th: [u8; TH_LEN], seq: u64) -> Proof {
        Proof {
            method: "POST".into(),
            path: "/v1/objects".into(),
            th,
            seq,
            device: [1; 32],
            nonce: [2; 32],
            at: NOW,
            mode: 0,
            device_sig: vec![3; 10],
            live_p256: vec![4; 10],
            live_mldsa: None,
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn a_proof_for_another_request_id_in_this_session_is_refused_before_the_unit() {
        let (mut srv, mut s) = pair();
        let th = s.th();
        // a proof made for request 1, carried by request 2
        let body = parts::encode(&[Part::Proof(Box::new(proof(th, s.proof_seq(1))))]);
        let call = s
            .raw(&Msg::Request(head(2, &body, Encoding::Parts), body.clone()))
            .unwrap();
        let r = srv.receive(&call, NOW);
        assert!(r.ready.is_empty());
        assert_eq!(refused(&mut s, &r.frames), [Code::ProofMismatch]);
        // the right one goes through, carrying its seq for the unit
        let body = parts::encode(&[Part::Proof(Box::new(proof(th, s.proof_seq(3))))]);
        let call = s
            .raw(&Msg::Request(head(3, &body, Encoding::Parts), body))
            .unwrap();
        let r = srv.receive(&call, NOW);
        assert_eq!(r.ready.len(), 1);
        assert_eq!(r.ready[0].seq, s.proof_seq(3));
        assert_eq!(r.ready[0].th, th);
        // a typed body that doesn't parse
        let call = s
            .raw(&Msg::Request(
                head(4, b"\x01\x09", Encoding::Parts),
                b"\x01\x09".to_vec(),
            ))
            .unwrap();
        let r = srv.receive(&call, NOW);
        assert_eq!(refused(&mut s, &r.frames), [Code::BadFrame]);
    }

    #[test]
    fn request_ids_are_single_use_and_only_grow_past_the_window() {
        let mut r = Rids::default();
        assert!(!r.take(0));
        // 10_000 is reserved (a long prompt) while 15_000 newer requests go by
        for i in (1..=25_000).filter(|i| *i != 10_000) {
            assert!(r.take(i));
        }
        assert!(!r.take(5), "old ids stay used after the window moves");
        assert!(!r.take(25_000));
        assert!(
            r.take(10_000),
            "a reserved id inside the window still works"
        );
        assert!(!r.take(10_000));
        assert!(r.take(60_000));
        assert!(!r.take(30_000), "below the floor once the window passed it");
    }

    #[test]
    fn kept_answers_are_bounded_and_released_with_the_session() {
        let (mut srv, mut s) = pair();
        let big = vec![7u8; 3 << 20];
        for _ in 0..3 {
            let (rid, call) = s
                .request(Method::Get, "/v1/x", Encoding::Raw, &[], b"")
                .unwrap();
            let r = srv.receive(&call, NOW);
            let sid = r.ready[0].sid;
            let out = srv.respond(&sid, rid, 200, 1, &big, NOW).unwrap();
            let _ = s.receive(&out).unwrap();
            assert!(srv.kept() <= MAX_KEPT_BYTES, "{}", srv.kept());
        }
        assert_eq!(
            srv.kept(),
            3 << 20,
            "the first is kept, the next two would pass the cap"
        );
        // a pull for an answer that wasn't kept: rid_unknown (the client repeats the request)
        let pull = s.pull(3, 0).unwrap();
        let r = srv.receive(&pull, NOW);
        assert_eq!(refused(&mut s, &r.frames), [Code::RidUnknown]);
        srv.close(&s.sid());
        assert_eq!(srv.kept(), 0);
    }

    #[test]
    fn server_messages_are_refused_from_a_client() {
        let (mut srv, mut s) = pair();
        let call = s.raw(&Msg::Ack { rid: 1, next: 1 }).unwrap();
        // an Ack decodes only travelling down: the server answers bad_frame, authenticated
        let r = srv.receive(&call, NOW);
        assert_eq!(refused(&mut s, &r.frames), [Code::BadFrame]);
    }
}
