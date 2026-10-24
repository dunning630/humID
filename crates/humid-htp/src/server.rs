//! The server end (HTP2.md §4, §5, §7): sans-io. The embedding unit feeds it the bytes of
//! one call and gets back frames to answer with plus the requests that are complete; it
//! dispatches those to its own router and hands each answer back to [`Server::respond`].
//!
//! Bounded everywhere: sessions, remembered hello nonces and used tickets, requests being
//! assembled per session, bytes buffered in all, answers kept for pulls.

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    /// Live sessions at most; past that the least recently used goes.
    pub max_sessions: usize,
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
            idle_ms: 15 * 60_000,
            max_age_ms: 8 * 3_600_000,
            ticket_ms: 8 * 3_600_000,
            max_in_flight: 4,
            max_buffered: 512 << 20,
            keep_answers: 8,
            answer_ms: 60_000,
        }
    }
}

/// A complete request, authenticated and assembled, for the unit to act on.
pub struct Ready {
    /// The session.
    pub sid: [u8; SID_LEN],
    /// The transcript sign-ins and live proofs name (the chain's full handshake).
    pub th: [u8; TH_LEN],
    /// The sequence number a live proof for this request names: `u64(generation) << 32 | rid`.
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
    /// Requests to dispatch, in order.
    pub ready: Vec<Ready>,
    /// The session the call was in (zero for a refused hello).
    pub sid: [u8; SID_LEN],
}

struct Assembly {
    head: RequestHead,
    chunks: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
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
    head: ResponseHead,
    body: Zeroizing<Vec<u8>>,
    class: u8,
    at: u64,
}

/// Request ids a session has used: everything at or below `floor`, and `seen` above it.
#[derive(Default)]
struct Rids {
    floor: u32,
    seen: BTreeSet<u32>,
}

impl Rids {
    const KEEP: usize = 1024;

    fn take(&mut self, rid: u32) -> bool {
        if rid == 0 || rid <= self.floor || !self.seen.insert(rid) {
            return false;
        }
        while self.seen.len() > Self::KEEP {
            if let Some(low) = self.seen.pop_first() {
                self.floor = low;
            }
        }
        true
    }
}

struct Sess {
    chain_th: [u8; TH_LEN],
    generation: u32,
    chain_start: u64,
    last_used: u64,
    tx: humid_pq2::TransitSealer,
    rx: humid_pq2::TransitOpener,
    rids: Rids,
    assembling: BTreeMap<u32, Assembly>,
    dispatched: BTreeMap<u32, u8>,
    answers: BTreeMap<u32, Answer>,
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

/// One unit's HTP/2 endpoint.
pub struct Server {
    cfg: Config,
    keys: Vec<Installed>,
    ticket_key: Secret32,
    sessions: HashMap<[u8; SID_LEN], Sess>,
    hello_nonces: HashMap<[u8; 32], u64>,
    used_tickets: HashMap<[u8; 32], u64>,
    buffered: usize,
}

fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    random_bytes(&mut b).map_err(|_| Code::Internal)?;
    Ok(b)
}

const TICKET_PLAIN: usize = 1 + 4 + 8 + 8 + TH_LEN + 32;
/// Most remembered hello nonces and used tickets (each).
pub const MAX_REMEMBERED: usize = 200_000;

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
            hello_nonces: HashMap::new(),
            used_tickets: HashMap::new(),
            buffered: 0,
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
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

    /// Bytes buffered for requests being assembled.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// End a session at once (its keys are wiped).
    pub fn close(&mut self, sid: &[u8; SID_LEN]) {
        if let Some(s) = self.sessions.remove(sid) {
            self.release(&s);
        }
    }

    fn release(&mut self, s: &Sess) {
        let b: usize = s.assembling.values().map(|a| a.bytes).sum();
        self.buffered = self.buffered.saturating_sub(b);
    }

    /// Drop expired sessions, hello nonces and used tickets.
    pub fn tick(&mut self, now: u64) {
        let (idle, age) = (self.cfg.idle_ms, self.cfg.max_age_ms);
        let dead: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| now > s.last_used + idle || now > s.chain_start + age)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.close(&k);
        }
        self.hello_nonces.retain(|_, exp| *exp > now);
        self.used_tickets.retain(|_, exp| *exp > now);
    }

    /// Take the bytes of one call.
    #[must_use]
    pub fn receive(&mut self, call: &[u8], now: u64) -> Received {
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
                match self.handshake(&first, now) {
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

    fn remember(map: &mut HashMap<[u8; 32], u64>, k: [u8; 32], exp: u64) -> Result<()> {
        if map.contains_key(&k) {
            return Err(Code::Replay);
        }
        if map.len() >= MAX_REMEMBERED {
            return Err(Code::Busy);
        }
        map.insert(k, exp);
        Ok(())
    }

    fn handshake(&mut self, f: &Frame<'_>, now: u64) -> Result<([u8; SID_LEN], Vec<u8>)> {
        let unit = self.cfg.unit;
        let body = f.clear_body()?;
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
                Self::remember(
                    &mut self.hello_nonces,
                    h.nonce_c,
                    now + 2 * u64::try_from(HELLO_SKEW_MS).unwrap_or(0),
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
                (keys, reply, (th, now, 0))
            }
            Kind::Resume => {
                let r = Resume::decode(body)?;
                check_time(r.time_c, now)?;
                let (chain_th, chain_start, generation, res) = self.open_ticket(&r.ticket, now)?;
                let ek_c = handshake::kem_pk(&r.ek_c)?;
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
                (keys, reply, (chain_th, chain_start, generation))
            }
            _ => return Err(Code::BadFrame),
        };
        let Keys {
            mut tx,
            rx,
            resumption,
            ..
        } = keys;
        let (chain_th, chain_start, generation) = chain;
        let next_generation = generation.checked_add(1).ok_or(Code::TicketUnknown)?;
        let mut out = frame::clear(Kind::Reply, unit, sid, &reply.encode(), 0)?;
        let expires = (chain_start + self.cfg.max_age_ms).min(now + self.cfg.ticket_ms);
        let ticket = self.seal_ticket(
            &chain_th,
            chain_start,
            next_generation,
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
        if self.sessions.len() >= self.cfg.max_sessions
            && let Some(lru) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last_used)
                .map(|(k, _)| *k)
        {
            self.close(&lru);
        }
        self.sessions.insert(
            sid,
            Sess {
                chain_th,
                generation,
                chain_start,
                last_used: now,
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
        res: &Secret32,
        expires: u64,
    ) -> Result<Vec<u8>> {
        let mut pt = Zeroizing::new(Vec::with_capacity(TICKET_PLAIN));
        pt.push(self.cfg.unit.to_u8());
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

    fn open_ticket(&mut self, t: &[u8], now: u64) -> Result<([u8; TH_LEN], u64, u32, Secret32)> {
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
        let generation = r.u32().map_err(bad)?;
        let start = r.u64().map_err(bad)?;
        let expires = r.u64().map_err(bad)?;
        let th: [u8; TH_LEN] = r.array().map_err(bad)?;
        let res =
            Secret32::from_slice(r.take(32).map_err(bad)?).map_err(|_| Code::TicketUnknown)?;
        r.finish().map_err(bad)?;
        if unit != self.cfg.unit.to_u8() || now > expires || now > start + self.cfg.max_age_ms {
            return Err(Code::TicketUnknown);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&sha3_512(t)[..32]);
        Self::remember(&mut self.used_tickets, id, expires + 1).map_err(|c| {
            if c == Code::Replay {
                Code::TicketUnknown
            } else {
                c
            }
        })?;
        Ok((th, start, generation, res))
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
                        s.last_used = now;
                        msgs.push((f.header.class, m));
                    }
                    Err(c) => {
                        first_err.get_or_insert(c);
                    }
                }
            }
        }
        if let Some(c) = first_err {
            // unauthenticated: a forged or replayed record says nothing about the session
            out.extend_from_slice(&frame::error(unit, sid, c));
        }
        let mut touched = BTreeSet::new();
        for (class, m) in msgs {
            let reply = match Msg::decode(&m, Dir::Up) {
                Ok(msg) => self.on_msg(&sid, class, msg, &mut ready, &mut touched, now),
                Err(c) => vec![(Msg::Error { rid: 0, code: c }, 0)],
            };
            for (r, c) in reply {
                if let Ok(b) = self.seal(&sid, &r.encode(), class_of(&r, c)) {
                    out.extend_from_slice(&b);
                }
            }
        }
        // acknowledge every request still being assembled that this call added to
        let acks: Vec<Msg> = self.sessions.get(&sid).map_or(vec![], |s| {
            touched
                .iter()
                .filter_map(|rid| {
                    s.assembling.get(rid).map(|a| Msg::Ack {
                        rid: *rid,
                        next: first_missing(a),
                    })
                })
                .collect()
        });
        for a in acks {
            if let Ok(b) = self.seal(&sid, &a.encode(), 0) {
                out.extend_from_slice(&b);
            }
        }
        Received {
            frames: out,
            ready,
            sid,
        }
    }

    fn seal(&mut self, sid: &[u8; SID_LEN], msg: &[u8], class: u8) -> Result<Vec<u8>> {
        let unit = self.cfg.unit;
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        frame::seal_record(&mut s.tx, unit, *sid, msg, class)
    }

    fn on_msg(
        &mut self,
        sid: &[u8; SID_LEN],
        class: u8,
        m: Msg,
        ready: &mut Vec<Ready>,
        touched: &mut BTreeSet<u32>,
        now: u64,
    ) -> Vec<(Msg, u8)> {
        let max_in_flight = self.cfg.max_in_flight;
        let answer_ms = self.cfg.answer_ms;
        let max_buffered = self.cfg.max_buffered;
        let Some(s) = self.sessions.get_mut(sid) else {
            return vec![];
        };
        let err = |rid, code| vec![(Msg::Error { rid, code }, 0)];
        match m {
            Msg::Request(head, c0) => {
                let rid = head.rid;
                // a head sent again after a cut call: the first copy stands, nothing runs twice
                if let Some(a) = s.assembling.get(&rid) {
                    if a.head == head {
                        touched.insert(rid);
                        return vec![];
                    }
                    return err(rid, Code::RidReused);
                }
                s.answers.retain(|_, a| now <= a.at + answer_ms);
                if let Some(a) = s.answers.get(&rid) {
                    let c = a.class;
                    return answer_msgs(&a.head, &a.body, 0)
                        .into_iter()
                        .map(|m| (m, c))
                        .collect();
                }
                if s.dispatched.contains_key(&rid) {
                    return err(rid, Code::InProgress);
                }
                if !s.rids.take(rid) {
                    return err(rid, Code::RidReused);
                }
                if s.assembling.len() >= max_in_flight {
                    return err(rid, Code::TooManyInFlight);
                }
                if self.buffered + c0.len() > max_buffered {
                    return err(rid, Code::Busy);
                }
                self.buffered += c0.len();
                let mut a = Assembly {
                    bytes: c0.len(),
                    head,
                    chunks: BTreeMap::new(),
                };
                a.chunks.insert(0, c0);
                s.assembling.insert(rid, a);
                s.dispatched.insert(rid, class);
                touched.insert(rid);
                Self::complete(s, rid, &mut self.buffered, ready, sid)
            }
            Msg::Body { rid, index, data } => {
                let Some(a) = s.assembling.get_mut(&rid) else {
                    return err(rid, Code::RidUnknown);
                };
                if !chunk_fits(a.head.body_len, index, &data) {
                    return err(rid, Code::BadFrame);
                }
                touched.insert(rid);
                if a.chunks.contains_key(&index) {
                    return vec![]; // a resent chunk: the first copy stands
                }
                if self.buffered + data.len() > max_buffered {
                    return err(rid, Code::Busy);
                }
                self.buffered += data.len();
                a.bytes += data.len();
                a.chunks.insert(index, data);
                Self::complete(s, rid, &mut self.buffered, ready, sid)
            }
            Msg::Pull { rid, from } => {
                if let Some(a) = s.assembling.get(&rid) {
                    return vec![(
                        Msg::Ack {
                            rid,
                            next: first_missing(a),
                        },
                        0,
                    )];
                }
                s.answers.retain(|_, a| now <= a.at + answer_ms);
                if let Some(a) = s.answers.get(&rid) {
                    let c = a.class;
                    return answer_msgs(&a.head, &a.body, from)
                        .into_iter()
                        .map(|m| (m, c))
                        .collect();
                }
                if s.dispatched.contains_key(&rid) {
                    return err(rid, Code::InProgress);
                }
                err(rid, Code::RidUnknown)
            }
            _ => err(0, Code::BadFrame),
        }
    }

    fn complete(
        s: &mut Sess,
        rid: u32,
        buffered: &mut usize,
        ready: &mut Vec<Ready>,
        sid: &[u8; SID_LEN],
    ) -> Vec<(Msg, u8)> {
        let done = s
            .assembling
            .get(&rid)
            .is_some_and(|a| a.chunks.len() == n_chunks(a.head.body_len) as usize);
        if !done {
            return vec![];
        }
        let Some(mut a) = s.assembling.remove(&rid) else {
            return vec![];
        };
        *buffered = buffered.saturating_sub(a.bytes);
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
        let seq = (u64::from(s.generation) << 32) | u64::from(rid);
        if !humid_pq2::ct_eq(&sha3_512(&body), &head.body_hash) {
            s.dispatched.remove(&rid);
            return vec![(
                Msg::Error {
                    rid,
                    code: Code::BodyMismatch,
                },
                0,
            )];
        }
        if let Err(code) = check_proof(&head, &body, &s.chain_th, seq) {
            s.dispatched.remove(&rid);
            return vec![(Msg::Error { rid, code }, 0)];
        }
        ready.push(Ready {
            sid: *sid,
            th: s.chain_th,
            seq,
            head,
            body,
        });
        vec![]
    }

    /// The unit's answer to request `rid`: response frames (head and chunks), padded to at
    /// least the class the request came in. The answer is kept for pulls.
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
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        let class = s.dispatched.remove(&rid).unwrap_or(0);
        let head = ResponseHead {
            rid,
            status,
            ctype,
            body_len: body.len() as u64,
            body_hash: sha3_512(body),
        };
        let msgs = answer_msgs(&head, body, 0);
        s.answers.insert(
            rid,
            Answer {
                head,
                body: Zeroizing::new(body.to_vec()),
                class,
                at: now,
            },
        );
        while s.answers.len() > keep {
            s.answers.pop_first();
        }
        let mut out = vec![];
        for m in msgs {
            out.extend_from_slice(&frame::seal_record(
                &mut s.tx,
                self.cfg.unit,
                *sid,
                &m.encode(),
                class_of(&m, class),
            )?);
        }
        Ok(out)
    }

    /// Refuse request `rid` with an authenticated error (the unit was unreachable, say).
    ///
    /// # Errors
    /// `session_unknown`.
    pub fn refuse(&mut self, sid: &[u8; SID_LEN], rid: u32, code: Code) -> Result<Vec<u8>> {
        let unit = self.cfg.unit;
        let s = self.sessions.get_mut(sid).ok_or(Code::SessionUnknown)?;
        let class = s.dispatched.remove(&rid).unwrap_or(0);
        frame::seal_record(
            &mut s.tx,
            unit,
            *sid,
            &Msg::Error { rid, code }.encode(),
            class,
        )
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

/// A typed body must parse; a proof made in this session must name this request's `seq`
/// (method, path, freshness, nonce and signatures are the unit's to check, and a proof made
/// in another session is the unit's to refuse with its own code).
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

fn class_of(m: &Msg, min: u8) -> u8 {
    match m {
        Msg::Response(..) | Msg::Body { .. } => min,
        _ => 0,
    }
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
        for i in 1..=2000 {
            assert!(r.take(i));
        }
        assert!(!r.take(5), "old ids stay used after the window moves");
        assert!(!r.take(2000));
        assert!(r.take(5000));
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
