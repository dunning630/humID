//! The client end (HTP2.md §4, §5, §8): sans-io. The phone's core builds calls with it and
//! feeds it what came back.
//!
//! ```text
//! let (hs, hello) = Handshake::full(Unit::Core, &cert, now)?;   // or Handshake::resume(ticket)
//! let reply = transport(hello);                                 // POST /htp/v2/call
//! let mut s = hs.finish(&reply)?;
//! let (rid, call) = s.request(Method::Post, "/v1/sync", Encoding::Raw, &[], &body)?;
//! let events = s.receive(&transport(call))?;                    // Event::Response(rid, …)
//! ```

use std::collections::BTreeMap;

use humid_pq2::{KemSecretKey, Role, Secret32, random_bytes, sha3_512};
use zeroize::Zeroizing;

use crate::cert::Cert;
use crate::frame::{self, Kind};
use crate::handshake::{self, Hello, Keys, NONCE_LEN, Reply, Resume};
use crate::msg::{Dir, Encoding, HeaderName, Method, Msg, RequestHead, chunk_fits};
use crate::{CHUNK, Code, MAX_BODY, Result, SID_LEN, TH_LEN, Unit, chunk_len, label, n_chunks};

/// A resumption ticket the server gave, kept by the phone until it expires or is used.
pub struct Ticket {
    /// The unit it resumes into.
    pub unit: Unit,
    /// Opaque ticket bytes.
    pub ticket: Vec<u8>,
    /// Server time it expires (ms).
    pub expires_at: u64,
    /// The resumption secret.
    pub secret: Secret32,
    /// The chain transcript (what sign-ins name; unchanged by resuming).
    pub chain_th: [u8; TH_LEN],
}

enum Pending {
    Full {
        hello: Hello,
        ss_s: Secret32,
    },
    Resume {
        body: Vec<u8>,
        res: Secret32,
        chain_th: [u8; TH_LEN],
    },
}

/// A handshake in flight.
pub struct Handshake {
    unit: Unit,
    eph: KemSecretKey,
    pending: Pending,
}

fn nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    random_bytes(&mut n).map_err(|_| Code::Internal)?;
    Ok(n)
}

impl Handshake {
    /// A full handshake to `cert`'s key (already verified against the pinned root with
    /// [`crate::cert::Bundle::verified`]). Returns the call to send.
    ///
    /// # Errors
    /// `bad_cert` for a certificate of another unit or outside its dates (± the clock slack,
    /// [`crate::cert::CERT_SKEW_MS`]); `internal` for a generator failure.
    pub fn full(unit: Unit, cert: &Cert, now: u64) -> Result<(Self, Vec<u8>)> {
        if cert.unit != unit || !cert.valid_at(now) {
            return Err(Code::BadCert);
        }
        let eph = KemSecretKey::generate().map_err(|_| Code::Internal)?;
        let (ct_s, ss_s) = cert
            .kem_pk
            .encapsulate()
            .map_err(|_| Code::HandshakeFailed)?;
        let hello = Hello {
            kid: cert.kid(),
            ct_s: ct_s.to_bytes().to_vec(),
            ek_c: eph.public_key().to_bytes().to_vec(),
            nonce_c: nonce()?,
            time_c: now,
        };
        let call = frame::clear(Kind::Hello, unit, [0; SID_LEN], &hello.encode(), 0)?;
        Ok((
            Self {
                unit,
                eph,
                pending: Pending::Full { hello, ss_s },
            },
            call,
        ))
    }

    /// A resumption with `ticket` (consumed: a ticket is good once). Returns the call.
    ///
    /// # Errors
    /// `ticket_unknown` for an expired ticket; `internal` for a generator failure.
    pub fn resume(ticket: Ticket, now: u64) -> Result<(Self, Vec<u8>)> {
        if now > ticket.expires_at {
            return Err(Code::TicketUnknown);
        }
        let eph = KemSecretKey::generate().map_err(|_| Code::Internal)?;
        let r = Resume {
            ticket: ticket.ticket.clone(),
            ek_c: eph.public_key().to_bytes().to_vec(),
            nonce_c: nonce()?,
            time_c: now,
        };
        let body = r.encode();
        let call = frame::clear(Kind::Resume, ticket.unit, [0; SID_LEN], &body, 0)?;
        Ok((
            Self {
                unit: ticket.unit,
                eph,
                pending: Pending::Resume {
                    body,
                    res: ticket.secret,
                    chain_th: ticket.chain_th,
                },
            },
            call,
        ))
    }

    /// Finish with the server's answer: the reply, its confirmation checked in constant
    /// time, and the ticket record that follows it.
    ///
    /// # Errors
    /// The server's (unauthenticated) error code; `handshake_failed` for a bad confirmation
    /// or a reply of the wrong mode; `bad_frame` for anything malformed.
    pub fn finish(self, answer: &[u8]) -> Result<Session> {
        let frames = frame::split(answer)?;
        let f = frames[0];
        if f.header.kind == Kind::Error {
            return Err(f.error_code()?);
        }
        if f.header.kind != Kind::Reply || f.header.unit != self.unit || frames.len() != 2 {
            return Err(Code::BadFrame);
        }
        let sid = f.header.sid;
        let reply = Reply::decode(f.clear_body()?)?;
        let ct_c = handshake::kem_ct(&reply.ct_c)?;
        let ss_e = self
            .eph
            .decapsulate(&ct_c)
            .map_err(|_| Code::HandshakeFailed)?;
        let (keys, chain_th) = match &self.pending {
            Pending::Full { hello, ss_s } => {
                if reply.mode != 0 {
                    return Err(Code::HandshakeFailed);
                }
                let th = handshake::transcript(self.unit, hello, &sid, &reply)?;
                (
                    handshake::schedule(
                        label::MASTER,
                        [ss_s, &ss_e],
                        th,
                        self.unit,
                        &sid,
                        Role::Initiator,
                    )?,
                    th,
                )
            }
            Pending::Resume {
                body,
                res,
                chain_th,
            } => {
                if reply.mode != 1 {
                    return Err(Code::HandshakeFailed);
                }
                let th = handshake::transcript_resume(self.unit, body, &sid, &reply)?;
                (
                    handshake::schedule(
                        label::RESUME_MASTER,
                        [res, &ss_e],
                        th,
                        self.unit,
                        &sid,
                        Role::Initiator,
                    )?,
                    *chain_th,
                )
            }
        };
        if !handshake::confirms(&keys.confirm, &reply.confirm) {
            return Err(Code::HandshakeFailed);
        }
        let Keys {
            tx,
            mut rx,
            resumption,
            ..
        } = keys;
        let m = frame::open_record(&mut rx, &frames[1])?;
        let Msg::Ticket { expires_at, ticket } = Msg::decode(&m, Dir::Down)? else {
            return Err(Code::BadFrame);
        };
        Ok(Session {
            unit: self.unit,
            sid,
            chain_th,
            generation: reply.generation,
            tx,
            rx,
            next_rid: 1,
            reserved: std::collections::BTreeSet::new(),
            spent_ticket: None,
            ticket: Some(Ticket {
                unit: self.unit,
                ticket,
                expires_at,
                secret: resumption,
                chain_th,
            }),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            min_class: 0,
        })
    }
}

struct Outgoing {
    head: RequestHead,
    body: Zeroizing<Vec<u8>>,
    class: u8,
}

struct Incoming {
    head: crate::msg::ResponseHead,
    chunks: BTreeMap<u32, Vec<u8>>,
}

impl Drop for Incoming {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for c in self.chunks.values_mut() {
            c.zeroize();
        }
    }
}

/// What came back.
pub enum Event {
    /// A complete response, its body hash checked.
    Response {
        /// The request.
        rid: u32,
        /// Status.
        status: u16,
        /// 0 JSON, 1 bytes.
        ctype: u8,
        /// Body.
        body: Zeroizing<Vec<u8>>,
    },
    /// The server holds chunks below `next` of request `rid`: send the rest with
    /// [`Session::resend`] if a call was cut.
    Ack {
        /// Request.
        rid: u32,
        /// Next chunk it wants.
        next: u32,
    },
    /// The request was refused by the protocol layer (authenticated).
    Refused {
        /// Request (0: none in particular).
        rid: u32,
        /// Why.
        code: Code,
    },
    /// An unauthenticated error frame came back in this call (anyone on the path could have
    /// sent it). It changes nothing here; the caller may prove the session with an
    /// authenticated [`Session::pull`] before believing it (review #97 M-5).
    Unauthenticated {
        /// What it said.
        code: Code,
    },
    /// Part of a response is still missing (the call was cut): [`Session::pull`] it.
    Partial {
        /// Request.
        rid: u32,
        /// First missing chunk.
        next: u32,
    },
}

/// An open session.
pub struct Session {
    unit: Unit,
    sid: [u8; SID_LEN],
    chain_th: [u8; TH_LEN],
    generation: u32,
    tx: humid_pq2::TransitSealer,
    rx: humid_pq2::TransitOpener,
    next_rid: u32,
    reserved: std::collections::BTreeSet<u32>,
    ticket: Option<Ticket>,
    /// The resumption secret of a ticket already taken (a re-minted ticket reuses it).
    spent_ticket: Option<Secret32>,
    outgoing: BTreeMap<u32, Outgoing>,
    incoming: BTreeMap<u32, Incoming>,
    min_class: u8,
}

/// Most body bytes one call carries (the client splits bigger bodies over several calls);
/// with the head and small messages this stays within [`frame::MAX_FRAMES_PER_CALL`] frames
/// and the server's call limit.
pub const MAX_CALL: usize = 7 << 20;

impl Session {
    /// The session id.
    #[must_use]
    pub fn sid(&self) -> [u8; SID_LEN] {
        self.sid
    }

    /// The transcript sign-ins and live proofs name.
    #[must_use]
    pub fn th(&self) -> [u8; TH_LEN] {
        self.chain_th
    }

    /// The unit.
    #[must_use]
    pub fn unit(&self) -> Unit {
        self.unit
    }

    /// The `seq` a live proof for request `rid` must name.
    #[must_use]
    pub fn proof_seq(&self, rid: u32) -> u64 {
        (u64::from(self.generation) << 32) | u64::from(rid)
    }

    /// The request id the next [`Session::request`] will use (so a live proof can name it
    /// before the body exists).
    #[must_use]
    pub fn next_rid(&self) -> u32 {
        self.next_rid
    }

    /// Take the resumption ticket (once): keep it for the next unlock. A newer one may
    /// arrive later in the session (after a sign-in); take it again then.
    pub fn take_ticket(&mut self) -> Option<Ticket> {
        let t = self.ticket.take();
        if let Some(t) = &t {
            self.spent_ticket = Some(t.secret.duplicate());
        }
        t
    }

    /// Pad every record to at least this class (cover for small requests), at most
    /// [`frame::COVER_MAX_CLASS`].
    pub fn set_min_class(&mut self, c: u8) {
        self.min_class = c.min(frame::COVER_MAX_CLASS);
    }

    fn seal(&mut self, m: &Msg, class: u8) -> Result<Vec<u8>> {
        frame::seal_record(&mut self.tx, self.unit, self.sid, &m.encode(), class)
    }

    /// Seal any message (tests of what a modified client could send).
    #[cfg(test)]
    pub(crate) fn raw(&mut self, m: &Msg) -> Result<Vec<u8>> {
        self.seal(m, 0)
    }

    /// Seal arbitrary message bytes under this session's keys (fuzzing the server past its
    /// AEAD: assembly, pulls, answers).
    ///
    /// # Errors
    /// `too_large`.
    #[cfg(feature = "fuzz-hooks")]
    pub fn seal_raw(&mut self, msg: &[u8], class: u8) -> Result<Vec<u8>> {
        frame::seal_record(&mut self.tx, self.unit, self.sid, msg, class)
    }

    /// A request under an id the caller picks, used or not: what a modified client (or a
    /// test of the server's request-id rules) sends.
    ///
    /// # Errors
    /// `too_large`.
    #[doc(hidden)]
    pub fn request_with_id(
        &mut self,
        rid: u32,
        method: Method,
        path: &str,
        enc: Encoding,
        headers: &[(HeaderName, &[u8])],
        body: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        self.reserved.insert(rid);
        self.request_reserved(rid, method, path, enc, headers, body)
    }

    /// A request: its head and as many chunks as fit [`MAX_CALL`]. Returns the request id and
    /// the call; if the body is larger, call [`Session::resend`] with the server's acks.
    ///
    /// # Errors
    /// `too_large` over [`MAX_BODY`]; `internal` when request ids run out (handshake again).
    pub fn request(
        &mut self,
        method: Method,
        path: &str,
        enc: Encoding,
        headers: &[(HeaderName, &[u8])],
        body: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        let rid = self.reserve()?;
        self.request_reserved(rid, method, path, enc, headers, body)
    }

    /// Reserve the next request id, for a request whose live proof must name it before the
    /// body exists (the biometric prompt opens first). Send it with
    /// [`Session::request_reserved`]; ids may be used in any order.
    ///
    /// # Errors
    /// `internal` when request ids run out (handshake again).
    pub fn reserve(&mut self) -> Result<u32> {
        let rid = self.next_rid;
        self.next_rid = rid.checked_add(1).ok_or(Code::Internal)?;
        self.reserved.insert(rid);
        Ok(rid)
    }

    /// Whether request `rid` was sent and has had no answer (or refusal) yet.
    #[must_use]
    pub fn is_outstanding(&self, rid: u32) -> bool {
        self.outgoing.contains_key(&rid) || self.incoming.contains_key(&rid)
    }

    /// Whether `rid` is reserved and not yet sent.
    #[must_use]
    pub fn is_reserved(&self, rid: u32) -> bool {
        self.reserved.contains(&rid)
    }

    /// The generation of this session in its chain (a live proof's `seq` carries it).
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Send a request under a reserved id (see [`Session::reserve`]).
    ///
    /// # Errors
    /// `rid_unknown` for an id that isn't reserved (or was sent); `too_large` over
    /// [`MAX_BODY`].
    pub fn request_reserved(
        &mut self,
        rid: u32,
        method: Method,
        path: &str,
        enc: Encoding,
        headers: &[(HeaderName, &[u8])],
        body: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        if body.len() as u64 > MAX_BODY {
            return Err(Code::TooLarge);
        }
        if !self.reserved.remove(&rid) {
            return Err(Code::RidUnknown);
        }
        let mut hs: Vec<(HeaderName, Vec<u8>)> =
            headers.iter().map(|(n, v)| (*n, v.to_vec())).collect();
        hs.sort_by_key(|(n, _)| *n);
        let head = RequestHead {
            rid,
            method,
            enc,
            headers: hs,
            path: path.to_string(),
            body_len: body.len() as u64,
            body_hash: sha3_512(body),
        };
        let class = self.min_class;
        self.outgoing.insert(
            rid,
            Outgoing {
                head,
                body: Zeroizing::new(body.to_vec()),
                class,
            },
        );
        let call = self.chunks_from(rid, 0)?;
        Ok((rid, call))
    }

    /// The call that sends request `rid` from chunk `from` (after an [`Event::Ack`], or when
    /// a call was cut). Chunk 0 is the head again; the server ignores chunks it holds.
    ///
    /// # Errors
    /// `rid_unknown` for a request that's done.
    pub fn resend(&mut self, rid: u32, from: u32) -> Result<Vec<u8>> {
        self.chunks_from(rid, from)
    }

    fn chunks_from(&mut self, rid: u32, from: u32) -> Result<Vec<u8>> {
        let o = self.outgoing.get(&rid).ok_or(Code::RidUnknown)?;
        let (len, class) = (o.head.body_len, o.class);
        let n = n_chunks(len);
        let mut msgs = vec![];
        let mut size = 0;
        for i in from..n {
            let start = i as usize * CHUNK;
            let data = o.body[start..start + chunk_len(len, i)].to_vec();
            size += data.len();
            msgs.push(if i == 0 {
                Msg::Request(o.head.clone(), data)
            } else {
                Msg::Body {
                    rid,
                    index: i,
                    data,
                }
            });
            if size >= MAX_CALL {
                break;
            }
        }
        let mut out = vec![];
        for m in msgs {
            out.extend_from_slice(&self.seal(&m, class)?);
        }
        Ok(out)
    }

    /// Ask for the response to `rid` again, from chunk `from` (a download cut off midway
    /// resumes here; no new live check, no new request).
    ///
    /// # Errors
    /// Never in practice.
    pub fn pull(&mut self, rid: u32, from: u32) -> Result<Vec<u8>> {
        let c = self.min_class;
        self.seal(&Msg::Pull { rid, from }, c)
    }

    /// Feed what came back from a call.
    ///
    /// # Errors
    /// An unauthenticated error frame's code (`session_unknown`: handshake again), or
    /// `bad_record` / `replay` / `bad_frame` for frames that don't authenticate. Nothing in
    /// an unauthenticated frame changes the session's state.
    pub fn receive(&mut self, answer: &[u8]) -> Result<Vec<Event>> {
        let frames = frame::split(answer)?;
        let mut events = vec![];
        let mut unauth = None;
        for f in &frames {
            if f.header.unit != self.unit || f.header.sid != self.sid {
                unauth.get_or_insert(Code::BadFrame);
                continue;
            }
            if f.header.kind == Kind::Error {
                unauth.get_or_insert(f.error_code().unwrap_or(Code::BadFrame));
                continue;
            }
            let m = match frame::open_record(&mut self.rx, f) {
                Ok(m) => m,
                Err(c) => {
                    unauth.get_or_insert(c);
                    continue;
                }
            };
            self.on_msg(Msg::decode(&m, Dir::Down)?, &mut events)?;
        }
        for (rid, inc) in &self.incoming {
            let next = (0..n_chunks(inc.head.body_len))
                .find(|i| !inc.chunks.contains_key(i))
                .unwrap_or(0);
            events.push(Event::Partial { rid: *rid, next });
        }
        match unauth {
            Some(c) if events.is_empty() => Err(c),
            Some(c) => {
                events.push(Event::Unauthenticated { code: c });
                Ok(events)
            }
            None => Ok(events),
        }
    }

    fn on_msg(&mut self, m: Msg, ev: &mut Vec<Event>) -> Result<()> {
        match m {
            Msg::Response(head, c0) => {
                let rid = head.rid;
                if !self.outgoing.contains_key(&rid) && !self.incoming.contains_key(&rid) {
                    return Ok(()); // already delivered (a pull raced the original)
                }
                self.outgoing.remove(&rid);
                let mut inc = Incoming {
                    head,
                    chunks: BTreeMap::new(),
                };
                inc.chunks.insert(0, c0);
                if let Some(old) = self.incoming.remove(&rid) {
                    for (k, v) in &old.chunks {
                        if *k > 0 && old.head == inc.head {
                            inc.chunks.insert(*k, v.clone());
                        }
                    }
                }
                self.incoming.insert(rid, inc);
                self.try_finish(rid, ev)
            }
            Msg::Body { rid, index, data } => {
                if let Some(inc) = self.incoming.get_mut(&rid) {
                    if !chunk_fits(inc.head.body_len, index, &data) {
                        return Err(Code::BadFrame);
                    }
                    inc.chunks.entry(index).or_insert(data);
                    self.try_finish(rid, ev)?;
                }
                Ok(())
            }
            Msg::Ack { rid, next } => {
                ev.push(Event::Ack { rid, next });
                Ok(())
            }
            Msg::Error { rid, code } => {
                self.outgoing.remove(&rid);
                self.incoming.remove(&rid);
                ev.push(Event::Refused { rid, code });
                Ok(())
            }
            Msg::Ticket { expires_at, ticket } => {
                // a new ticket for the same chain (the server re-mints it after a sign-in so
                // the next session starts signed in): keep it in place of the old one
                if let Some(t) = self.ticket.as_mut() {
                    t.ticket = ticket;
                    t.expires_at = expires_at;
                } else if let Some(t) = self.spent_ticket.as_ref() {
                    self.ticket = Some(Ticket {
                        unit: self.unit,
                        ticket,
                        expires_at,
                        secret: t.duplicate(),
                        chain_th: self.chain_th,
                    });
                }
                Ok(())
            }
            _ => Err(Code::BadFrame),
        }
    }

    fn try_finish(&mut self, rid: u32, ev: &mut Vec<Event>) -> Result<()> {
        let done = self
            .incoming
            .get(&rid)
            .is_some_and(|i| i.chunks.len() == n_chunks(i.head.body_len) as usize);
        if !done {
            return Ok(());
        }
        let Some(inc) = self.incoming.remove(&rid) else {
            return Ok(());
        };
        let mut body = Zeroizing::new(Vec::with_capacity(
            usize::try_from(inc.head.body_len).unwrap_or(0),
        ));
        for c in inc.chunks.values() {
            body.extend_from_slice(c);
        }
        if !humid_pq2::ct_eq(&sha3_512(&body), &inc.head.body_hash) {
            return Err(Code::BodyMismatch);
        }
        ev.push(Event::Response {
            rid,
            status: inc.head.status,
            ctype: inc.head.ctype,
            body,
        });
        Ok(())
    }
}
