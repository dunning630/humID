//! Messages inside records (HTP2.md §5). One message per record; the record's padding hides
//! its exact size. Every decoder checks every length first, refuses trailing bytes and never
//! panics.
//!
//! ```text
//! REQUEST  01 ‖ u32 rid ‖ u8 method ‖ u8 enc ‖ u8 nh ‖ (u8 name ‖ lp(value))×nh ‖ lp(path)
//!             ‖ u64 body_len ‖ body_hash (64) ‖ lp(chunk 0)                         c → s
//! BODY     02 ‖ u32 rid ‖ u32 index ‖ lp(chunk)                                     both
//! PULL     03 ‖ u32 rid ‖ u32 from                                                  c → s
//! RESPONSE 11 ‖ u32 rid ‖ u16 status ‖ u8 ctype ‖ u64 body_len ‖ body_hash (64) ‖ lp(chunk 0)
//! ACK      12 ‖ u32 rid ‖ u32 next                                                  s → c
//! ERROR    13 ‖ u32 rid ‖ u16 code                                                  s → c
//! TICKET   14 ‖ u64 expires_at ‖ lp(ticket)                                         s → c
//! ```

use humid_pq2::encoding::Reader;

use crate::{CHUNK, Code, MAX_BODY, MAX_RESPONSE, Result, chunk_len, n_chunks};

/// A request's method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

impl Method {
    /// The wire byte.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Method::Get => 1,
            Method::Post => 2,
            Method::Put => 3,
            Method::Patch => 4,
            Method::Delete => 5,
        }
    }

    /// From the wire byte.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Method::Get,
            2 => Method::Post,
            3 => Method::Put,
            4 => Method::Patch,
            5 => Method::Delete,
            _ => return None,
        })
    }

    /// As HTTP spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }

    /// From the HTTP spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [
            Method::Get,
            Method::Post,
            Method::Put,
            Method::Patch,
            Method::Delete,
        ]
        .into_iter()
        .find(|m| m.as_str() == s)
    }
}

/// How a request body is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// The unit's own bytes (JSON for core and anon).
    Raw,
    /// Typed parts (crate::parts): binary proofs and blobs beside a JSON object.
    Parts,
}

/// The typed request headers. Nothing else can be expressed: in particular not the session
/// transcript or the client network, which the endpoint sets itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeaderName {
    /// The core session token (raw bytes, ≤ 64).
    Session,
    /// A download ticket from an open (raw bytes, ≤ 64).
    DownloadTicket,
}

impl HeaderName {
    fn to_u8(self) -> u8 {
        match self {
            HeaderName::Session => 1,
            HeaderName::DownloadTicket => 2,
        }
    }
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(HeaderName::Session),
            2 => Some(HeaderName::DownloadTicket),
            _ => None,
        }
    }
}

/// Largest header value.
pub const MAX_HEADER: usize = 64;
/// Largest path.
pub const MAX_PATH: usize = 1024;
/// Largest resumption ticket.
pub const MAX_TICKET: usize = 1024;

/// What a request is, without its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    /// Request id: unique within the session; it is also the `seq` a live proof names.
    pub rid: u32,
    /// Method.
    pub method: Method,
    /// Body encoding.
    pub enc: Encoding,
    /// Typed headers, in ascending name order, each at most once.
    pub headers: Vec<(HeaderName, Vec<u8>)>,
    /// Path and query.
    pub path: String,
    /// Body length.
    pub body_len: u64,
    /// SHA3-512 of the body.
    pub body_hash: [u8; 64],
}

impl RequestHead {
    /// The value of header `n`.
    #[must_use]
    pub fn header(&self, n: HeaderName) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_slice())
    }
}

/// What a response is, without its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    /// The request it answers.
    pub rid: u32,
    /// HTTP-style status from the unit.
    pub status: u16,
    /// 0 JSON, 1 bytes.
    pub ctype: u8,
    /// Body length.
    pub body_len: u64,
    /// SHA3-512 of the body.
    pub body_hash: [u8; 64],
}

/// A message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// A request head with its first chunk.
    Request(RequestHead, Vec<u8>),
    /// A body chunk (request or response, by direction).
    Body {
        /// Request id.
        rid: u32,
        /// Chunk index (≥ 1; chunk 0 rides in the head).
        index: u32,
        /// The bytes.
        data: Vec<u8>,
    },
    /// Send the response to `rid` again, from chunk `from`.
    Pull {
        /// Request id.
        rid: u32,
        /// First chunk wanted.
        from: u32,
    },
    /// A response head with its first chunk.
    Response(ResponseHead, Vec<u8>),
    /// The server holds chunks `0..next` of request `rid`.
    Ack {
        /// Request id.
        rid: u32,
        /// The next chunk it wants.
        next: u32,
    },
    /// A refusal of one request, authenticated.
    Error {
        /// Request id (0: not about one request).
        rid: u32,
        /// Why.
        code: Code,
    },
    /// A resumption ticket for the next session.
    Ticket {
        /// When it stops working (server ms).
        expires_at: u64,
        /// The opaque ticket.
        ticket: Vec<u8>,
    },
}

/// Which way a message travels (each end refuses the other end's messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Client → server.
    Up,
    /// Server → client.
    Down,
}

fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(b);
}

fn chunk_ok(body_len: u64, index: u32, data: &[u8]) -> bool {
    index < n_chunks(body_len) && data.len() == chunk_len(body_len, index)
}

impl Msg {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Msg::Request(h, c0) => {
                o.push(0x01);
                o.extend_from_slice(&h.rid.to_be_bytes());
                o.push(h.method.to_u8());
                o.push(match h.enc {
                    Encoding::Raw => 0,
                    Encoding::Parts => 1,
                });
                o.push(u8::try_from(h.headers.len()).unwrap_or(0));
                for (n, v) in &h.headers {
                    o.push(n.to_u8());
                    lp(&mut o, v);
                }
                lp(&mut o, h.path.as_bytes());
                o.extend_from_slice(&h.body_len.to_be_bytes());
                o.extend_from_slice(&h.body_hash);
                lp(&mut o, c0);
            }
            Msg::Body { rid, index, data } => {
                o.push(0x02);
                o.extend_from_slice(&rid.to_be_bytes());
                o.extend_from_slice(&index.to_be_bytes());
                lp(&mut o, data);
            }
            Msg::Pull { rid, from } => {
                o.push(0x03);
                o.extend_from_slice(&rid.to_be_bytes());
                o.extend_from_slice(&from.to_be_bytes());
            }
            Msg::Response(h, c0) => {
                o.push(0x11);
                o.extend_from_slice(&h.rid.to_be_bytes());
                o.extend_from_slice(&h.status.to_be_bytes());
                o.push(h.ctype);
                o.extend_from_slice(&h.body_len.to_be_bytes());
                o.extend_from_slice(&h.body_hash);
                lp(&mut o, c0);
            }
            Msg::Ack { rid, next } => {
                o.push(0x12);
                o.extend_from_slice(&rid.to_be_bytes());
                o.extend_from_slice(&next.to_be_bytes());
            }
            Msg::Error { rid, code } => {
                o.push(0x13);
                o.extend_from_slice(&rid.to_be_bytes());
                o.extend_from_slice(&code.to_u16().to_be_bytes());
            }
            Msg::Ticket { expires_at, ticket } => {
                o.push(0x14);
                o.extend_from_slice(&expires_at.to_be_bytes());
                lp(&mut o, ticket);
            }
        }
        o
    }

    /// Decode a message travelling `dir`.
    ///
    /// # Errors
    /// `bad_frame` for anything malformed or travelling the wrong way; `too_large` for a
    /// body over the cap.
    pub fn decode(b: &[u8], dir: Dir) -> Result<Self> {
        let mut r = Reader::new(b);
        let e = |_| Code::BadFrame;
        let t = r.array::<1>().map_err(e)?[0];
        let m = match (t, dir) {
            (0x01, Dir::Up) => {
                let rid = r.u32().map_err(e)?;
                let method =
                    Method::from_u8(r.array::<1>().map_err(e)?[0]).ok_or(Code::BadFrame)?;
                let enc = match r.array::<1>().map_err(e)?[0] {
                    0 => Encoding::Raw,
                    1 => Encoding::Parts,
                    _ => return Err(Code::BadFrame),
                };
                let nh = r.array::<1>().map_err(e)?[0];
                let mut headers: Vec<(HeaderName, Vec<u8>)> = vec![];
                for _ in 0..nh {
                    let n =
                        HeaderName::from_u8(r.array::<1>().map_err(e)?[0]).ok_or(Code::BadFrame)?;
                    if headers.last().is_some_and(|(p, _)| *p >= n) {
                        return Err(Code::BadFrame); // ascending, each once
                    }
                    headers.push((n, r.lp(MAX_HEADER).map_err(e)?.to_vec()));
                }
                let path = r.lp(MAX_PATH).map_err(e)?;
                if path.first() != Some(&b'/') || !path.iter().all(|c| (0x21..0x7f).contains(c)) {
                    return Err(Code::BadFrame);
                }
                let body_len = r.u64().map_err(e)?;
                if body_len > MAX_BODY {
                    return Err(Code::TooLarge);
                }
                let body_hash = r.array::<64>().map_err(e)?;
                let c0 = r.lp(CHUNK).map_err(e)?;
                if !chunk_ok(body_len, 0, c0) {
                    return Err(Code::BadFrame);
                }
                Msg::Request(
                    RequestHead {
                        rid,
                        method,
                        enc,
                        headers,
                        path: String::from_utf8(path.to_vec()).map_err(|_| Code::BadFrame)?,
                        body_len,
                        body_hash,
                    },
                    c0.to_vec(),
                )
            }
            (0x02, _) => {
                let rid = r.u32().map_err(e)?;
                let index = r.u32().map_err(e)?;
                let data = r.lp(CHUNK).map_err(e)?;
                if index == 0 || data.is_empty() {
                    return Err(Code::BadFrame);
                }
                Msg::Body {
                    rid,
                    index,
                    data: data.to_vec(),
                }
            }
            (0x03, Dir::Up) => Msg::Pull {
                rid: r.u32().map_err(e)?,
                from: r.u32().map_err(e)?,
            },
            (0x11, Dir::Down) => {
                let rid = r.u32().map_err(e)?;
                let status = r.u16().map_err(e)?;
                let ctype = r.array::<1>().map_err(e)?[0];
                let body_len = r.u64().map_err(e)?;
                if ctype > 1 || !(100..600).contains(&status) {
                    return Err(Code::BadFrame);
                }
                if body_len > MAX_RESPONSE {
                    return Err(Code::TooLarge);
                }
                let body_hash = r.array::<64>().map_err(e)?;
                let c0 = r.lp(CHUNK).map_err(e)?;
                if !chunk_ok(body_len, 0, c0) {
                    return Err(Code::BadFrame);
                }
                Msg::Response(
                    ResponseHead {
                        rid,
                        status,
                        ctype,
                        body_len,
                        body_hash,
                    },
                    c0.to_vec(),
                )
            }
            (0x12, Dir::Down) => Msg::Ack {
                rid: r.u32().map_err(e)?,
                next: r.u32().map_err(e)?,
            },
            (0x13, Dir::Down) => Msg::Error {
                rid: r.u32().map_err(e)?,
                code: Code::from_u16(r.u16().map_err(e)?).ok_or(Code::BadFrame)?,
            },
            (0x14, Dir::Down) => Msg::Ticket {
                expires_at: r.u64().map_err(e)?,
                ticket: r.lp(MAX_TICKET).map_err(e)?.to_vec(),
            },
            _ => return Err(Code::BadFrame),
        };
        r.finish().map_err(e)?;
        Ok(m)
    }
}

/// Whether chunk `index` of `body_len` may hold `data` (for assemblers).
#[must_use]
pub fn chunk_fits(body_len: u64, index: u32, data: &[u8]) -> bool {
    chunk_ok(body_len, index, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(len: u64) -> RequestHead {
        RequestHead {
            rid: 7,
            method: Method::Post,
            enc: Encoding::Parts,
            headers: vec![
                (HeaderName::Session, vec![1; 32]),
                (HeaderName::DownloadTicket, vec![2; 16]),
            ],
            path: "/v1/objects".into(),
            body_len: len,
            body_hash: [9; 64],
        }
    }

    #[test]
    fn round_trips() {
        let msgs = [
            Msg::Request(head(3), vec![1, 2, 3]),
            Msg::Body {
                rid: 7,
                index: 1,
                data: vec![5; 10],
            },
            Msg::Pull { rid: 7, from: 2 },
        ];
        for m in msgs {
            assert_eq!(Msg::decode(&m.encode(), Dir::Up).unwrap(), m);
            if !matches!(m, Msg::Body { .. }) {
                assert!(
                    Msg::decode(&m.encode(), Dir::Down).is_err(),
                    "the other direction refuses it"
                );
            }
        }
        let down = [
            Msg::Response(
                ResponseHead {
                    rid: 7,
                    status: 200,
                    ctype: 0,
                    body_len: 0,
                    body_hash: [0; 64],
                },
                vec![],
            ),
            Msg::Ack { rid: 1, next: 3 },
            Msg::Error {
                rid: 1,
                code: Code::RouteNotFound,
            },
            Msg::Ticket {
                expires_at: 5,
                ticket: vec![1; 97],
            },
        ];
        for m in down {
            assert_eq!(Msg::decode(&m.encode(), Dir::Down).unwrap(), m);
            assert!(Msg::decode(&m.encode(), Dir::Up).is_err());
        }
    }

    #[test]
    fn decoders_refuse_the_malformed() {
        let ok = Msg::Request(head(3), vec![1, 2, 3]).encode();
        for n in 0..ok.len() {
            assert!(Msg::decode(&ok[..n], Dir::Up).is_err(), "truncated at {n}");
        }
        assert!(
            Msg::decode(&[ok.clone(), vec![0]].concat(), Dir::Up).is_err(),
            "trailing"
        );
        // a chunk 0 that doesn't match the announced length
        assert!(Msg::decode(&Msg::Request(head(4), vec![1, 2, 3]).encode(), Dir::Up).is_err());
        // headers out of order
        let mut h = head(0);
        h.headers.reverse();
        assert!(Msg::decode(&Msg::Request(h, vec![]).encode(), Dir::Up).is_err());
        // a relative path, a path with a space
        let mut h = head(0);
        h.path = "v1/x".into();
        assert!(Msg::decode(&Msg::Request(h, vec![]).encode(), Dir::Up).is_err());
        let mut h = head(0);
        h.path = "/v1/a b".into();
        assert!(Msg::decode(&Msg::Request(h, vec![]).encode(), Dir::Up).is_err());
        // over the body cap
        assert_eq!(
            Msg::decode(&Msg::Request(head(MAX_BODY + 1), vec![]).encode(), Dir::Up),
            Err(Code::TooLarge)
        );
        // body chunk 0 or empty
        assert!(
            Msg::decode(
                &Msg::Body {
                    rid: 1,
                    index: 0,
                    data: vec![1]
                }
                .encode(),
                Dir::Up
            )
            .is_err()
        );
        assert!(
            Msg::decode(
                &Msg::Body {
                    rid: 1,
                    index: 1,
                    data: vec![]
                }
                .encode(),
                Dir::Up
            )
            .is_err()
        );
        assert!(Msg::decode(&[0x7f], Dir::Up).is_err());
        assert!(Msg::decode(&[], Dir::Up).is_err());
    }

    #[test]
    fn methods() {
        for m in [
            Method::Get,
            Method::Post,
            Method::Put,
            Method::Patch,
            Method::Delete,
        ] {
            assert_eq!(Method::parse(m.as_str()), Some(m));
            assert_eq!(Method::from_u8(m.to_u8()), Some(m));
        }
        assert_eq!(Method::parse("TRACE"), None);
    }
}
