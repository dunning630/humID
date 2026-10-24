//! Request bodies as typed parts, and live proofs as binary TLV (HTP2.md §6).
//!
//! ```text
//! parts  = u8 n ‖ part×n                    n ≤ 16, at most one JSON and one PROOF part
//! part   = 01 ‖ lp(json object)              the unit's JSON, minus the binary fields
//!        | 02 ‖ lp(name) ‖ lp(bytes)         a binary field: name is [a-z_]{1,32}
//!        | 03 ‖ lp(proof)                    a step-up live proof (below)
//!
//! proof  = header(0x0303) ‖ lp(method) ‖ lp(path) ‖ th (64) ‖ u64 seq ‖ device (32) ‖ nonce (32)
//!          ‖ u64 at ‖ u8 mode ‖ lp(device_sig) ‖ lp(live_p256) ‖ lp(live_mldsa | "") ‖ lp(signed body)
//!          ‖ lp(app_attest | "")
//! ```
//!
//! `app_attest` is the iPhone's App Attest assertion for this check (empty on Android).
//!
//! A proof made in this session must name the `seq` of the request that carries it: the
//! endpoint refuses a mismatch before the unit sees it, and passes the request's `seq` to the
//! unit, which checks it again with method, path, `th`, mode, nonce, time, the signatures and
//! (on iOS) the App Attest assertion. A proof travels only as a proof part: the endpoint
//! refuses `signed` anywhere else.

use humid_pq2::encoding::{Reader, header};

use crate::{Code, MAX_BODY, Result, TH_LEN, types};

/// Most parts in one body.
pub const MAX_PARTS: usize = 16;
/// Largest JSON part.
pub const MAX_JSON: usize = 256 << 10;
/// Largest signed body inside a proof.
pub const MAX_SIGNED_BODY: usize = 256 << 10;
/// Largest signature field in a proof (an ML-DSA-87 encoding is 4,640 bytes).
pub const MAX_SIG: usize = 8 << 10;

/// One part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    /// The JSON object.
    Json(Vec<u8>),
    /// A named binary field.
    Bytes(String, Vec<u8>),
    /// A step-up proof.
    Proof(Box<Proof>),
}

/// A step-up live proof (SERVER.md §2.3; HTP2.md §6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The approved method.
    pub method: String,
    /// The approved path.
    pub path: String,
    /// The session transcript.
    pub th: [u8; TH_LEN],
    /// The request id the proof approves.
    pub seq: u64,
    /// The device id.
    pub device: [u8; 32],
    /// The single-use nonce from the session's pool.
    pub nonce: [u8; 32],
    /// When the check happened (ms).
    pub at: u64,
    /// The session mode the device key and chip signed: 0 normal, 1 duress.
    pub mode: u8,
    /// The device key's signature.
    pub device_sig: Vec<u8>,
    /// The secure chip's P-256 signature.
    pub live_p256: Vec<u8>,
    /// The chip's ML-DSA-87 signature, where it has one.
    pub live_mldsa: Option<Vec<u8>>,
    /// The exact body bytes the device key signed.
    pub body: Vec<u8>,
    /// The App Attest assertion for this check (iOS; SERVER.md §2.3), CBOR as the platform
    /// returns it.
    pub app_attest: Option<Vec<u8>>,
}

/// Largest App Attest assertion in a proof (real ones are about 120 bytes).
pub const MAX_APP_ATTEST: usize = 1024;

fn lp(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
    o.extend_from_slice(b);
}

fn name_ok(n: &[u8]) -> bool {
    (1..=32).contains(&n.len()) && n.iter().all(|c| c.is_ascii_lowercase() || *c == b'_')
}

impl Proof {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut o = header(types::PROOF).to_vec();
        lp(&mut o, self.method.as_bytes());
        lp(&mut o, self.path.as_bytes());
        o.extend_from_slice(&self.th);
        o.extend_from_slice(&self.seq.to_be_bytes());
        o.extend_from_slice(&self.device);
        o.extend_from_slice(&self.nonce);
        o.extend_from_slice(&self.at.to_be_bytes());
        o.push(self.mode);
        lp(&mut o, &self.device_sig);
        lp(&mut o, &self.live_p256);
        lp(&mut o, self.live_mldsa.as_deref().unwrap_or(&[]));
        lp(&mut o, &self.body);
        lp(&mut o, self.app_attest.as_deref().unwrap_or(&[]));
        o
    }

    /// Decode.
    ///
    /// # Errors
    /// `bad_frame`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let e = |_| Code::BadFrame;
        let mut r = Reader::new(b);
        r.header(types::PROOF).map_err(e)?;
        let text = |v: &[u8]| String::from_utf8(v.to_vec()).map_err(|_| Code::BadFrame);
        let p = Self {
            method: text(r.lp(8).map_err(e)?)?,
            path: text(r.lp(crate::msg::MAX_PATH).map_err(e)?)?,
            th: r.array().map_err(e)?,
            seq: r.u64().map_err(e)?,
            device: r.array().map_err(e)?,
            nonce: r.array().map_err(e)?,
            at: r.u64().map_err(e)?,
            mode: r.array::<1>().map_err(e)?[0],
            device_sig: r.lp(MAX_SIG).map_err(e)?.to_vec(),
            live_p256: r.lp(MAX_SIG).map_err(e)?.to_vec(),
            live_mldsa: Some(r.lp(MAX_SIG).map_err(e)?.to_vec()).filter(|v| !v.is_empty()),
            body: r.lp(MAX_SIGNED_BODY).map_err(e)?.to_vec(),
            app_attest: Some(r.lp(MAX_APP_ATTEST).map_err(e)?.to_vec()).filter(|v| !v.is_empty()),
        };
        r.finish().map_err(e)?;
        if p.mode > 1 {
            return Err(Code::BadFrame);
        }
        Ok(p)
    }
}

/// Encode parts.
#[must_use]
pub fn encode(parts: &[Part]) -> Vec<u8> {
    let mut o = vec![u8::try_from(parts.len()).unwrap_or(0)];
    for p in parts {
        match p {
            Part::Json(j) => {
                o.push(1);
                lp(&mut o, j);
            }
            Part::Bytes(n, v) => {
                o.push(2);
                lp(&mut o, n.as_bytes());
                lp(&mut o, v);
            }
            Part::Proof(p) => {
                o.push(3);
                lp(&mut o, &p.encode());
            }
        }
    }
    o
}

/// Decode parts: at most one JSON part and one proof, field names unique and well-formed.
///
/// # Errors
/// `bad_frame`.
pub fn decode(b: &[u8]) -> Result<Vec<Part>> {
    let e = |_| Code::BadFrame;
    let mut r = Reader::new(b);
    let n = usize::from(r.array::<1>().map_err(e)?[0]);
    if n > MAX_PARTS {
        return Err(Code::BadFrame);
    }
    let max = usize::try_from(MAX_BODY).unwrap_or(usize::MAX);
    let mut out: Vec<Part> = Vec::with_capacity(n);
    for _ in 0..n {
        let p = match r.array::<1>().map_err(e)?[0] {
            1 => Part::Json(r.lp(MAX_JSON).map_err(e)?.to_vec()),
            2 => {
                let name = r.lp(32).map_err(e)?;
                if !name_ok(name) {
                    return Err(Code::BadFrame);
                }
                let name = String::from_utf8(name.to_vec()).map_err(|_| Code::BadFrame)?;
                Part::Bytes(name, r.lp(max).map_err(e)?.to_vec())
            }
            3 => Part::Proof(Box::new(Proof::decode(
                r.lp(MAX_SIGNED_BODY + 4 * MAX_SIG + 2048).map_err(e)?,
            )?)),
            _ => return Err(Code::BadFrame),
        };
        let dup = out.iter().any(|q| match (q, &p) {
            (Part::Json(_), Part::Json(_)) | (Part::Proof(_), Part::Proof(_)) => true,
            (Part::Bytes(a, _), Part::Bytes(b, _)) => a == b,
            _ => false,
        });
        if dup {
            return Err(Code::BadFrame);
        }
        out.push(p);
    }
    r.finish().map_err(e)?;
    Ok(out)
}

/// The proof among `parts`, if any.
#[must_use]
pub fn proof(parts: &[Part]) -> Option<&Proof> {
    parts.iter().find_map(|p| match p {
        Part::Proof(p) => Some(p.as_ref()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_() -> Proof {
        Proof {
            method: "POST".into(),
            path: "/v1/objects".into(),
            th: [1; 64],
            seq: 3,
            device: [2; 32],
            nonce: [3; 32],
            at: 4,
            mode: 0,
            device_sig: vec![5; 4640],
            live_p256: vec![6; 71],
            live_mldsa: None,
            body: b"{}".to_vec(),
            app_attest: None,
        }
    }

    #[test]
    fn round_trip_and_rules() {
        let ps = vec![
            Part::Json(b"{\"a\":1}".to_vec()),
            Part::Bytes("envelope".into(), vec![9; 1000]),
            Part::Bytes("sealed_share".into(), vec![8; 10]),
            Part::Proof(Box::new(proof_())),
        ];
        let b = encode(&ps);
        assert_eq!(decode(&b).unwrap(), ps);
        assert_eq!(proof(&ps).unwrap().seq, 3);
        for n in 0..b.len() {
            assert!(decode(&b[..n]).is_err());
        }
        assert!(decode(&[b.clone(), vec![0]].concat()).is_err());
        let dup = encode(&[Part::Json(vec![]), Part::Json(vec![])]);
        assert!(decode(&dup).is_err());
        let dup = encode(&[
            Part::Bytes("a".into(), vec![]),
            Part::Bytes("a".into(), vec![]),
        ]);
        assert!(decode(&dup).is_err());
        let bad = encode(&[Part::Bytes("A-b".into(), vec![])]);
        assert!(decode(&bad).is_err());
        let mut p = proof_();
        p.live_mldsa = Some(vec![1; 4627]);
        assert_eq!(Proof::decode(&p.encode()).unwrap(), p);
        p.app_attest = Some(vec![2; 120]);
        assert_eq!(Proof::decode(&p.encode()).unwrap(), p);
        p.app_attest = Some(vec![2; MAX_APP_ATTEST + 1]);
        assert!(
            Proof::decode(&p.encode()).is_err(),
            "an assertion over the cap"
        );
    }
}
