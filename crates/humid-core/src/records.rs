//! Local records (CORE.md §7): one AAD shape per record type, no fallbacks, and a revision
//! that only grows, so a server or a restored copy can't serve an older record back.
//!
//! ```text
//! index entry   = u64 rev ‖ box(0x0110, index_key, [account_id, item_id, u64 rev], pad64(lp(entry)))
//! revisions     = box(0x0113, device_records_key, [device_id], (lp(id) ‖ u64 rev)*)
//! setting       = box(0x0111, device_records_key, [device_id, name], lp(value))
//! ```

use std::collections::BTreeMap;

use humid_pq2::encoding::{Reader, lp};
use humid_pq2::{ObjectType, Secret32, open_at_rest, seal_at_rest};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Largest index entry / setting value.
pub const MAX_RECORD: usize = 64 * 1024;
/// Largest record id.
pub const MAX_ID: usize = 256;

fn pad64(body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut v = Zeroizing::new(lp(&[body])?);
    let n = v.len().div_ceil(64) * 64;
    v.resize(n, 0);
    Ok(v)
}

fn unpad(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut r = Reader::new(bytes);
    let body = r.lp(MAX_RECORD)?;
    if r.rest().iter().any(|&b| b != 0) {
        return Err(CoreError::Format);
    }
    Ok(Zeroizing::new(body.to_vec()))
}

/// Seal an index entry for `item_id` at `rev` (≥ 1).
pub(crate) fn seal_index(
    key: &Secret32,
    account_id: &[u8; 32],
    item_id: &[u8],
    rev: u64,
    entry: &[u8],
) -> Result<Vec<u8>> {
    if rev == 0 || item_id.len() > MAX_ID || entry.len() > MAX_RECORD {
        return Err(CoreError::Format);
    }
    let mut out = rev.to_be_bytes().to_vec();
    out.extend(seal_at_rest(
        key,
        ObjectType::INDEX_ENTRY,
        &[account_id, item_id, &rev.to_be_bytes()],
        &pad64(entry)?,
    )?);
    Ok(out)
}

/// Open an index entry as `item_id`'s. Returns `(rev, entry)`.
pub(crate) fn open_index(
    key: &Secret32,
    account_id: &[u8; 32],
    item_id: &[u8],
    blob: &[u8],
) -> Result<(u64, Zeroizing<Vec<u8>>)> {
    let mut r = Reader::new(blob);
    let rev = r.u64()?;
    let pt = open_at_rest(
        key,
        ObjectType::INDEX_ENTRY,
        &[account_id, item_id, &rev.to_be_bytes()],
        r.rest(),
    )
    .map_err(|_| CoreError::WrongDocument)?;
    if rev == 0 {
        return Err(CoreError::Format);
    }
    Ok((rev, unpad(&pt)?))
}

/// The highest revision this device has seen per record id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revisions(pub(crate) BTreeMap<Vec<u8>, u64>);

impl Revisions {
    /// Accept `rev` for `id`: refuses anything older than seen, remembers the highest.
    pub(crate) fn accept(&mut self, id: &[u8], rev: u64) -> Result<()> {
        let seen = self.0.get(id).copied().unwrap_or(0);
        if rev < seen {
            return Err(CoreError::Rollback);
        }
        self.0.insert(id.to_vec(), rev);
        Ok(())
    }

    /// The next revision to write for `id`.
    pub(crate) fn next(&self, id: &[u8]) -> Result<u64> {
        self.0
            .get(id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(CoreError::Format)
    }

    pub(crate) fn seal(&self, key: &Secret32, device_id: &[u8; 32]) -> Result<Vec<u8>> {
        let mut body = Zeroizing::new(Vec::new());
        for (id, rev) in &self.0 {
            humid_pq2::encoding::lp_push(&mut body, id)?;
            body.extend_from_slice(&rev.to_be_bytes());
        }
        Ok(seal_at_rest(
            key,
            ObjectType::RECORD_REVS,
            &[device_id],
            &body,
        )?)
    }

    pub(crate) fn open(key: &Secret32, device_id: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let pt = open_at_rest(key, ObjectType::RECORD_REVS, &[device_id], blob)?;
        let mut r = Reader::new(&pt);
        let mut m = BTreeMap::new();
        while r.remaining() > 0 {
            let id = r.lp(MAX_ID)?.to_vec();
            let rev = r.u64()?;
            m.insert(id, rev);
        }
        Ok(Self(m))
    }
}

/// Seal a device-only setting.
pub(crate) fn seal_setting(
    key: &Secret32,
    device_id: &[u8; 32],
    name: &str,
    value: &[u8],
) -> Result<Vec<u8>> {
    if name.len() > MAX_ID || value.len() > MAX_RECORD {
        return Err(CoreError::Format);
    }
    Ok(seal_at_rest(
        key,
        ObjectType::SETTINGS,
        &[device_id, name.as_bytes()],
        &lp(&[value])?,
    )?)
}

/// Open a device-only setting.
pub(crate) fn open_setting(
    key: &Secret32,
    device_id: &[u8; 32],
    name: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let pt = open_at_rest(
        key,
        ObjectType::SETTINGS,
        &[device_id, name.as_bytes()],
        blob,
    )?;
    let mut r = Reader::new(&pt);
    let v = Zeroizing::new(r.lp(MAX_RECORD)?.to_vec());
    r.finish()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_entries_are_bound_and_versioned() {
        let k = Secret32::random().unwrap();
        let a = [3u8; 32];
        let e1 = seal_index(&k, &a, b"item-1", 1, b"Passport").unwrap();
        let e2 = seal_index(&k, &a, b"item-1", 2, b"Passport (renamed)").unwrap();
        let (rev, pt) = open_index(&k, &a, b"item-1", &e2).unwrap();
        assert_eq!((rev, &pt[..]), (2, &b"Passport (renamed)"[..]));
        // moved to another item, or another account: refused (audit M2)
        assert!(open_index(&k, &a, b"item-2", &e1).is_err());
        assert!(open_index(&k, &[4u8; 32], b"item-1", &e1).is_err());
        // rev rewritten in the clear prefix: refused
        let mut e = e1.clone();
        e[7] = 9;
        assert!(open_index(&k, &a, b"item-1", &e).is_err());
        // served back older than seen: refused
        let mut revs = Revisions::default();
        revs.accept(b"item-1", 2).unwrap();
        let (old, _) = open_index(&k, &a, b"item-1", &e1).unwrap();
        assert_eq!(revs.accept(b"item-1", old), Err(CoreError::Rollback));
        assert_eq!(revs.next(b"item-1").unwrap(), 3);
        // padding hides short lengths
        assert_eq!(
            seal_index(&k, &a, b"i", 1, b"a").unwrap().len(),
            seal_index(&k, &a, b"i", 1, b"abcdefgh").unwrap().len()
        );
    }

    #[test]
    fn revisions_and_settings_round_trip() {
        let k = Secret32::random().unwrap();
        let d = [1u8; 32];
        let mut r = Revisions::default();
        r.accept(b"x", 5).unwrap();
        r.accept(b"yy", 1).unwrap();
        assert_eq!(
            Revisions::open(&k, &d, &r.seal(&k, &d).unwrap()).unwrap(),
            r
        );
        assert!(Revisions::open(&k, &[2u8; 32], &r.seal(&k, &d).unwrap()).is_err());
        let s = seal_setting(&k, &d, "duress", b"gesture-3").unwrap();
        assert_eq!(
            &open_setting(&k, &d, "duress", &s).unwrap()[..],
            b"gesture-3"
        );
        assert!(open_setting(&k, &d, "other", &s).is_err());
    }
}
