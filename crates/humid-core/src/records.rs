//! Local records (CORE.md §7): one AAD shape per record type, no fallbacks, and revisions
//! that only grow, so a server or a restored copy can't serve an older record back.
//!
//! ```text
//! index entry = u64 rev ‖ writer device_id (32)
//!               ‖ box(0x0110, index_key, [account_id, item_id, u64 rev, writer], pad64(lp(entry)))
//! revisions   = u64 c ‖ box(0x0113, device_records_key, [device_id, u64 c],
//!                           (lp(id) ‖ u64 rev ‖ writer (32))*)
//! setting     = box(0x0111, device_records_key, [device_id, name], lp(value))
//! ```
//!
//! Index entries are synced, so their version is `(rev, writer)`, ordered lexicographically:
//! a writer takes `rev = max(seen, current) + 1` from the entry the vault holds now, and two
//! devices that write the same `rev` are still totally ordered (review M7). The revisions
//! record carries a counter `c` that the store also keeps outside the files; a copy older
//! than that counter, or a missing one, is a rollback (review M2).

use std::collections::BTreeMap;

use humid_pq2::encoding::{Reader, lp};
use humid_pq2::{ObjectType, Secret32, open_at_rest, seal_at_rest};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Largest index entry / setting value.
pub const MAX_RECORD: usize = 64 * 1024;
/// Largest record id.
pub const MAX_ID: usize = 256;

/// A synced record's version: revision, then the writing device's id.
pub type Version = (u64, [u8; 32]);

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

/// Seal an index entry for `item_id` at `version` (rev ≥ 1).
pub(crate) fn seal_index(
    key: &Secret32,
    account_id: &[u8; 32],
    item_id: &[u8],
    version: Version,
    entry: &[u8],
) -> Result<Vec<u8>> {
    let (rev, writer) = version;
    if rev == 0 || item_id.len() > MAX_ID || entry.len() > MAX_RECORD {
        return Err(CoreError::Format);
    }
    let mut out = rev.to_be_bytes().to_vec();
    out.extend_from_slice(&writer);
    out.extend(seal_at_rest(
        key,
        ObjectType::INDEX_ENTRY,
        &[account_id, item_id, &rev.to_be_bytes(), &writer],
        &pad64(entry)?,
    )?);
    Ok(out)
}

/// Open an index entry as `item_id`'s. Returns its version and the entry.
pub(crate) fn open_index(
    key: &Secret32,
    account_id: &[u8; 32],
    item_id: &[u8],
    blob: &[u8],
) -> Result<(Version, Zeroizing<Vec<u8>>)> {
    let mut r = Reader::new(blob);
    let rev = r.u64()?;
    let writer: [u8; 32] = r.array()?;
    let pt = open_at_rest(
        key,
        ObjectType::INDEX_ENTRY,
        &[account_id, item_id, &rev.to_be_bytes(), &writer],
        r.rest(),
    )
    .map_err(|_| CoreError::WrongDocument)?;
    if rev == 0 {
        return Err(CoreError::Format);
    }
    Ok(((rev, writer), unpad(&pt)?))
}

/// The highest version this device has seen per record id.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Revisions(pub(crate) BTreeMap<Vec<u8>, Version>);

impl core::fmt::Debug for Revisions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // ids are item ids: don't print them
        write!(f, "Revisions({} records)", self.0.len())
    }
}

impl Revisions {
    /// Accept `v` for `id`: refuses anything older than seen, remembers the highest.
    pub(crate) fn accept(&mut self, id: &[u8], v: Version) -> Result<()> {
        if self.0.get(id).is_some_and(|seen| v < *seen) {
            return Err(CoreError::Rollback);
        }
        self.0.insert(id.to_vec(), v);
        Ok(())
    }

    /// The highest version seen for `id`.
    pub(crate) fn seen(&self, id: &[u8]) -> Option<Version> {
        self.0.get(id).copied()
    }

    pub(crate) fn seal(&self, key: &Secret32, device_id: &[u8; 32], c: u64) -> Result<Vec<u8>> {
        let mut body = Zeroizing::new(Vec::new());
        for (id, (rev, writer)) in &self.0 {
            humid_pq2::encoding::lp_push(&mut body, id)?;
            body.extend_from_slice(&rev.to_be_bytes());
            body.extend_from_slice(writer);
        }
        let mut out = c.to_be_bytes().to_vec();
        out.extend(seal_at_rest(
            key,
            ObjectType::RECORD_REVS,
            &[device_id, &c.to_be_bytes()],
            &body,
        )?);
        Ok(out)
    }

    /// Open; returns the record and its counter.
    pub(crate) fn open(key: &Secret32, device_id: &[u8; 32], blob: &[u8]) -> Result<(Self, u64)> {
        let mut r = Reader::new(blob);
        let c = r.u64()?;
        let pt = open_at_rest(
            key,
            ObjectType::RECORD_REVS,
            &[device_id, &c.to_be_bytes()],
            r.rest(),
        )?;
        let mut r = Reader::new(&pt);
        let mut m = BTreeMap::new();
        while r.remaining() > 0 {
            let id = r.lp(MAX_ID)?.to_vec();
            let rev = r.u64()?;
            let writer = r.array()?;
            m.insert(id, (rev, writer));
        }
        Ok((Self(m), c))
    }
}

/// Setting names: `[a-z0-9-]{1,64}`, since they become file names (review L4).
pub(crate) fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(CoreError::Format);
    }
    Ok(())
}

/// Seal a device-only setting.
pub(crate) fn seal_setting(
    key: &Secret32,
    device_id: &[u8; 32],
    name: &str,
    value: &[u8],
) -> Result<Vec<u8>> {
    check_name(name)?;
    if value.len() > MAX_RECORD {
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
    check_name(name)?;
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

    const A: [u8; 32] = [0xA; 32];
    const B: [u8; 32] = [0xB; 32];

    #[test]
    fn index_entries_are_bound_and_versioned() {
        let k = Secret32::random().unwrap();
        let a = [3u8; 32];
        let e1 = seal_index(&k, &a, b"item-1", (1, A), b"Passport").unwrap();
        let e2 = seal_index(&k, &a, b"item-1", (2, A), b"Passport (renamed)").unwrap();
        let (v, pt) = open_index(&k, &a, b"item-1", &e2).unwrap();
        assert_eq!((v, &pt[..]), ((2, A), &b"Passport (renamed)"[..]));
        // moved to another item, or another account: refused (audit M2)
        assert!(open_index(&k, &a, b"item-2", &e1).is_err());
        assert!(open_index(&k, &[4u8; 32], b"item-1", &e1).is_err());
        // rev or writer rewritten in the clear prefix: refused
        for i in [7, 8, 39] {
            let mut e = e1.clone();
            e[i] ^= 1;
            assert!(open_index(&k, &a, b"item-1", &e).is_err(), "{i}");
        }
        // served back older than seen: refused
        let mut revs = Revisions::default();
        revs.accept(b"item-1", (2, A)).unwrap();
        let (old, _) = open_index(&k, &a, b"item-1", &e1).unwrap();
        assert_eq!(revs.accept(b"item-1", old), Err(CoreError::Rollback));
        // same rev from two writers: totally ordered (review M7)
        revs.accept(b"item-1", (2, B)).unwrap();
        assert_eq!(revs.accept(b"item-1", (2, A)), Err(CoreError::Rollback));
        // padding hides short lengths
        assert_eq!(
            seal_index(&k, &a, b"i", (1, A), b"a").unwrap().len(),
            seal_index(&k, &a, b"i", (1, A), b"abcdefgh").unwrap().len()
        );
        assert_eq!(format!("{revs:?}"), "Revisions(1 records)");
    }

    #[test]
    fn revisions_and_settings_round_trip() {
        let k = Secret32::random().unwrap();
        let d = [1u8; 32];
        let mut r = Revisions::default();
        r.accept(b"x", (5, A)).unwrap();
        r.accept(b"yy", (1, B)).unwrap();
        let blob = r.seal(&k, &d, 9).unwrap();
        assert_eq!(Revisions::open(&k, &d, &blob).unwrap(), (r.clone(), 9));
        assert!(Revisions::open(&k, &[2u8; 32], &blob).is_err());
        // the counter in the clear is authenticated
        let mut bumped = blob.clone();
        bumped[7] = 10;
        assert!(Revisions::open(&k, &d, &bumped).is_err());
        let s = seal_setting(&k, &d, "duress", b"gesture-3").unwrap();
        assert_eq!(
            &open_setting(&k, &d, "duress", &s).unwrap()[..],
            b"gesture-3"
        );
        assert!(open_setting(&k, &d, "other", &s).is_err());
    }

    #[test]
    fn setting_names_are_file_safe() {
        for bad in [
            "",
            "../wrap-0",
            "a/b",
            "A",
            "x y",
            &"a".repeat(65),
            "wrap\0",
        ] {
            assert_eq!(check_name(bad), Err(CoreError::Format), "{bad:?}");
        }
        check_name("duress-gesture-2").unwrap();
    }
}
