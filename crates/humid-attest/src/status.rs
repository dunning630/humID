//! Google's attestation status list: certificates in Android attestation chains that Google
//! revoked or suspended (leaked device keys, compromised factory keys).
//! https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
//!
//! Google serves the list as plain JSON over HTTPS (`https://android.googleapis.com/attestation/status`);
//! it carries no signature of its own. The server keeps a **cached copy that the operator's
//! fetcher signs** (the `status_signer` key named in the signed policy) together with its
//! fetch time, so a copy on disk can't be edited or backdated without the fetcher's key, and
//! a stale copy fails closed:
//!
//! ```text
//! cached = lp(fetched_at u64 ‖ google_json, sig)      sig = signer over "HUMID-PQ2 attestation-status" ‖ that
//! ```
//!
//! The signature itself is the server's (its suite lives in humid-server's crypto module);
//! this module parses Google's JSON and enforces the age rule.

use std::collections::HashSet;

use crate::{Result, refuse};

/// Google's URL.
pub const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";
/// The largest list accepted (today's is about 100 KiB).
pub const MAX_LIST: usize = 8 << 20;
/// A copy older than this is stale (Google adds entries as keys leak; the fetcher refreshes
/// every 6 hours). The 4.x default.
pub const DEFAULT_MAX_AGE_MS: i64 = 48 * 3_600_000;

/// A copy of the list, with when it was fetched.
#[derive(Clone, Debug, Default)]
pub struct StatusList {
    serials: HashSet<String>,
    fetched_at: Option<i64>,
    max_age_ms: i64,
    required: bool,
}

#[derive(serde::Deserialize)]
struct Json {
    entries: std::collections::BTreeMap<String, Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    status: String,
}

impl StatusList {
    /// No list yet. With `required`, every check fails closed (`status_unavailable`) until a
    /// copy arrives; without, an empty list (development).
    #[must_use]
    pub fn empty(required: bool, max_age_ms: i64) -> Self {
        Self {
            serials: HashSet::new(),
            fetched_at: None,
            max_age_ms,
            required,
        }
    }

    /// Parse Google's JSON (`{"entries": {"<serial hex>": {"status": "REVOKED" | "SUSPENDED", …}}}`),
    /// fetched at `fetched_at` (ms).
    ///
    /// # Errors
    /// `bad_status_list`: not a status list, too large, or a serial that isn't hex.
    pub fn parse(json: &[u8], fetched_at: i64, required: bool, max_age_ms: i64) -> Result<Self> {
        let bad = refuse(
            "bad_status_list",
            "That isn't Google's attestation status list.",
        );
        if json.len() > MAX_LIST {
            return Err(bad);
        }
        let j: Json = serde_json::from_slice(json).map_err(|_| bad)?;
        let mut serials = HashSet::new();
        for (serial, e) in j.entries {
            if serial.is_empty()
                || serial.len() > 64
                || !serial.bytes().all(|c| c.is_ascii_hexdigit())
            {
                return Err(bad);
            }
            if e.status == "REVOKED" || e.status == "SUSPENDED" {
                serials.insert(crate::x509::serial_key(&serial));
            }
        }
        Ok(Self {
            serials,
            fetched_at: Some(fetched_at),
            max_age_ms,
            required,
        })
    }

    /// When this copy was fetched.
    #[must_use]
    pub fn fetched_at(&self) -> Option<i64> {
        self.fetched_at
    }

    /// How many certificates are listed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.serials.len()
    }

    /// Nothing listed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.serials.is_empty()
    }

    /// Whether the copy is usable at `now`: present, not dated in the future, not stale.
    ///
    /// # Errors
    /// `status_unavailable`, `status_stale` (only when required).
    pub fn usable(&self, now: i64) -> Result<()> {
        if !self.required {
            return Ok(());
        }
        match self.fetched_at {
            None => Err(refuse(
                "status_unavailable",
                "Google's list of revoked phone keys hasn't been fetched yet, so phones can't be checked. Try again shortly.",
            )),
            Some(at) if at > now + 5 * 60_000 || now - at > self.max_age_ms => Err(refuse(
                "status_stale",
                "Google's list of revoked phone keys is out of date, so phones can't be checked. The server's operator needs to restore its fetch.",
            )),
            Some(_) => Ok(()),
        }
    }

    /// Check a chain's serials (as [`crate::x509::serial_key`] writes them).
    ///
    /// # Errors
    /// `revoked` when one is listed; `status_unavailable` / `status_stale` as [`Self::usable`].
    pub fn check(&self, serials: &[String], now: i64) -> Result<()> {
        self.usable(now)?;
        if serials.iter().any(|s| self.serials.contains(s)) {
            return Err(refuse(
                "revoked",
                "Google has revoked this phone's secure-chip certificate (a leaked or compromised key).",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_and_suspended_count_leading_zeros_dont() {
        let s = StatusList::parse(
            br#"{"entries":{"00Ab12":{"status":"REVOKED","reason":"KEY_COMPROMISE"},"77":{"status":"SUSPENDED"},"88":{"status":"VALID","comment":"x"}}}"#,
            0,
            true,
            1000,
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.check(&["ab12".into()], 0).unwrap_err().code, "revoked");
        assert_eq!(s.check(&["77".into()], 0).unwrap_err().code, "revoked");
        s.check(&["88".into(), "1".into()], 0).unwrap();
        assert!(StatusList::parse(b"{}", 0, true, 1).is_err());
        assert!(
            StatusList::parse(br#"{"entries":{"zz":{"status":"REVOKED"}}}"#, 0, true, 1).is_err()
        );
    }

    #[test]
    fn required_means_present_and_fresh() {
        let none = StatusList::empty(true, 1000);
        assert_eq!(none.check(&[], 0).unwrap_err().code, "status_unavailable");
        StatusList::empty(false, 1000).check(&[], 0).unwrap();
        let s = StatusList::parse(br#"{"entries":{}}"#, 10_000, true, 1000).unwrap();
        s.check(&[], 11_000).unwrap();
        assert_eq!(s.check(&[], 11_001).unwrap_err().code, "status_stale");
        assert_eq!(
            s.check(&[], 10_000 - 5 * 60_000 - 1).unwrap_err().code,
            "status_stale",
            "a copy dated in the future isn't believed"
        );
    }
}
