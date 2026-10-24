//! The gate designs (CORE.md §5) and the gate-mode setting that picks one.

use serde::Serialize;

/// How the hardware makes `HW` and how many prompts a set of operations costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Design {
    /// iOS 26+: Secure Enclave ML-KEM-1024 decapsulation and P-256 key agreement, the
    /// liveness signatures and the App Attest assertion, all in one `LAContext`.
    Ios,
    /// Android proposal A: every wrap and document target imports a fresh per-use HMAC key
    /// whose bytes the core picked (the value is known at once). Each Keystore operation
    /// is its own `CryptoObject`, so each costs a prompt: an unlock is the HMAC plus the
    /// P-256 liveness signature, two prompts.
    A,
    /// Android proposal B: the same per-use keys, every operation begun first, one prompt
    /// bound to the first operation's handle (`CryptoObject(long)`, API 35+); then every
    /// operation is tried. Works only if one authentication unlocks them all.
    B,
    /// Android proposal C (experiment, **relaxes V5.md's "no time window"**): A's imported
    /// HMAC keys accept any strong biometric in the last second; the liveness key stays per
    /// use and its `CryptoObject` is the one prompt. Needs the owner's sign-off to ship.
    C,
    /// Android proposal D: one ML-DSA-87 Keystore key; `HW` is a hash of its signature over
    /// a per-wrap message. Works only if Keystore's ML-DSA signing is deterministic (each
    /// signature is also its own `CryptoObject`, so its own prompt).
    D,
}

impl Design {
    /// Every design.
    pub const ALL: [Design; 5] = [Design::Ios, Design::A, Design::B, Design::C, Design::D];

    /// The id used in settings, the wire and reports.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Design::Ios => "ios",
            Design::A => "a",
            Design::B => "b",
            Design::C => "c",
            Design::D => "d",
        }
    }

    /// The design an id names.
    #[must_use]
    pub fn from_id(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.id() == s)
    }

    /// The byte the native side receives.
    #[must_use]
    pub fn wire(self) -> u8 {
        match self {
            Design::Ios => 0,
            Design::A => 1,
            Design::B => 2,
            Design::C => 3,
            Design::D => 4,
        }
    }

    /// Whether this design runs on Android (else iOS).
    #[must_use]
    pub fn android(self) -> bool {
        self != Design::Ios
    }

    /// How many ops one `authorize` is planned for (GateInfo::max_ops). For A and D this is
    /// what one call carries, not one prompt: their reports show the prompts it really took.
    #[must_use]
    pub fn max_ops(self) -> usize {
        match self {
            Design::Ios => 64,
            Design::A | Design::B | Design::D => 8,
            // every HMAC must finish inside the 1 s window
            Design::C => 6,
        }
    }

    /// Whether targets import a per-use HMAC key whose value is known at once.
    #[must_use]
    pub fn imports(self) -> bool {
        matches!(self, Design::A | Design::B | Design::C)
    }

    /// True for the design that relaxes the spec and needs the owner's sign-off.
    #[must_use]
    pub fn experimental(self) -> bool {
        self == Design::C
    }

    /// One line for the hardware check screen.
    #[must_use]
    pub fn summary(self) -> &'static str {
        match self {
            Design::Ios => {
                "Secure Enclave ML-KEM-1024 + P-256 agreement, liveness signatures and App Attest in one Face ID check"
            }
            Design::A => {
                "A fresh per-use HMAC key per wrap and document; one prompt per Keystore operation"
            }
            Design::B => {
                "Per-use keys, every operation begun, one prompt for the first operation's handle"
            }
            Design::C => {
                "Experiment: A's keys usable for 1 s after the liveness prompt (relaxes the spec)"
            }
            Design::D => {
                "ML-DSA-87 Keystore signature over a per-wrap message as the factor (needs deterministic signing)"
            }
        }
    }

    /// The designs a platform offers.
    #[must_use]
    pub fn for_platform(android: bool) -> Vec<Design> {
        Self::ALL
            .into_iter()
            .filter(|d| d.android() == android)
            .collect()
    }

    /// The design a release build uses until the device lab picks one (CORE.md §10.1):
    /// iOS has only one; on Android, A is the one that keeps the spec (per-use keys, no
    /// window), at the cost of a second prompt.
    #[must_use]
    pub fn default_for(android: bool) -> Self {
        if android { Design::A } else { Design::Ios }
    }
}

/// The gate-mode setting: the design the app's gate uses. Release builds always use
/// [`Design::default_for`]; development and hardware-check builds honour the file the
/// hardware check screen writes (`gate-mode` in the app's data directory).
#[must_use]
pub fn configured(android: bool, file: Option<&str>) -> Design {
    let chosen = file
        .map(str::trim)
        .and_then(Design::from_id)
        .filter(|d| d.android() == android);
    if cfg!(any(debug_assertions, humid_hwcheck)) {
        chosen.unwrap_or_else(|| Design::default_for(android))
    } else {
        Design::default_for(android)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_wire_bytes_are_distinct() {
        for d in Design::ALL {
            assert_eq!(Design::from_id(d.id()), Some(d));
        }
        let mut w: Vec<u8> = Design::ALL.iter().map(|d| d.wire()).collect();
        w.dedup();
        assert_eq!(w.len(), 5);
        assert_eq!(Design::from_id("e"), None);
    }

    #[test]
    fn platforms_and_the_setting() {
        assert_eq!(Design::for_platform(false), vec![Design::Ios]);
        assert_eq!(
            Design::for_platform(true),
            vec![Design::A, Design::B, Design::C, Design::D]
        );
        // a design for the other platform, or junk, falls back to the default
        assert_eq!(configured(true, Some("ios")), Design::A);
        assert_eq!(configured(false, Some("b")), Design::Ios);
        assert_eq!(configured(true, Some("zz")), Design::A);
        assert_eq!(configured(true, None), Design::A);
        // tests are a debug build: the file counts
        assert_eq!(configured(true, Some(" d\n")), Design::D);
    }

    #[test]
    fn only_c_is_experimental() {
        for d in Design::ALL {
            assert_eq!(d.experimental(), d == Design::C);
        }
    }
}
