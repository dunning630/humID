//! The four units, the clock every unit reads, and the run mode.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Which unit a process (or a TLS peer) is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Edge + gateway: the only unit on the internet.
    Front,
    /// Identity + vault + ledger + recovery.
    Core,
    /// The key-share service (the split).
    Keys,
    /// Access + relay: knows no accounts.
    Anon,
}

impl Role {
    /// Every role.
    pub const ALL: [Role; 4] = [Role::Front, Role::Core, Role::Keys, Role::Anon];

    /// Lower-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Front => "front",
            Role::Core => "core",
            Role::Keys => "keys",
            Role::Anon => "anon",
        }
    }

    /// Parse a lower-case name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Which roles may call this unit over internal TLS (SERVER.md §2.5).
    #[must_use]
    pub fn callers(self) -> &'static [Role] {
        match self {
            Role::Front => &[],
            Role::Core | Role::Anon => &[Role::Front],
            Role::Keys => &[Role::Core],
        }
    }
}

/// How strictly a unit runs. Comes from the signed policy, never from a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Development and pilot: software HSM allowed, unattested devices allowed.
    Development,
    /// Production: refuses the software HSM, unattested devices and any stub in a required path.
    Production,
}

/// Milliseconds since the Unix epoch, as every unit sees them.
///
/// The system clock is the wall clock at start plus a monotonic elapsed time, so changing
/// the machine's clock while a unit runs can't stretch a Check-in deadline or a recovery
/// wait. Tests use a manual clock they move by hand.
#[derive(Clone)]
pub struct Clock(Arc<ClockInner>);

enum ClockInner {
    System { wall_at_start: i64, start: Instant },
    Manual(AtomicI64),
}

impl Clock {
    /// The system clock.
    #[must_use]
    pub fn system() -> Self {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Clock(Arc::new(ClockInner::System {
            wall_at_start: wall,
            start: Instant::now(),
        }))
    }

    /// A clock that moves only when told to (tests).
    #[must_use]
    pub fn manual(start_ms: i64) -> Self {
        Clock(Arc::new(ClockInner::Manual(AtomicI64::new(start_ms))))
    }

    /// Now, in ms.
    #[must_use]
    pub fn now(&self) -> i64 {
        match &*self.0 {
            ClockInner::System {
                wall_at_start,
                start,
            } => wall_at_start + i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX / 2),
            ClockInner::Manual(t) => t.load(Ordering::SeqCst),
        }
    }

    /// Move a manual clock forward (no effect on the system clock).
    pub fn advance(&self, ms: i64) {
        if let ClockInner::Manual(t) = &*self.0 {
            t.fetch_add(ms, Ordering::SeqCst);
        }
    }

    /// Today as `YYYY-MM-DD` (anon keeps days only, never times).
    #[must_use]
    pub fn day(&self) -> String {
        day_of(self.now())
    }
}

/// `YYYY-MM-DD` for a time in ms.
#[must_use]
pub fn day_of(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

/// Time constants (ms).
pub mod ms {
    /// One second.
    pub const SECOND: i64 = 1_000;
    /// One minute.
    pub const MINUTE: i64 = 60_000;
    /// One hour.
    pub const HOUR: i64 = 3_600_000;
    /// One day.
    pub const DAY: i64 = 86_400_000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_round_trip_and_callers() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::Keys.callers(), &[Role::Core]);
        assert!(
            Role::Front.callers().is_empty(),
            "nothing calls front over internal TLS"
        );
        assert!(
            !Role::Core.callers().contains(&Role::Anon),
            "anon can't reach core"
        );
    }

    #[test]
    fn days() {
        assert_eq!(day_of(0), "1970-01-01");
        assert_eq!(day_of(1_761_177_600_000), "2025-10-23");
        assert_eq!(day_of(951_782_400_000), "2000-02-29");
    }

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = Clock::manual(1000);
        assert_eq!(c.now(), 1000);
        c.advance(500);
        assert_eq!(c.now(), 1500);
        let s = Clock::system();
        let a = s.now();
        assert!(s.now() >= a);
    }
}
