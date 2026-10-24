//! What isn't built yet, in one list (SERVER.md §12).
//!
//! Each stub answers a typed `not_implemented` at run time. This list is what a unit checks
//! at start-up: in production mode, a unit whose required path still has a stub refuses to
//! start, naming it, rather than running half-built.

use crate::error::{Error, Result};
use crate::unit::{Mode, Role};

/// One stub.
pub struct Stub {
    /// The units whose path it is in.
    pub units: &'static [Role],
    /// What isn't built.
    pub what: &'static str,
    /// What it waits on.
    pub waiting_on: &'static str,
    /// Whether production can't run without it.
    pub blocks_production: bool,
}

/// Every stub on this branch.
pub const STUBS: &[Stub] = &[
    Stub {
        units: &[Role::Front],
        what: "HTP/2 handshake and frames",
        waiting_on: "the HTP/2 specification",
        blocks_production: true,
    },
    Stub {
        units: &[Role::Core],
        what: "verifying Android key attestation and Apple App Attest (and per-check assertions)",
        waiting_on: "the Rust port of packages/attest",
        blocks_production: true,
    },
    Stub {
        units: &[Role::Core],
        what: "verifying a document envelope's account signature server-side",
        waiting_on: "the humid-core envelope v2 format",
        blocks_production: false,
    },
    Stub {
        units: &[Role::Core],
        what: "passport (ID chip) recovery evidence",
        waiting_on: "a second share operator, and ICAO passive authentication in Rust",
        blocks_production: false,
    },
    Stub {
        units: &[Role::Core],
        what: "security-key (FIDO) recovery evidence",
        waiting_on: "CTAP / hmac-secret verification in Rust",
        blocks_production: false,
    },
    Stub {
        units: &[Role::Anon],
        what: "live stamps",
        waiting_on: "stamp v2 (partially blind RSA with epoch metadata)",
        blocks_production: false,
    },
    Stub {
        units: &[Role::Anon],
        what: "the push sender (APNs / FCM)",
        waiting_on: "push provider accounts",
        blocks_production: false,
    },
    Stub {
        units: &Role::ALL,
        what: "the PKCS#11 HSM backend",
        waiting_on: "the choice of HSM model",
        blocks_production: true,
    },
];

/// Refuse a production start while a blocking stub is in this unit's path.
///
/// # Errors
/// `stub_in_production`, naming the first one.
pub fn check(unit: Role, mode: Mode) -> Result<()> {
    if mode != Mode::Production {
        return Ok(());
    }
    if let Some(s) = STUBS
        .iter()
        .find(|s| s.blocks_production && s.units.contains(&unit))
    {
        return Err(Error::forbidden(
            "stub_in_production",
            format!(
                "{} isn't built yet ({}), so this unit can't run in production.",
                s.what, s.waiting_on
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_is_refused_while_blocking_stubs_remain() {
        for r in Role::ALL {
            assert!(check(r, Mode::Development).is_ok());
            assert_eq!(
                check(r, Mode::Production).unwrap_err().code(),
                "stub_in_production"
            );
        }
    }
}
