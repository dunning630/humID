//! # humid-server
//!
//! The HumID 5.0 server: four units sharing this library (docs/v5/SERVER.md).
//!
//! | Unit | Module | Owns |
//! | --- | --- | --- |
//! | front | [`front`] | outer TLS, HTP termination (stubbed), rate limits, the route allow-list |
//! | core | [`core`] | accounts, devices, sessions, documents, the ledger and public log, recovery |
//! | keys | [`keys`] | one sealed key share per document; Check-in |
//! | anon | [`anon`] | access passes, post tokens, the relay; knows no accounts |
//!
//! Shared plumbing: [`crypto`] (the only door to HUMID-PQ2), [`hsm`], [`policy`], [`proofs`],
//! [`statement`], [`tls`], [`net`], [`db`], [`retention`], [`limits`].
//!
//! The rule: **every unit verifies the holder's own live proof itself**; between units, only
//! HSM-signed statements, never a caller's network position.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod hsm;
pub mod limits;
pub mod net;
pub mod policy;
pub mod proofs;
pub mod retention;
pub mod statement;
pub mod stubs;
pub mod tls;
pub mod unit;
pub mod wire;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use error::{Error, Result};

#[cfg(test)]
mod boundaries {
    /// Source of every module, for the boundary checks below.
    const SOURCES: &[(&str, &str)] = &[
        ("config", include_str!("config.rs")),
        ("crypto", include_str!("crypto.rs")),
        ("db", include_str!("db.rs")),
        ("error", include_str!("error.rs")),
        ("hsm", include_str!("hsm.rs")),
        ("limits", include_str!("limits.rs")),
        ("net", include_str!("net.rs")),
        ("policy", include_str!("policy.rs")),
        ("proofs", include_str!("proofs.rs")),
        ("retention", include_str!("retention.rs")),
        ("statement", include_str!("statement.rs")),
        ("stubs", include_str!("stubs.rs")),
        ("tls", include_str!("tls.rs")),
        ("unit", include_str!("unit.rs")),
        ("wire", include_str!("wire.rs")),
    ];

    #[test]
    fn only_crypto_rs_touches_the_suite() {
        for (name, src) in SOURCES {
            if *name == "crypto" || *name == "error" {
                continue; // error.rs maps humid_pq2::Error, nothing more
            }
            assert!(
                !src.contains("humid_pq2"),
                "{name}.rs uses humid_pq2 directly; go through crypto.rs"
            );
            assert!(
                !src.contains("blind_rsa_signatures"),
                "{name}.rs uses a crypto crate directly"
            );
        }
    }
}
