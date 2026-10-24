//! `humid-server-core dev-setup <dir> [database-url]`: everything four units need to run on
//! one development machine — an internal CA and ML-DSA-87 leaves, a development identity root
//! and a signed development policy, a software-HSM seed per unit, and a `server.toml` each.
//!
//! **Development only.** The identity root's seed is left in `<dir>/root/` so the policy can be
//! re-signed; in production the root lives offline and signs at a ceremony. The policy says
//! `mode = development`, which the app shows as an unsafe server.

use std::path::Path;

use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef, SoftHsm};
use crate::policy;
use crate::tls::DevCa;
use crate::unit::{Clock, Role};

/// Ports used on loopback.
pub const PORTS: [(Role, u16); 4] = [
    (Role::Front, 8443),
    (Role::Core, 9441),
    (Role::Keys, 9442),
    (Role::Anon, 9443),
];

fn port(r: Role) -> u16 {
    PORTS.iter().find(|(x, _)| *x == r).map_or(0, |(_, p)| *p)
}

fn w(p: &Path, s: &[u8]) -> Result<()> {
    std::fs::write(p, s).map_err(|e| Error::internal(format!("{}: {e}", p.display())))
}

/// Write a development setup into `dir` (which must not exist yet).
///
/// # Errors
/// `dir` exists; a file can't be written.
pub fn write(dir: &Path, database_url: &str) -> Result<()> {
    if dir.exists() {
        return Err(Error::conflict(
            "exists",
            format!(
                "{} already exists; dev-setup won't overwrite keys.",
                dir.display()
            ),
        ));
    }
    let mk = |p: &Path| {
        std::fs::create_dir_all(p).map_err(|e| Error::internal(format!("{}: {e}", p.display())))
    };
    mk(dir)?;
    // one soft HSM per unit, each in its own data directory
    let data = |r: Role| dir.join(r.as_str()).join("data");
    let mut hsms = vec![];
    for r in Role::ALL {
        mk(&data(r))?;
        hsms.push(SoftHsm::open_dir(&data(r))?);
    }
    let (core, keys, anon) = (&hsms[1], &hsms[2], &hsms[3]);
    // the development identity root
    mk(&dir.join("root"))?;
    let root = SoftHsm::open_dir(&dir.join("root"))?;
    w(
        &dir.join("identity-root.pub"),
        &root.dual_public(KeyRef::IdentityRoot)?.to_bytes(),
    )?;
    let p = policy::development(
        1,
        Clock::system().now(),
        policy::unit_keys_from(core, keys, anon)?,
    );
    let bytes = serde_json::to_vec_pretty(&p).map_err(|e| Error::internal(e.to_string()))?;
    w(&dir.join("policy.json"), &bytes)?;
    w(&dir.join("policy.json.sig"), &policy::sign(&root, &bytes)?)?;
    // certificates
    let ca = DevCa::new()?;
    let certs = dir.join("tls");
    mk(&certs)?;
    for r in Role::ALL {
        ca.issue(r)?.write(&certs, r.as_str())?;
    }
    // development: front's outer listener reuses its unit leaf; production uses a certificate
    // for the public name (ECDSA P-384 until clients verify ML-DSA chains, SERVER.md §8)
    for r in Role::ALL {
        let units = match r {
            Role::Front => format!(
                "core = \"https://127.0.0.1:{}\"\nanon = \"https://127.0.0.1:{}\"\n",
                port(Role::Core),
                port(Role::Anon)
            ),
            Role::Core => format!("keys = \"https://127.0.0.1:{}\"\n", port(Role::Keys)),
            _ => String::new(),
        };
        let db = if r == Role::Front {
            String::new()
        } else {
            format!("database = {{ url = \"{database_url}\" }}\n")
        };
        let public = if r == Role::Front {
            "public_tls = { cert = \"tls/front.pem\", key = \"tls/front.key\" }\n".to_string()
        } else {
            String::new()
        };
        let toml = format!(
            "# {name} unit — development (docs/v5/SERVER.md). Security settings are in policy.json, not here.\n\
             role = \"{name}\"\nlisten = \"127.0.0.1:{port}\"\ndata_dir = \"{name}/data\"\npolicy = \"policy.json\"\n\
             identity_root = \"identity-root.pub\"\nhsm = {{ kind = \"soft\" }}\n\
             tls = {{ cert = \"tls/{name}.pem\", key = \"tls/{name}.key\", ca = \"tls/ca.pem\" }}\n{public}{db}\n[units]\n{units}",
            name = r.as_str(),
            port = port(r),
        );
        w(&dir.join(format!("{}.toml", r.as_str())), toml.as_bytes())?;
    }
    Ok(())
}
