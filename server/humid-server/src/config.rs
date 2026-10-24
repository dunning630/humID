//! `server.toml`: where things are. Nothing here can weaken a check — every security
//! setting is in the signed policy (policy.rs).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::hsm::HsmConfig;
use crate::unit::Role;

/// One unit's configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which unit this file configures (a core binary refuses a keys file).
    pub role: Role,
    /// Where it listens.
    pub listen: SocketAddr,
    /// Its own data directory (policy state, soft-HSM key in development).
    pub data_dir: PathBuf,
    /// The signed policy (`policy.json`; the signature is `policy.json.sig` beside it).
    pub policy: PathBuf,
    /// The identity root's public key (dual verifying key encoding).
    pub identity_root: PathBuf,
    /// The HSM.
    pub hsm: HsmConfig,
    /// Internal TLS identity.
    pub tls: TlsFiles,
    /// The outer TLS certificate (front only).
    #[serde(default)]
    pub public_tls: Option<PublicTlsFiles>,
    /// PostgreSQL (core, keys, anon).
    #[serde(default)]
    pub database: Option<Database>,
    /// The other units this one calls, by role: `https://host:port`.
    #[serde(default)]
    pub units: BTreeMap<Role, String>,
}

/// Internal TLS files (PEM).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    /// This unit's certificate chain (leaf, then the CA).
    pub cert: PathBuf,
    /// Its PKCS#8 key.
    pub key: PathBuf,
    /// The internal CA.
    pub ca: PathBuf,
}

/// Outer TLS files (PEM).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTlsFiles {
    /// Certificate chain for the public name.
    pub cert: PathBuf,
    /// Its key.
    pub key: PathBuf,
}

/// Database connection.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    /// `host=/run/postgresql dbname=humid_core user=humid_core` or a `postgres://` URL. In
    /// production the host must be a Unix socket directory or loopback (no network hop).
    pub url: String,
    /// Pool size.
    #[serde(default = "default_pool")]
    pub pool: usize,
}

fn default_pool() -> usize {
    16
}

impl Config {
    /// Read and check a `server.toml`.
    ///
    /// # Errors
    /// Unreadable, malformed, or for another role.
    pub fn load(path: &Path, expect: Role) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::internal(format!("{}: {e}", path.display())))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse(&text, base, expect)
    }

    /// Parse, resolving relative paths against `base`.
    ///
    /// # Errors
    /// Malformed, or for another role.
    pub fn parse(text: &str, base: &Path, expect: Role) -> Result<Self> {
        let mut c: Config = toml::from_str(text)
            .map_err(|e| Error::bad("bad_config", format!("server.toml: {e}")))?;
        if c.role != expect {
            return Err(Error::bad(
                "bad_config",
                format!(
                    "this file configures {}, not {}",
                    c.role.as_str(),
                    expect.as_str()
                ),
            ));
        }
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut c.data_dir);
        fix(&mut c.policy);
        fix(&mut c.identity_root);
        fix(&mut c.tls.cert);
        fix(&mut c.tls.key);
        fix(&mut c.tls.ca);
        if let Some(p) = c.public_tls.as_mut() {
            fix(&mut p.cert);
            fix(&mut p.key);
        }
        if let HsmConfig::Pkcs11 { module } = &mut c.hsm {
            fix(module);
        }
        for (role, url) in &c.units {
            if !url.starts_with("https://") {
                return Err(Error::bad(
                    "bad_config",
                    format!("units.{}: internal hops are https only", role.as_str()),
                ));
            }
        }
        if expect != Role::Front && c.database.is_none() {
            return Err(Error::bad("bad_config", "this unit needs [database]"));
        }
        Ok(c)
    }
}

/// True when a libpq connection string or URL points at a Unix socket or loopback.
#[must_use]
pub fn database_is_local(url: &str) -> bool {
    let Ok(cfg) = url.parse::<tokio_postgres::Config>() else {
        return false;
    };
    cfg.get_hosts().iter().all(|h| match h {
        tokio_postgres::config::Host::Unix(_) => true,
        tokio_postgres::config::Host::Tcp(name) => {
            name == "localhost" || name == "127.0.0.1" || name == "::1"
        }
    }) && !cfg.get_hosts().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE: &str = r#"
role = "core"
listen = "127.0.0.1:8443"
data_dir = "data"
policy = "policy.json"
identity_root = "root.pub"
hsm = { kind = "soft" }
tls = { cert = "core.pem", key = "core.key", ca = "ca.pem" }
database = { url = "host=/run/postgresql dbname=humid_core" }
[units]
keys = "https://keys.example:8443"
"#;

    #[test]
    fn parses_and_resolves_paths() {
        let c = Config::parse(CORE, Path::new("/etc/humid"), Role::Core).unwrap();
        assert_eq!(c.data_dir, Path::new("/etc/humid/data"));
        assert_eq!(
            c.units.get(&Role::Keys).unwrap(),
            "https://keys.example:8443"
        );
        assert!(
            Config::parse(CORE, Path::new("/etc/humid"), Role::Keys).is_err(),
            "another role's file is refused"
        );
    }

    #[test]
    fn refuses_plain_http_and_unknown_settings() {
        let http = CORE.replace("https://keys", "http://keys");
        assert!(Config::parse(&http, Path::new("/"), Role::Core).is_err());
        let extra = format!("{CORE}\ntrust_forwarded = true\n");
        assert!(
            Config::parse(&extra, Path::new("/"), Role::Core).is_err(),
            "nothing unknown, so nothing can weaken a check"
        );
    }

    #[test]
    fn local_database() {
        assert!(database_is_local("host=/run/postgresql dbname=x"));
        assert!(database_is_local("postgres://u@127.0.0.1/x"));
        assert!(!database_is_local("postgres://u@db.example/x"));
    }
}
