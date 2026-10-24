//! TLS for every hop (SERVER.md §8).
//!
//! * **Internal** (unit ↔ unit, loopback included): TLS 1.3 only, one group —
//!   SecP384r1MLKEM1024 (0x11ED) — and ML-DSA-87 certificates from one internal CA. Mutual:
//!   the client certificate's DNS name says which unit is calling (`core.unit.humid.internal`).
//! * **Outer** (front ↔ internet): TLS 1.3 only, X25519MLKEM768 required with
//!   SecP384r1MLKEM1024 offered first. A classical-only client fails the handshake.
//!
//! rustls ships the ML-KEM-768 hybrids only, so SecP384r1MLKEM1024 is built here from
//! aws-lc-rs's P-384 and ML-KEM-1024 groups, as draft-kwiatkowski-tls-ecdhe-mlkem lays it
//! out: the ECDH share first, then the ML-KEM share; the secret is ECDH ‖ ML-KEM.

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{self as provider, kx_group};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{NamedGroup, PeerMisbehaved, ProtocolVersion};

use crate::error::{Error, Result};
use crate::unit::Role;

/// The SecP384r1MLKEM1024 codepoint.
pub const SECP384R1_MLKEM1024: u16 = 0x11ED;
const P384_SHARE: usize = 97;
const MLKEM1024_EK: usize = 1568;
const MLKEM1024_CT: usize = 1568;

/// SecP384r1MLKEM1024 as a rustls key-exchange group.
#[derive(Debug)]
pub struct P384MlKem1024;

/// The one instance.
pub static P384_MLKEM1024: &dyn SupportedKxGroup = &P384MlKem1024;

fn bad_share() -> rustls::Error {
    rustls::Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

impl SupportedKxGroup for P384MlKem1024 {
    fn start(&self) -> std::result::Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let ecdh = kx_group::SECP384R1.start()?;
        let kem = provider::kx_group::MLKEM1024.start()?;
        let mut pub_key = ecdh.pub_key().to_vec();
        pub_key.extend_from_slice(kem.pub_key());
        Ok(Box::new(ActiveP384MlKem1024 { ecdh, kem, pub_key }))
    }

    fn start_and_complete(
        &self,
        client_share: &[u8],
    ) -> std::result::Result<CompletedKeyExchange, rustls::Error> {
        if client_share.len() != P384_SHARE + MLKEM1024_EK {
            return Err(bad_share());
        }
        let ecdh = kx_group::SECP384R1.start_and_complete(&client_share[..P384_SHARE])?;
        let kem = provider::kx_group::MLKEM1024.start_and_complete(&client_share[P384_SHARE..])?;
        let mut pub_key = ecdh.pub_key;
        pub_key.extend_from_slice(&kem.pub_key);
        let mut secret = ecdh.secret.secret_bytes().to_vec();
        secret.extend_from_slice(kem.secret.secret_bytes());
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::Unknown(SECP384R1_MLKEM1024)
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveP384MlKem1024 {
    ecdh: Box<dyn ActiveKeyExchange>,
    kem: Box<dyn ActiveKeyExchange>,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveP384MlKem1024 {
    fn complete(self: Box<Self>, peer: &[u8]) -> std::result::Result<SharedSecret, rustls::Error> {
        if peer.len() != P384_SHARE + MLKEM1024_CT {
            return Err(bad_share());
        }
        let a = self.ecdh.complete(&peer[..P384_SHARE])?;
        let b = self.kem.complete(&peer[P384_SHARE..])?;
        let mut secret = a.secret_bytes().to_vec();
        secret.extend_from_slice(b.secret_bytes());
        Ok(SharedSecret::from(secret))
    }
    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::Unknown(SECP384R1_MLKEM1024)
    }
}

/// The internal provider: aws-lc-rs with SecP384r1MLKEM1024 as the only group.
#[must_use]
pub fn internal_provider() -> Arc<CryptoProvider> {
    let mut p = provider::default_provider();
    p.kx_groups = vec![P384_MLKEM1024];
    Arc::new(p)
}

/// The outer provider: SecP384r1MLKEM1024 offered first, X25519MLKEM768 required otherwise.
#[must_use]
pub fn outer_provider() -> Arc<CryptoProvider> {
    let mut p = provider::default_provider();
    p.kx_groups = vec![P384_MLKEM1024, provider::kx_group::X25519MLKEM768];
    Arc::new(p)
}

/// The DNS name in a unit's certificate.
#[must_use]
pub fn unit_dns_name(role: Role) -> String {
    format!("{}.unit.humid.internal", role.as_str())
}

/// One unit's TLS identity: its certificate chain and key, plus the CA it trusts.
pub struct Identity {
    /// Leaf, then the CA.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's PKCS#8 key (ML-DSA-87).
    pub key: PrivatePkcs8KeyDer<'static>,
    /// The internal CA certificate.
    pub ca: CertificateDer<'static>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
            ca: self.ca.clone(),
        }
    }
}

impl Identity {
    /// Load PEM files (`cert` holds the leaf and the CA; `key` the PKCS#8 key).
    ///
    /// # Errors
    /// Missing or malformed files.
    pub fn load(
        cert: &std::path::Path,
        key: &std::path::Path,
        ca: &std::path::Path,
    ) -> Result<Self> {
        use rustls::pki_types::pem::PemObject;
        let chain = CertificateDer::pem_file_iter(cert)
            .map_err(|e| Error::internal(format!("{}: {e}", cert.display())))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::internal(format!("{}: {e}", cert.display())))?;
        let key = PrivatePkcs8KeyDer::from_pem_file(key)
            .map_err(|e| Error::internal(format!("{}: {e}", key.display())))?;
        let ca = CertificateDer::from_pem_file(ca)
            .map_err(|e| Error::internal(format!("{}: {e}", ca.display())))?;
        if chain.is_empty() {
            return Err(Error::internal("empty certificate chain"));
        }
        Ok(Self { chain, key, ca })
    }

    fn roots(&self) -> Result<Arc<rustls::RootCertStore>> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.ca.clone())
            .map_err(|e| Error::internal(format!("internal CA: {e}")))?;
        Ok(Arc::new(roots))
    }

    /// The server side of an internal hop: requires a client certificate from the same CA.
    ///
    /// # Errors
    /// A bad certificate or key.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            self.roots()?,
            internal_provider(),
        )
        .build()
        .map_err(|e| Error::internal(format!("client verifier: {e}")))?;
        let cfg = rustls::ServerConfig::builder_with_provider(internal_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::internal(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                self.chain.clone(),
                PrivateKeyDer::Pkcs8(self.key.clone_key()),
            )
            .map_err(|e| Error::internal(format!("server certificate: {e}")))?;
        Ok(Arc::new(cfg))
    }

    /// The client side of an internal hop.
    ///
    /// # Errors
    /// A bad certificate or key.
    pub fn client_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let cfg = rustls::ClientConfig::builder_with_provider(internal_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::internal(e.to_string()))?
            .with_root_certificates(self.roots()?)
            .with_client_auth_cert(
                self.chain.clone(),
                PrivateKeyDer::Pkcs8(self.key.clone_key()),
            )
            .map_err(|e| Error::internal(format!("client certificate: {e}")))?;
        Ok(Arc::new(cfg))
    }
}

/// The verified role of a peer, from its (already chain-verified) leaf certificate.
#[must_use]
pub fn peer_role(certs: Option<&[CertificateDer<'static>]>) -> Option<Role> {
    let leaf = certs?.first()?;
    let ee = webpki::EndEntityCert::try_from(leaf).ok()?;
    let mut found = None;
    for name in ee.valid_dns_names() {
        for role in Role::ALL {
            if name == unit_dns_name(role) {
                if found.is_some() {
                    return None; // a certificate naming two roles is refused
                }
                found = Some(role);
            }
        }
    }
    found
}

/// The server name a client uses to reach `role`.
///
/// # Errors
/// Never in practice (the names are fixed).
pub fn server_name(role: Role) -> Result<ServerName<'static>> {
    ServerName::try_from(unit_dns_name(role)).map_err(|e| Error::internal(e.to_string()))
}

/// The internal CA (≤ 2 years) and leaves (≤ 90 days), issued with rcgen. In production the
/// CA key is in the HSM (`tls-ca`) and leaves are issued at a ceremony; this issuer is what
/// `humid-server-* dev-certs` and the tests use.
pub struct DevCa {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

impl DevCa {
    /// A fresh ML-DSA-87 CA.
    ///
    /// # Errors
    /// Key generation failed.
    pub fn new() -> Result<Self> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ML_DSA_87)
            .map_err(|e| Error::internal(e.to_string()))?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::internal(e.to_string()))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HumID internal CA (development)");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(730);
        let cert = params
            .self_signed(&key)
            .map_err(|e| Error::internal(e.to_string()))?;
        Ok(Self { params, key, cert })
    }

    /// A leaf for `role` (90 days).
    ///
    /// # Errors
    /// Key generation or signing failed.
    pub fn issue(&self, role: Role) -> Result<Identity> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ML_DSA_87)
            .map_err(|e| Error::internal(e.to_string()))?;
        let mut params = rcgen::CertificateParams::new(vec![unit_dns_name(role)])
            .map_err(|e| Error::internal(e.to_string()))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, unit_dns_name(role));
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(90);
        let issuer = rcgen::Issuer::new(self.params.clone(), &self.key);
        let leaf = params
            .signed_by(&key, &issuer)
            .map_err(|e| Error::internal(e.to_string()))?;
        let ca = CertificateDer::from(self.cert.der().to_vec());
        Ok(Identity {
            chain: vec![CertificateDer::from(leaf.der().to_vec()), ca.clone()],
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
            ca,
        })
    }

    /// The CA certificate, PEM.
    #[must_use]
    pub fn ca_pem(&self) -> String {
        self.cert.pem()
    }
}

/// PEM text for one DER object.
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

impl Identity {
    /// Write `<name>.pem` (chain), `<name>.key` (PKCS#8, mode 0600) and `ca.pem` into `dir`.
    ///
    /// # Errors
    /// The files can't be written.
    pub fn write(&self, dir: &std::path::Path, name: &str) -> Result<()> {
        let chain: String = self.chain.iter().map(|c| pem("CERTIFICATE", c)).collect();
        let w = |p: std::path::PathBuf, s: &str| {
            std::fs::write(&p, s).map_err(|e| Error::internal(format!("{}: {e}", p.display())))
        };
        w(dir.join(format!("{name}.pem")), &chain)?;
        w(dir.join("ca.pem"), &pem("CERTIFICATE", &self.ca))?;
        let key = dir.join(format!("{name}.key"));
        let _ = std::fs::remove_file(&key);
        crate::hsm::write_private(
            &key,
            pem("PRIVATE KEY", self.key.secret_pkcs8_der()).as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn handshake(
        server: Arc<rustls::ServerConfig>,
        client: Arc<rustls::ClientConfig>,
        name: Role,
    ) -> std::result::Result<(Option<Role>, u16), String> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let acc = tokio_rustls::TlsAcceptor::from(server);
        let srv = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut t = acc.accept(s).await.map_err(|e| e.to_string())?;
            let (_, c) = t.get_ref();
            let role = peer_role(c.peer_certificates());
            let group = match c.negotiated_key_exchange_group().map(|g| g.name()) {
                Some(NamedGroup::Unknown(x)) => x,
                Some(g) => u16::from(g),
                None => 0,
            };
            let mut b = [0u8; 4];
            t.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            t.write_all(b"pong").await.map_err(|e| e.to_string())?;
            Ok::<_, String>((role, group))
        });
        let s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let con = tokio_rustls::TlsConnector::from(client);
        match con.connect(server_name(name).unwrap(), s).await {
            Ok(mut t) => {
                // TLS 1.3: a server refusing the client certificate does so after the client's
                // handshake finished, so the refusal shows up on the first read
                let io = async {
                    t.write_all(b"ping").await?;
                    let mut b = [0u8; 4];
                    t.read_exact(&mut b).await
                };
                let client = io.await.map_err(|e| e.to_string());
                let server = srv.await.unwrap();
                client.and(server)
            }
            Err(e) => {
                let _ = srv.await;
                Err(e.to_string())
            }
        }
    }

    #[tokio::test]
    async fn internal_hop_uses_p384_mlkem1024_and_ml_dsa_certs() {
        let ca = DevCa::new().unwrap();
        let core = ca.issue(Role::Core).unwrap();
        let front = ca.issue(Role::Front).unwrap();
        let (role, group) = handshake(
            core.server_config().unwrap(),
            front.client_config().unwrap(),
            Role::Core,
        )
        .await
        .unwrap();
        assert_eq!(
            role,
            Some(Role::Front),
            "the client certificate says who is calling"
        );
        assert_eq!(group, SECP384R1_MLKEM1024);
    }

    #[tokio::test]
    async fn a_classical_client_is_refused() {
        let ca = DevCa::new().unwrap();
        let core = ca.issue(Role::Core).unwrap();
        let front = ca.issue(Role::Front).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(front.ca.clone()).unwrap();
        // the stock provider: classical and 768 hybrids, but not SecP384r1MLKEM1024
        let mut p = provider::default_provider();
        p.kx_groups = vec![
            kx_group::X25519,
            kx_group::SECP384R1,
            provider::kx_group::X25519MLKEM768,
        ];
        let classical = rustls::ClientConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                front.chain.clone(),
                PrivateKeyDer::Pkcs8(front.key.clone_key()),
            )
            .unwrap();
        assert!(
            handshake(
                core.server_config().unwrap(),
                Arc::new(classical),
                Role::Core
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_certificate_from_another_ca_is_refused() {
        let ca = DevCa::new().unwrap();
        let other = DevCa::new().unwrap();
        let core = ca.issue(Role::Core).unwrap();
        let rogue = other.issue(Role::Front).unwrap();
        // the rogue client trusts the real CA (so it accepts core) but presents its own leaf
        let mut roots = rustls::RootCertStore::empty();
        roots.add(core.ca.clone()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(internal_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                rogue.chain.clone(),
                PrivateKeyDer::Pkcs8(rogue.key.clone_key()),
            )
            .unwrap();
        let r = handshake(core.server_config().unwrap(), Arc::new(cfg), Role::Core).await;
        assert!(r.is_err(), "a leaf from another CA never gets a connection");
    }
}
