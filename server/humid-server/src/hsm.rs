//! The HSM boundary (SERVER.md §6).
//!
//! Units hold no long-lived private key in their own memory: they ask an [`Hsm`] to sign,
//! wrap, unwrap or MAC with a key named by a [`KeyRef`]. The trait offers only operations
//! PKCS#11 v3.2 has mechanisms for — ML-DSA (`CKM_ML_DSA`, with a context string), SLH-DSA
//! (`CKM_SLH_DSA`), AES key wrap with padding (`CKM_AES_KEY_WRAP_KWP`), HMAC/KMAC — and
//! each key allows only its own operation (as `CKA_SIGN`, `CKA_WRAP`… would).
//!
//! * [`SoftHsm`]: software, for development and tests. Every key is derived from one
//!   32-byte master seed in the unit's data directory. **Refused in production mode.**
//! * [`Pkcs11Hsm`]: the production path; a typed stub until the HSM model is chosen.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use zeroize::Zeroizing;

use crate::crypto::{
    self, DualPublic, DualSecret, MlDsaPublic, MlDsaSecret, ObjectType, Secret, Secret32, label,
};
use crate::error::{Error, Result};
use crate::unit::Mode;

/// A key inside the HSM, by its label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRef {
    /// The identity root (dual): signs the policy. Ceremony only; no unit uses it at run time.
    IdentityRoot,
    /// Core's statement key (ML-DSA-87).
    CoreStatement,
    /// The ledger and public-log key (dual).
    Ledger,
    /// Server-keyed recovery-card tags (KMAC).
    CardTag,
    /// The keys unit's statement key (ML-DSA-87).
    KeysStatement,
    /// The share KEK (wrap).
    ShareKek,
    /// Anon's statement key (ML-DSA-87).
    AnonStatement,
    /// Every unit's at-rest seal (wrap).
    Seal,
}

/// What a key may be used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// ML-DSA-87 signing.
    MlDsa,
    /// ML-DSA-87 + SLH-DSA-SHA2-256s signing.
    Dual,
    /// Key wrap.
    Wrap,
    /// Keyed tag.
    Mac,
}

impl KeyRef {
    /// Every key.
    pub const ALL: [KeyRef; 8] = [
        KeyRef::IdentityRoot,
        KeyRef::CoreStatement,
        KeyRef::Ledger,
        KeyRef::CardTag,
        KeyRef::KeysStatement,
        KeyRef::ShareKek,
        KeyRef::AnonStatement,
        KeyRef::Seal,
    ];

    /// The label (PKCS#11 `CKA_LABEL`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            KeyRef::IdentityRoot => "identity-root",
            KeyRef::CoreStatement => "core-statement",
            KeyRef::Ledger => "ledger",
            KeyRef::CardTag => "card-tag",
            KeyRef::KeysStatement => "keys-statement",
            KeyRef::ShareKek => "share-kek",
            KeyRef::AnonStatement => "anon-statement",
            KeyRef::Seal => "seal",
        }
    }

    /// Its one mechanism.
    #[must_use]
    pub fn mechanism(self) -> Mechanism {
        match self {
            KeyRef::CoreStatement | KeyRef::KeysStatement | KeyRef::AnonStatement => {
                Mechanism::MlDsa
            }
            KeyRef::IdentityRoot | KeyRef::Ledger => Mechanism::Dual,
            KeyRef::ShareKek | KeyRef::Seal => Mechanism::Wrap,
            KeyRef::CardTag => Mechanism::Mac,
        }
    }

    fn index(self) -> usize {
        KeyRef::ALL.iter().position(|k| *k == self).unwrap_or(0)
    }
}

/// Which implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsmKind {
    /// [`SoftHsm`].
    Software,
    /// [`Pkcs11Hsm`].
    Pkcs11,
}

/// The HSM operations a unit may ask for.
pub trait Hsm: Send + Sync {
    /// Which implementation this is.
    fn kind(&self) -> HsmKind;
    /// The public half of an ML-DSA key.
    ///
    /// # Errors
    /// Wrong mechanism; HSM unavailable.
    fn mldsa_public(&self, k: KeyRef) -> Result<MlDsaPublic>;
    /// Sign with an ML-DSA key.
    ///
    /// # Errors
    /// Wrong mechanism; HSM unavailable.
    fn mldsa_sign(&self, k: KeyRef, label: &str, msg: &[u8]) -> Result<Vec<u8>>;
    /// The public half of a dual key.
    ///
    /// # Errors
    /// Wrong mechanism; HSM unavailable.
    fn dual_public(&self, k: KeyRef) -> Result<DualPublic>;
    /// Sign with both halves of a dual key.
    ///
    /// # Errors
    /// Wrong mechanism; HSM unavailable.
    fn dual_sign(&self, k: KeyRef, label: &str, msg: &[u8]) -> Result<Vec<u8>>;
    /// Wrap (seal) `pt`, bound to `t` and `aad`.
    ///
    /// # Errors
    /// Wrong mechanism; HSM unavailable.
    fn wrap(&self, k: KeyRef, t: ObjectType, aad: &[&[u8]], pt: &[u8]) -> Result<Vec<u8>>;
    /// Unwrap; the plaintext is wiped on drop.
    ///
    /// # Errors
    /// Wrong mechanism; not wrapped by this key with this binding; HSM unavailable.
    fn unwrap(
        &self,
        k: KeyRef,
        t: ObjectType,
        aad: &[&[u8]],
        boxed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
    /// A 32-byte keyed tag over `parts`.
    ///
    /// # Errors
    /// Wrong mechanism; HSM unavailable.
    fn mac(&self, k: KeyRef, label: &str, parts: &[&[u8]]) -> Result<[u8; 32]>;
}

fn wrong(k: KeyRef, want: Mechanism) -> Result<()> {
    if k.mechanism() == want {
        Ok(())
    } else {
        Err(Error::internal(format!(
            "HSM key {} can't be used for {want:?}",
            k.label()
        )))
    }
}

/* ------------------------------ software ------------------------------ */

/// The software HSM. Development and tests only.
pub struct SoftHsm {
    master: Secret32,
    mldsa: [OnceLock<MlDsaSecret>; 8],
    dual: [OnceLock<DualSecret>; 8],
}

const SOFT_HSM_FILE: &str = "soft-hsm.key";

impl SoftHsm {
    /// From a master seed.
    #[must_use]
    pub fn from_master(master: Secret32) -> Self {
        Self {
            master,
            mldsa: Default::default(),
            dual: Default::default(),
        }
    }

    /// A fresh, in-memory HSM (tests).
    ///
    /// # Errors
    /// The generator failed.
    pub fn ephemeral() -> Result<Self> {
        Ok(Self::from_master(Secret32::random().map_err(Error::from)?))
    }

    /// Open (or create, mode 0600) the master seed file in `dir`.
    ///
    /// # Errors
    /// The file can't be read or written, or isn't 32 bytes.
    pub fn open_dir(dir: &Path) -> Result<Self> {
        let path: PathBuf = dir.join(SOFT_HSM_FILE);
        if !path.exists() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::internal(format!("{}: {e}", dir.display())))?;
            let seed = Zeroizing::new(crypto::random::<32>()?);
            write_private(&path, &seed[..])?;
        }
        let bytes = Zeroizing::new(
            std::fs::read(&path)
                .map_err(|e| Error::internal(format!("{}: {e}", path.display())))?,
        );
        let master = Secret32::from_slice(&bytes)
            .map_err(|_| Error::internal(format!("{} isn't 32 bytes", path.display())))?;
        Ok(Self::from_master(master))
    }

    fn seed<const N: usize>(&self, k: KeyRef, part: &str) -> Result<Secret<N>> {
        crypto::kdf::<N>(
            label::SOFT_HSM,
            &[self.master.expose()],
            &[k.label().as_bytes(), part.as_bytes()],
        )
    }

    fn mldsa_key(&self, k: KeyRef) -> Result<&MlDsaSecret> {
        wrong(k, Mechanism::MlDsa)?;
        let cell = &self.mldsa[k.index()];
        if let Some(key) = cell.get() {
            return Ok(key);
        }
        let key = MlDsaSecret::from_seed(&self.seed::<32>(k, "ml-dsa")?);
        Ok(cell.get_or_init(|| key))
    }

    fn dual_key(&self, k: KeyRef) -> Result<&DualSecret> {
        wrong(k, Mechanism::Dual)?;
        let cell = &self.dual[k.index()];
        if let Some(key) = cell.get() {
            return Ok(key);
        }
        let key = DualSecret::from_seeds(
            &self.seed::<32>(k, "ml-dsa")?,
            &self.seed::<96>(k, "slh-dsa")?,
        );
        Ok(cell.get_or_init(|| key))
    }
}

/// Write a file only its owner can read (0600 on Unix).
///
/// # Errors
/// The file can't be written.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|e| Error::internal(format!("{}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| Error::internal(format!("{}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| Error::internal(format!("{}: {e}", path.display())))
}

impl Hsm for SoftHsm {
    fn kind(&self) -> HsmKind {
        HsmKind::Software
    }
    fn mldsa_public(&self, k: KeyRef) -> Result<MlDsaPublic> {
        Ok(self.mldsa_key(k)?.public())
    }
    fn mldsa_sign(&self, k: KeyRef, label: &str, msg: &[u8]) -> Result<Vec<u8>> {
        self.mldsa_key(k)?.sign(label, msg)
    }
    fn dual_public(&self, k: KeyRef) -> Result<DualPublic> {
        Ok(self.dual_key(k)?.public())
    }
    fn dual_sign(&self, k: KeyRef, label: &str, msg: &[u8]) -> Result<Vec<u8>> {
        self.dual_key(k)?.sign(label, msg)
    }
    fn wrap(&self, k: KeyRef, t: ObjectType, aad: &[&[u8]], pt: &[u8]) -> Result<Vec<u8>> {
        wrong(k, Mechanism::Wrap)?;
        crypto::seal_at_rest(&self.seed::<32>(k, "wrap")?, t, aad, pt)
    }
    fn unwrap(
        &self,
        k: KeyRef,
        t: ObjectType,
        aad: &[&[u8]],
        boxed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        wrong(k, Mechanism::Wrap)?;
        crypto::open_at_rest(&self.seed::<32>(k, "wrap")?, t, aad, boxed)
    }
    fn mac(&self, k: KeyRef, label: &str, parts: &[&[u8]]) -> Result<[u8; 32]> {
        wrong(k, Mechanism::Mac)?;
        let key = self.seed::<32>(k, "mac")?;
        Ok(*crypto::kdf::<32>(label, &[key.expose()], parts)?.expose())
    }
}

/* ------------------------------- PKCS#11 ------------------------------- */

/// The production HSM over PKCS#11 v3.2. A typed stub until the HSM model is chosen
/// (SERVER.md §13): every operation answers `not_implemented`, so a unit configured for it
/// fails at start-up with a clear reason instead of running half-built.
pub struct Pkcs11Hsm {
    /// The PKCS#11 module path.
    pub module: PathBuf,
}

fn pkcs11_pending<T>() -> Result<T> {
    Err(Error::NotImplemented {
        what: "the PKCS#11 HSM backend",
        waiting_on: "the choice of HSM model (SERVER.md §13)",
    })
}

impl Hsm for Pkcs11Hsm {
    fn kind(&self) -> HsmKind {
        HsmKind::Pkcs11
    }
    fn mldsa_public(&self, _: KeyRef) -> Result<MlDsaPublic> {
        pkcs11_pending()
    }
    fn mldsa_sign(&self, _: KeyRef, _: &str, _: &[u8]) -> Result<Vec<u8>> {
        pkcs11_pending()
    }
    fn dual_public(&self, _: KeyRef) -> Result<DualPublic> {
        pkcs11_pending()
    }
    fn dual_sign(&self, _: KeyRef, _: &str, _: &[u8]) -> Result<Vec<u8>> {
        pkcs11_pending()
    }
    fn wrap(&self, _: KeyRef, _: ObjectType, _: &[&[u8]], _: &[u8]) -> Result<Vec<u8>> {
        pkcs11_pending()
    }
    fn unwrap(
        &self,
        _: KeyRef,
        _: ObjectType,
        _: &[&[u8]],
        _: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        pkcs11_pending()
    }
    fn mac(&self, _: KeyRef, _: &str, _: &[&[u8]]) -> Result<[u8; 32]> {
        pkcs11_pending()
    }
}

/// How `server.toml` names the HSM.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum HsmConfig {
    /// The software HSM, keyed from `<data_dir>/soft-hsm.key`.
    Soft,
    /// A PKCS#11 module.
    Pkcs11 {
        /// Path to the module (`.so`).
        module: PathBuf,
    },
}

/// Open the configured HSM, refusing the software one in production, and check that the
/// keys this unit needs answer.
///
/// # Errors
/// Software HSM in production; the HSM can't be opened; a needed key doesn't answer.
pub fn open(
    cfg: &HsmConfig,
    mode: Mode,
    data_dir: &Path,
    needs: &[KeyRef],
) -> Result<Arc<dyn Hsm>> {
    let hsm: Arc<dyn Hsm> = match cfg {
        HsmConfig::Soft => {
            if mode == Mode::Production {
                return Err(Error::forbidden(
                    "soft_hsm_in_production",
                    "The software HSM is for development only. A production server needs its keys in an HSM (hsm.kind = \"pkcs11\").",
                ));
            }
            tracing::warn!(
                "using the SOFTWARE HSM: development only, keys live in a file on this machine"
            );
            Arc::new(SoftHsm::open_dir(data_dir)?)
        }
        HsmConfig::Pkcs11 { module } => Arc::new(Pkcs11Hsm {
            module: module.clone(),
        }),
    };
    check(hsm.as_ref(), needs)?;
    Ok(hsm)
}

/// Every needed key answers (no unit starts without its seal key, SERVER.md §6).
///
/// # Errors
/// The first key that doesn't.
pub fn check(hsm: &dyn Hsm, needs: &[KeyRef]) -> Result<()> {
    for &k in needs {
        match k.mechanism() {
            Mechanism::MlDsa => {
                hsm.mldsa_public(k)?;
            }
            Mechanism::Dual => {
                hsm.dual_public(k)?;
            }
            Mechanism::Wrap => {
                let b = hsm.wrap(
                    k,
                    crate::crypto::object_type::UNIT_SEALED,
                    &[b"hsm-check"],
                    b"ok",
                )?;
                hsm.unwrap(
                    k,
                    crate::crypto::object_type::UNIT_SEALED,
                    &[b"hsm-check"],
                    &b,
                )?;
            }
            Mechanism::Mac => {
                hsm.mac(k, label::CARD_TAG, &[b"hsm-check"])?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::object_type::UNIT_SEALED;

    #[test]
    fn software_hsm_is_refused_in_production() {
        let dir = std::env::temp_dir().join(format!(
            "humid-hsm-{}",
            hex::encode(crypto::random::<8>().unwrap())
        ));
        let e = open(&HsmConfig::Soft, Mode::Production, &dir, &[KeyRef::Seal])
            .err()
            .unwrap();
        assert_eq!(e.code(), "soft_hsm_in_production");
        assert!(
            !dir.join(SOFT_HSM_FILE).exists(),
            "nothing is written when refused"
        );
        let h = open(&HsmConfig::Soft, Mode::Development, &dir, &[KeyRef::Seal]).unwrap();
        assert_eq!(h.kind(), HsmKind::Software);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pkcs11_stub_fails_at_start_with_a_reason() {
        let cfg = HsmConfig::Pkcs11 {
            module: "/usr/lib/none.so".into(),
        };
        let e = open(
            &cfg,
            Mode::Production,
            Path::new("/nonexistent"),
            &[KeyRef::Seal],
        )
        .err()
        .unwrap();
        assert_eq!(e.code(), "not_implemented");
    }

    #[test]
    fn soft_hsm_is_stable_across_reopen_and_keys_are_separate() {
        let dir = std::env::temp_dir().join(format!(
            "humid-hsm-{}",
            hex::encode(crypto::random::<8>().unwrap())
        ));
        let a = SoftHsm::open_dir(&dir).unwrap();
        let b = SoftHsm::open_dir(&dir).unwrap();
        assert_eq!(
            a.mldsa_public(KeyRef::CoreStatement).unwrap(),
            b.mldsa_public(KeyRef::CoreStatement).unwrap()
        );
        assert_ne!(
            a.mldsa_public(KeyRef::CoreStatement).unwrap(),
            a.mldsa_public(KeyRef::KeysStatement).unwrap()
        );
        let w = a
            .wrap(KeyRef::Seal, UNIT_SEALED, &[b"x"], b"secret")
            .unwrap();
        assert_eq!(
            &b.unwrap(KeyRef::Seal, UNIT_SEALED, &[b"x"], &w).unwrap()[..],
            b"secret"
        );
        assert!(
            b.unwrap(KeyRef::Seal, UNIT_SEALED, &[b"y"], &w).is_err(),
            "binding is checked"
        );
        assert!(
            b.unwrap(KeyRef::ShareKek, UNIT_SEALED, &[b"x"], &w)
                .is_err(),
            "another key doesn't open it"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.join(SOFT_HSM_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_key_does_only_its_own_job() {
        let h = SoftHsm::ephemeral().unwrap();
        assert!(
            h.mldsa_sign(KeyRef::Seal, label::UNIT_STATEMENT, b"m")
                .is_err()
        );
        assert!(
            h.wrap(KeyRef::CoreStatement, UNIT_SEALED, &[], b"m")
                .is_err()
        );
        assert!(h.mac(KeyRef::ShareKek, label::CARD_TAG, &[]).is_err());
        let sig = h
            .mldsa_sign(KeyRef::CoreStatement, label::UNIT_STATEMENT, b"m")
            .unwrap();
        assert!(h.mldsa_public(KeyRef::CoreStatement).unwrap().verifies(
            label::UNIT_STATEMENT,
            b"m",
            &sig
        ));
    }
}
