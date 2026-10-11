// Linux: fingerprint match through fprintd (D-Bus, polkit-authorised for the
// active local session), then the 32-byte secret is read from the user's
// Secret Service keyring (GNOME Keyring, KWallet).
//
// Linux has no standard way to bind a key to a fingerprint in hardware, so the
// keyring hands the secret over once the user's session is unlocked; the
// fingerprint check is enforced by HumID, not by secure hardware. This gate
// reports assurance "os" and the UI labels it as such.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use secret_service::{EncryptionType, SecretService};
use zbus::{zvariant::OwnedObjectPath, Connection, Proxy};
use zeroize::Zeroizing;

use super::{random32, Secret};
use crate::{Error, Probe, Result};

pub const METHOD: &str = "linux-fprintd-keyring";
pub const ASSURANCE: &str = "os";

const FPRINT: &str = "net.reactivated.Fprint";
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

fn run<T>(f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tauri::async_runtime::block_on(f)
}

fn dbus(e: zbus::Error) -> Error {
    let msg = e.to_string();
    if msg.contains("NoEnrolledPrints") {
        Error::Unavailable("No fingerprints are enrolled. Enrol one with your desktop settings or `fprintd-enroll`.".into())
    } else if msg.contains("system_bus_socket") || msg.contains("Failed to connect") {
        Error::Unavailable("The system service that runs fingerprint readers (D-Bus) is not reachable.".into())
    } else if msg.contains("ServiceUnknown") || msg.contains("NoSuchDevice") {
        Error::Unavailable("No fingerprint reader found (fprintd is not running or no device is attached).".into())
    } else if msg.contains("PermissionDenied") {
        Error::Unavailable("The system did not allow HumID to use the fingerprint reader.".into())
    } else {
        Error::Platform(format!("fprintd: {msg}"))
    }
}

fn keyring(e: secret_service::Error) -> Error {
    match e {
        secret_service::Error::Prompt => Error::Cancelled,
        other => Error::Unavailable(format!("Secret Service keyring unavailable: {other}")),
    }
}

async fn device(conn: &Connection) -> Result<Proxy<'static>> {
    let mgr = Proxy::new(conn, FPRINT, "/net/reactivated/Fprint/Manager", "net.reactivated.Fprint.Manager")
        .await
        .map_err(dbus)?;
    let path: OwnedObjectPath = mgr.call("GetDefaultDevice", &()).await.map_err(dbus)?;
    Proxy::new(conn, FPRINT, path, "net.reactivated.Fprint.Device").await.map_err(dbus)
}

/// Block until fprintd reports a match for the current user.
async fn verify_finger() -> Result<()> {
    let conn = Connection::system().await.map_err(dbus)?;
    let dev = device(&conn).await?;
    dev.call::<_, _, ()>("Claim", &("",)).await.map_err(dbus)?;
    let outcome = async {
        let mut status = dev.receive_signal("VerifyStatus").await.map_err(dbus)?;
        dev.call::<_, _, ()>("VerifyStart", &("any",)).await.map_err(dbus)?;
        let wait = async {
            while let Some(msg) = status.next().await {
                let (result, done): (String, bool) = msg.body().deserialize().map_err(|e| Error::Platform(e.to_string()))?;
                match result.as_str() {
                    "verify-match" => return Ok(()),
                    "verify-no-match" if done => return Err(Error::Platform("Fingerprint did not match.".into())),
                    "verify-disconnected" => return Err(Error::Unavailable("The fingerprint reader was disconnected.".into())),
                    "verify-unknown-error" => return Err(Error::Platform("The fingerprint reader reported an error.".into())),
                    _ if done => return Err(Error::Platform(format!("Fingerprint check ended: {result}"))),
                    _ => {} // retry-scan, swipe-too-short, finger-not-centered, ...
                }
            }
            Err(Error::Platform("fprintd stopped reporting.".into()))
        };
        tokio::time::timeout(VERIFY_TIMEOUT, wait).await.unwrap_or(Err(Error::Cancelled))
    }
    .await;
    let _ = dev.call::<_, _, ()>("VerifyStop", &()).await;
    let _ = dev.call::<_, _, ()>("Release", &()).await;
    outcome
}

fn attrs(id: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", "app.humid.gate"), ("humid-gate-id", id)])
}

pub fn probe() -> Result<Probe> {
    let check = run(async {
        let conn = Connection::system().await.map_err(dbus)?;
        let dev = device(&conn).await?;
        let fingers: Vec<String> = dev.call("ListEnrolledFingers", &("",)).await.map_err(dbus)?;
        if fingers.is_empty() {
            return Err(Error::Unavailable("No fingerprints are enrolled.".into()));
        }
        SecretService::connect(EncryptionType::Dh).await.map_err(keyring)?;
        Ok(())
    });
    Ok(Probe {
        available: check.is_ok(),
        method: METHOD.into(),
        assurance: ASSURANCE.into(),
        label: "Fingerprint (fprintd)".into(),
        reason: check.err().map(|e| e.to_string()),
    })
}

pub fn enroll(id: &str, _prompt: &str) -> Result<Secret> {
    run(async {
        verify_finger().await?;
        let secret = random32();
        let ss = SecretService::connect(EncryptionType::Dh).await.map_err(keyring)?;
        let col = ss.get_default_collection().await.map_err(keyring)?;
        col.ensure_unlocked().await.map_err(keyring)?;
        col.create_item("HumID gate key", attrs(id), &secret, true, "application/octet-stream")
            .await
            .map_err(keyring)?;
        Ok(Secret { bytes: secret, detail: Some(serde_json::json!({ "factor": "fingerprint" })) })
    })
}

pub fn release(id: &str, _prompt: &str) -> Result<Secret> {
    run(async {
        verify_finger().await?;
        let ss = SecretService::connect(EncryptionType::Dh).await.map_err(keyring)?;
        let found = ss.search_items(attrs(id)).await.map_err(keyring)?;
        let item = found.unlocked.into_iter().chain(found.locked).next().ok_or(Error::KeyInvalidated)?;
        item.ensure_unlocked().await.map_err(keyring)?;
        let bytes = Zeroizing::new(item.get_secret().await.map_err(keyring)?);
        if bytes.len() != 32 {
            return Err(Error::KeyInvalidated);
        }
        Ok(Secret { bytes, detail: Some(serde_json::json!({ "factor": "fingerprint" })) })
    })
}

pub fn forget(id: &str) -> Result<()> {
    run(async {
        let ss = SecretService::connect(EncryptionType::Dh).await.map_err(keyring)?;
        let found = ss.search_items(attrs(id)).await.map_err(keyring)?;
        for item in found.unlocked.iter().chain(found.locked.iter()) {
            let _ = item.delete().await;
        }
        Ok(())
    })
}
