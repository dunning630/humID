use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// The user dismissed the prompt or it timed out. The JS side maps any
    /// message containing "cancel" to its "Interrupt cancelled." state.
    Cancelled,
    /// No usable biometric, no enrolled fingers, no keyring, etc.
    Unavailable(String),
    /// The biometric set changed or the key was deleted; the identity must be re-bound.
    KeyInvalidated,
    BadHandle,
    Platform(String),
    #[cfg(mobile)]
    PluginInvoke(tauri::plugin::mobile::PluginInvokeError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Cancelled => write!(f, "Biometric check cancelled."),
            Error::Unavailable(r) => write!(f, "{r}"),
            Error::KeyInvalidated => write!(
                f,
                "The device biometric key is gone or was invalidated by a biometric change. This identity can no longer be unlocked here."
            ),
            Error::BadHandle => write!(f, "The stored gate handle is malformed."),
            Error::Platform(m) => write!(f, "{m}"),
            #[cfg(mobile)]
            Error::PluginInvoke(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(mobile)]
impl From<tauri::plugin::mobile::PluginInvokeError> for Error {
    fn from(e: tauri::plugin::mobile::PluginInvokeError) -> Self {
        Error::PluginInvoke(e)
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
