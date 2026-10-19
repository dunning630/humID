use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// No scanner on this device (not Android, no Play services, not enough memory).
    #[allow(dead_code)]
    Unavailable(String),
    #[cfg(mobile)]
    PluginInvoke(tauri::plugin::mobile::PluginInvokeError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unavailable(r) => write!(f, "unavailable: {r}"),
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
