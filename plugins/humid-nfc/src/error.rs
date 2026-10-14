use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// The person closed the reader sheet, or no document arrived in time.
    Cancelled,
    /// No NFC hardware, NFC turned off, no PC/SC reader.
    Unavailable(String),
    /// The chip moved away or the link dropped.
    Lost,
    NoSession,
    Platform(String),
    #[cfg(mobile)]
    PluginInvoke(tauri::plugin::mobile::PluginInvokeError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Cancelled => write!(f, "Chip reading cancelled."),
            Error::Unavailable(r) => write!(f, "{r}"),
            Error::Lost => write!(f, "Lost contact with the chip. Hold the document still against the reader and try again."),
            Error::NoSession => write!(f, "No chip reading session is open."),
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
