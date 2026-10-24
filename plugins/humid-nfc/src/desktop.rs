// Desktop: PC/SC contactless readers (an ACR1252U, an Identiv uTrust, a
// laptop's built-in NFC). A verification station is often a laptop with one.
// Windows uses WinSCard and macOS the PCSC framework, both built in. Linux
// isn't wired up yet: pcsc-lite would have to be installed for the app to start.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::de::DeserializeOwned;
use tauri::{AppHandle, Runtime, plugin::PluginApi};

use crate::models::*;
use crate::{Error, Result};

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> Result<HumidNfc<R>> {
    Ok(HumidNfc(app.clone()))
}

pub struct HumidNfc<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| Error::Platform(format!("reader worker failed: {e}")))?
}

#[allow(dead_code)]
fn new_session_id() -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).expect("OS random source");
    B64.encode(b)
}

#[cfg(any(windows, target_os = "macos", feature = "pcsc-linux"))]
pub(crate) mod pcsc_reader {
    use super::*;
    use pcsc::{
        Card, Context, MAX_BUFFER_SIZE_EXTENDED, Protocols, ReaderState, Scope, ShareMode, State,
    };
    use std::ffi::{CStr, CString};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    struct Open {
        id: String,
        card: Card,
        _ctx: Context,
    }
    static SESSION: Mutex<Option<Open>> = Mutex::new(None);

    fn readers(ctx: &Context) -> Result<Vec<CString>> {
        let len = ctx
            .list_readers_len()
            .map_err(|e| Error::Unavailable(format!("No smart card service: {e}")))?;
        let mut buf = vec![0u8; len];
        match ctx.list_readers(&mut buf) {
            Ok(names) => Ok(names.map(CStr::to_owned).collect()),
            Err(pcsc::Error::NoReadersAvailable) => Ok(vec![]),
            Err(e) => Err(Error::Platform(format!("Can't list card readers: {e}"))),
        }
    }

    /// Prefer the contactless interface of a dual reader.
    fn pick(names: &[CString], wanted: Option<&str>) -> Option<CString> {
        if let Some(w) = wanted {
            return names.iter().find(|n| n.to_string_lossy() == w).cloned();
        }
        let contactless = |n: &&CString| {
            let s = n.to_string_lossy().to_lowercase();
            s.contains("picc")
                || s.contains("contactless")
                || s.contains(" cl ")
                || s.contains("nfc")
        };
        names
            .iter()
            .find(contactless)
            .or_else(|| names.first())
            .cloned()
    }

    pub fn probe() -> Result<Probe> {
        let ctx = match Context::establish(Scope::User) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Probe {
                    available: false,
                    kind: "none".into(),
                    readers: vec![],
                    reason: Some(format!("The smart card service isn't running ({e}).")),
                });
            }
        };
        let names: Vec<String> = readers(&ctx)?
            .iter()
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        Ok(Probe {
            available: !names.is_empty(),
            kind: if names.is_empty() {
                "none".into()
            } else {
                "reader".into()
            },
            reason: if names.is_empty() {
                Some("Connect a USB contactless (NFC) card reader to read a passport chip on this computer.".into())
            } else {
                None
            },
            readers: names,
        })
    }

    pub fn begin(req: BeginRequest) -> Result<Session> {
        let ctx = Context::establish(Scope::User).map_err(|e| {
            Error::Unavailable(format!("The smart card service isn't running ({e})."))
        })?;
        let names = readers(&ctx)?;
        let reader = pick(&names, req.reader.as_deref()).ok_or_else(|| {
            Error::Unavailable("Connect a USB contactless (NFC) card reader.".into())
        })?;
        let deadline = Instant::now() + Duration::from_millis(req.timeout_ms.unwrap_or(60_000));
        let mut states = vec![ReaderState::new(reader.clone(), State::UNAWARE)];
        loop {
            ctx.get_status_change(Duration::from_millis(500), &mut states)
                .or_else(|e| {
                    if e == pcsc::Error::Timeout {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(|e| Error::Platform(format!("Card reader error: {e}")))?;
            let st = states[0].event_state();
            if st.contains(State::PRESENT) && !st.contains(State::MUTE) {
                break;
            }
            states[0].sync_current_state();
            if Instant::now() > deadline {
                return Err(Error::Cancelled);
            }
        }
        let card = ctx
            .connect(&reader, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| Error::Platform(format!("Can't talk to the chip: {e}")))?;
        let id = new_session_id();
        *SESSION.lock().unwrap() = Some(Open {
            id: id.clone(),
            card,
            _ctx: ctx,
        });
        Ok(Session {
            session: id,
            kind: "reader".into(),
            reader: Some(reader.to_string_lossy().into_owned()),
        })
    }

    pub fn transceive(req: TransceiveRequest) -> Result<Response> {
        let apdu = B64
            .decode(req.apdu.as_bytes())
            .map_err(|_| Error::Platform("Bad APDU encoding".into()))?;
        let guard = SESSION.lock().unwrap();
        let open = guard
            .as_ref()
            .filter(|o| o.id == req.session)
            .ok_or(Error::NoSession)?;
        let mut buf = vec![0u8; MAX_BUFFER_SIZE_EXTENDED];
        let r = open.card.transmit(&apdu, &mut buf).map_err(|e| match e {
            pcsc::Error::RemovedCard | pcsc::Error::ResetCard | pcsc::Error::NoSmartcard => {
                Error::Lost
            }
            e => Error::Platform(format!("Chip exchange failed: {e}")),
        })?;
        Ok(Response {
            response: B64.encode(r),
        })
    }

    pub fn end(req: EndRequest) -> Result<()> {
        let mut guard = SESSION.lock().unwrap();
        if guard.as_ref().is_some_and(|o| o.id == req.session)
            && let Some(open) = guard.take()
        {
            let _ = open.card.disconnect(pcsc::Disposition::ResetCard);
        }
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "macos", feature = "pcsc-linux")))]
pub(crate) mod pcsc_reader {
    use super::*;
    const WHY: &str = "Reading ID chips on Linux isn't available yet. Use the HumID app on your phone, or on Windows or a Mac with a USB card reader.";
    pub fn probe() -> Result<Probe> {
        Ok(Probe {
            available: false,
            kind: "none".into(),
            readers: vec![],
            reason: Some(WHY.into()),
        })
    }
    pub fn begin(_: BeginRequest) -> Result<Session> {
        Err(Error::Unavailable(WHY.into()))
    }
    pub fn transceive(_: TransceiveRequest) -> Result<Response> {
        Err(Error::NoSession)
    }
    pub fn end(_: EndRequest) -> Result<()> {
        Ok(())
    }
}

impl<R: Runtime> HumidNfc<R> {
    pub async fn probe(&self) -> Result<Probe> {
        blocking(pcsc_reader::probe).await
    }
    pub async fn begin(&self, req: BeginRequest) -> Result<Session> {
        blocking(move || pcsc_reader::begin(req)).await
    }
    pub async fn transceive(&self, req: TransceiveRequest) -> Result<Response> {
        blocking(move || pcsc_reader::transceive(req)).await
    }
    pub async fn message(&self, _req: MessageRequest) -> Result<()> {
        Ok(())
    }
    pub async fn end(&self, req: EndRequest) -> Result<()> {
        blocking(move || pcsc_reader::end(req)).await
    }
}
