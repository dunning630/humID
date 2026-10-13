//! Drives the desktop PC/SC reader from a line protocol, so the shared JS chip
//! reader (@humid/emrtd) can be tested through the real native transport:
//!   stdin:  "begin" | "<apdu hex>" | "end"      stdout: one JSON line per command
//! Used by tests/e2e/pcsc.test.js against pcscd with a virtual reader.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::io::{BufRead, Write};
use tauri_plugin_humid_nfc::{reader, BeginRequest, EndRequest, TransceiveRequest};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut session = String::new();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        let reply = match line.trim() {
            "probe" => serde_json::to_string(&reader::probe().map_err(|e| e.to_string())).unwrap(),
            "begin" => match reader::begin(BeginRequest { prompt: None, timeout_ms: Some(10_000), reader: None }) {
                Ok(s) => { session = s.session.clone(); serde_json::json!({ "ok": s }).to_string() }
                Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
            },
            "end" => { let _ = reader::end(EndRequest { session: session.clone(), message: None, error: None }); "{\"ok\":true}".into() }
            hex => {
                let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect();
                match reader::transceive(TransceiveRequest { session: session.clone(), apdu: B64.encode(bytes) }) {
                    Ok(r) => serde_json::json!({ "response": B64.decode(r.response).unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>() }).to_string(),
                    Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
                }
            }
        };
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
}
