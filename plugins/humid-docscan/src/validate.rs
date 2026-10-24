//! Everything that crosses into the camera is checked here first: the web view is not trusted
//! to send sensible numbers, and native code is not trusted to hand back anything but a JPEG.
//! Pure functions, tested below (`cargo test -p tauri-plugin-humid-docscan`).

use base64::Engine;

use crate::Error;
use crate::models::{Point, Rect, Size};

/// The largest web view side accepted, in CSS pixels (a big tablet is about 1400).
pub const MAX_SIDE: f64 = 10_000.0;
/// The smallest frame side accepted, in CSS pixels.
pub const MIN_FRAME: f64 = 16.0;
/// The largest JPEG handed to the web view (a 12 MP still cut to a page is about 2 MB).
pub const MAX_JPEG: usize = 24 * 1024 * 1024;

fn bad(what: &str) -> Error {
    Error::Invalid(what.to_string())
}

fn finite(v: &[f64]) -> bool {
    v.iter().all(|x| x.is_finite())
}

/// The web view's size: finite, at least 100 × 100, at most MAX_SIDE.
pub fn view(v: &Size) -> Result<Size, Error> {
    if !finite(&[v.w, v.h]) || v.w < 100.0 || v.h < 100.0 || v.w > MAX_SIDE || v.h > MAX_SIDE {
        return Err(bad("The camera's view size isn't valid."));
    }
    Ok(*v)
}

/// The frame: finite, at least MIN_FRAME on each side, and mostly on screen (it may reach a
/// little past an edge, as a layout does while it settles, but not wander off it).
pub fn frame(r: &Rect, v: &Size) -> Result<Rect, Error> {
    let v = view(v)?;
    if !finite(&[r.x, r.y, r.w, r.h]) || r.w < MIN_FRAME || r.h < MIN_FRAME {
        return Err(bad("The camera's frame isn't valid."));
    }
    let slack_x = v.w * 0.25;
    let slack_y = v.h * 0.25;
    if r.x < -slack_x || r.y < -slack_y || r.x + r.w > v.w + slack_x || r.y + r.h > v.h + slack_y {
        return Err(bad("The camera's frame is off the screen."));
    }
    Ok(*r)
}

/// A tap: finite and on the screen.
pub fn point(p: &Point, v: &Size) -> Result<Point, Error> {
    if !finite(&[p.x, p.y]) || p.x < 0.0 || p.y < 0.0 || p.x > v.w || p.y > v.h {
        return Err(bad("The focus point is off the screen."));
    }
    Ok(*p)
}

/// A still's id (made by native code, echoed back by the web view): 1-40 of A-Z a-z 0-9 and '-'.
pub fn id(s: &str) -> Result<&str, Error> {
    if s.is_empty() || s.len() > 40 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(bad("That photo id isn't valid."));
    }
    Ok(s)
}

/// What native code hands back for `take`: base64 of a JPEG, no bigger than MAX_JPEG. Returns
/// the bytes. Anything else (a PNG, a HEIC, text, an empty answer) is refused.
pub fn jpeg_b64(s: &str) -> Result<Vec<u8>, Error> {
    // 4 base64 characters per 3 bytes; refuse before decoding anything huge
    if s.len() > MAX_JPEG / 3 * 4 + 8 {
        return Err(bad("The photo is too large."));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| bad("The camera gave back something that isn't a photo."))?;
    jpeg(&bytes)?;
    Ok(bytes)
}

/// A JPEG: starts with SOI and a marker, ends with EOI, within MAX_JPEG.
pub fn jpeg(b: &[u8]) -> Result<(), Error> {
    if b.len() < 64 || b.len() > MAX_JPEG {
        return Err(bad("The photo's size isn't valid."));
    }
    if b[0] != 0xFF
        || b[1] != 0xD8
        || b[2] != 0xFF
        || b[b.len() - 2] != 0xFF
        || b[b.len() - 1] != 0xD9
    {
        return Err(bad("The camera gave back something that isn't a JPEG."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: Size = Size { w: 412.0, h: 915.0 };
    const R: Rect = Rect {
        x: 16.0,
        y: 300.0,
        w: 380.0,
        h: 240.0,
    };

    #[test]
    fn view_sizes() {
        assert!(view(&V).is_ok());
        for s in [
            Size { w: 0.0, h: 915.0 },
            Size { w: 99.0, h: 915.0 },
            Size {
                w: 412.0,
                h: 20_000.0,
            },
            Size {
                w: f64::NAN,
                h: 915.0,
            },
            Size {
                w: f64::INFINITY,
                h: 915.0,
            },
            Size {
                w: -412.0,
                h: 915.0,
            },
        ] {
            assert!(view(&s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn frames() {
        assert!(frame(&R, &V).is_ok());
        // a little past the edge while a layout settles
        assert!(frame(&Rect { x: -20.0, ..R }, &V).is_ok());
        for r in [
            Rect { w: 10.0, ..R },
            Rect { h: 0.0, ..R },
            Rect { w: -380.0, ..R },
            Rect { x: f64::NAN, ..R },
            Rect {
                y: f64::NEG_INFINITY,
                ..R
            },
            Rect { x: 5_000.0, ..R },
            Rect { y: -400.0, ..R },
            Rect { w: 5_000.0, ..R },
        ] {
            assert!(frame(&r, &V).is_err(), "{r:?}");
        }
        // the view is checked too
        assert!(frame(&R, &Size { w: 0.0, h: 0.0 }).is_err());
    }

    #[test]
    fn points() {
        assert!(point(&Point { x: 200.0, y: 400.0 }, &V).is_ok());
        assert!(point(&Point { x: 0.0, y: 0.0 }, &V).is_ok());
        for p in [
            Point { x: -1.0, y: 400.0 },
            Point { x: 413.0, y: 400.0 },
            Point { x: 200.0, y: 916.0 },
            Point {
                x: f64::NAN,
                y: 1.0,
            },
        ] {
            assert!(point(&p, &V).is_err(), "{p:?}");
        }
    }

    #[test]
    fn ids() {
        assert!(id("a1b2-C3").is_ok());
        assert!(id(&"x".repeat(40)).is_ok());
        for s in [
            "",
            "../etc",
            "a b",
            "a\u{0}b",
            "é",
            &"x".repeat(41),
            "a/b",
            "a.b",
        ] {
            assert!(id(s).is_err(), "{s:?}");
        }
    }

    fn fake_jpeg(n: usize) -> Vec<u8> {
        let mut b = vec![0xFF, 0xD8, 0xFF, 0xE0];
        b.resize(n - 2, 0x11);
        b.extend([0xFF, 0xD9]);
        b
    }

    #[test]
    fn jpegs() {
        let ok = fake_jpeg(200);
        assert!(jpeg(&ok).is_ok());
        let enc = base64::engine::general_purpose::STANDARD.encode(&ok);
        assert_eq!(jpeg_b64(&enc).unwrap(), ok);
        // not a JPEG
        let mut png = ok.clone();
        png[0] = 0x89;
        assert!(jpeg(&png).is_err());
        let mut cut = ok.clone();
        cut.truncate(150);
        assert!(jpeg(&cut).is_err(), "no end marker");
        assert!(jpeg(&[0xFF, 0xD8, 0xFF, 0xD9]).is_err(), "too small");
        assert!(jpeg_b64("not base64 !!!").is_err());
        assert!(jpeg_b64("").is_err());
        // too large is refused before decoding
        assert!(jpeg_b64(&"A".repeat(MAX_JPEG / 3 * 4 + 100)).is_err());
    }
}
