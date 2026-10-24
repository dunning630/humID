//! The allow-list of inner (app) routes and the unit each goes to. Anything not here is a 404
//! before any unit sees it. HTP/2 frames will be dispatched through [`resolve`].

use crate::unit::Role;

/// Whether a route needs a signed-in session (front forwards the token; core checks it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// No session (a new device, or the anonymous messaging session).
    Anonymous,
    /// A signed-in session.
    Session,
    /// Must be a session that never signed in (messaging: nothing links an account to a mailbox).
    NeverSignedIn,
}

/// One route.
pub struct Route {
    /// Method.
    pub method: &'static str,
    /// Path pattern: `{id}` is 64 hex, `{code}` a code, `{n}` a number, `{req}` base64url, `{ref}` 16 hex.
    pub path: &'static str,
    /// Which unit.
    pub unit: Role,
    /// Session rule.
    pub auth: Auth,
}

macro_rules! r {
    ($m:literal, $p:literal, $u:ident, $a:ident) => {
        Route {
            method: $m,
            path: $p,
            unit: Role::$u,
            auth: Auth::$a,
        }
    };
}

/// Every app route.
pub const ROUTES: &[Route] = &[
    r!("POST", "/v1/auth/register", Core, Anonymous),
    r!("POST", "/v1/auth/challenge", Core, Anonymous),
    r!("POST", "/v1/auth/login", Core, Anonymous),
    r!("POST", "/v1/auth/logout", Core, Session),
    r!("POST", "/v1/auth/nonces", Core, Session),
    r!("GET", "/v1/me", Core, Session),
    r!("DELETE", "/v1/me", Core, Session),
    r!("POST", "/v1/sync", Core, Session),
    r!("POST", "/v1/duress/clear", Core, Session),
    r!("GET", "/v1/keys-kem", Core, Session),
    r!("POST", "/v1/links", Core, Anonymous),
    r!("GET", "/v1/links/{code}", Core, Session),
    r!("POST", "/v1/links/{code}/approve", Core, Session),
    r!("GET", "/v1/links/{code}/result", Core, Anonymous),
    r!("POST", "/v1/devices", Core, Anonymous),
    r!("DELETE", "/v1/devices/{id}", Core, Session),
    r!("POST", "/v1/objects", Core, Session),
    r!("PATCH", "/v1/objects/{id}", Core, Session),
    r!("DELETE", "/v1/objects/{id}", Core, Session),
    r!("POST", "/v1/objects/{id}/open", Core, Session),
    r!("GET", "/v1/objects/{id}/chunks/{n}", Core, Session),
    r!("GET", "/v1/ledger/events", Core, Session),
    r!("GET", "/v1/ledger/inclusion", Core, Session),
    r!("PUT", "/v1/recovery/mode", Core, Session),
    r!("PUT", "/v1/recovery/card", Core, Session),
    r!("DELETE", "/v1/recovery/card", Core, Session),
    r!("PUT", "/v1/recovery/witnesses", Core, Session),
    r!("DELETE", "/v1/recovery/witnesses", Core, Session),
    r!("POST", "/v1/recovery/requests", Core, Anonymous),
    r!("GET", "/v1/recovery/requests/{req}", Core, Anonymous),
    r!("POST", "/v1/recovery/requests/{req}/card", Core, Anonymous),
    r!(
        "POST",
        "/v1/recovery/requests/{req}/anchor",
        Core,
        Anonymous
    ),
    r!("POST", "/v1/recovery/requests/{req}/key", Core, Anonymous),
    r!("GET", "/v1/recovery/help/{code}", Core, Session),
    r!("POST", "/v1/recovery/help/{code}", Core, Session),
    r!("GET", "/v1/recovery/alerts", Core, Session),
    r!("POST", "/v1/recovery/alerts/{ref}/cancel", Core, Session),
    r!("GET", "/v1/checkin", Core, Session),
    r!("POST", "/v1/checkin/arm", Core, Session),
    r!("POST", "/v1/checkin/check", Core, Session),
    r!("POST", "/v1/checkin/disarm", Core, Session),
    r!("POST", "/v1/live/attest", Core, Session),
    r!("GET", "/v1/pass/keys", Anon, NeverSignedIn),
    r!("POST", "/v1/pass/issue", Anon, NeverSignedIn),
    r!("POST", "/v1/pass/spend", Anon, NeverSignedIn),
    r!("GET", "/v1/post-tokens/keys", Anon, NeverSignedIn),
    r!("POST", "/v1/post-tokens", Anon, NeverSignedIn),
    r!("POST", "/v1/relay/deposit", Anon, NeverSignedIn),
    r!("POST", "/v1/relay/tick", Anon, NeverSignedIn),
    r!("POST", "/v1/relay/fetch", Anon, NeverSignedIn),
    r!("POST", "/v1/relay/ack", Anon, NeverSignedIn),
    r!("POST", "/v1/relay/retract", Anon, NeverSignedIn),
    r!("POST", "/v1/push/subscribe", Anon, NeverSignedIn),
];

fn seg_ok(pattern: &str, seg: &str) -> bool {
    let hex = |n: usize| {
        seg.len() == n
            && seg
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    match pattern {
        "{id}" => hex(64),
        "{ref}" => hex(16),
        "{code}" => (12..=20).contains(&seg.len()) && crate::wire::is_code(seg, seg.len()),
        "{n}" => !seg.is_empty() && seg.len() <= 6 && seg.bytes().all(|b| b.is_ascii_digit()),
        "{req}" => {
            seg.len() == 22
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }
        lit => lit == seg,
    }
}

/// The route for `method path` (query string ignored), if it is allowed.
#[must_use]
pub fn resolve(method: &str, path: &str) -> Option<&'static Route> {
    let path = path.split('?').next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').collect();
    ROUTES.iter().find(|r| {
        if r.method != method {
            return false;
        }
        let ps: Vec<&str> = r.path.split('/').collect();
        ps.len() == segs.len() && ps.iter().zip(&segs).all(|(p, s)| seg_ok(p, s))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list() {
        let id = "ab".repeat(32);
        assert_eq!(
            resolve("POST", &format!("/v1/objects/{id}/open"))
                .unwrap()
                .unit,
            Role::Core
        );
        assert!(
            resolve("POST", "/v1/objects/zz/open").is_none(),
            "ids are strict"
        );
        assert_eq!(
            resolve("POST", "/v1/relay/tick").unwrap().auth,
            Auth::NeverSignedIn
        );
        assert!(resolve("GET", "/internal/anything").is_none());
        assert!(
            resolve("POST", "/v1/shares").is_none(),
            "keys is never reachable from the app"
        );
        assert!(
            resolve("POST", "/v1/ledger/events").is_none(),
            "no route writes the ledger (M3)"
        );
        assert!(
            resolve("POST", "/v1/duress").is_none(),
            "duress comes only inside a signed sign-in (M2)"
        );
    }

    #[test]
    fn no_route_reaches_keys() {
        assert!(
            ROUTES
                .iter()
                .all(|r| r.unit != Role::Keys && r.unit != Role::Front)
        );
    }
}
