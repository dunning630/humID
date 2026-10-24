//! One error type for every unit, mapped to an HTTP status and a stable `code` the app shows.
//!
//! Messages never carry secrets, account ids or request bodies. A refused proof says *that*
//! it was refused, never which check failed beyond the code.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// What a unit can answer instead of doing the thing.
#[derive(Debug)]
pub enum Error {
    /// 400: the request is malformed.
    BadRequest(&'static str, String),
    /// 401: no session, or a proof that doesn't verify.
    Unauthorized(&'static str, String),
    /// 403: verified, but not allowed.
    Forbidden(&'static str, String),
    /// 404: no such thing (also used where "exists but not yours" must look the same).
    NotFound(&'static str, String),
    /// 409: conflicts with the current state.
    Conflict(&'static str, String),
    /// 410: gone for good (a Check-in erase).
    Gone(&'static str, String),
    /// 413: over a size cap.
    TooLarge(&'static str, String),
    /// 423: locked (a missed Check-in).
    Locked(&'static str, String),
    /// 429: over a rate limit or cap.
    TooMany(&'static str, String),
    /// 501: depends on a format still being designed. Never a panic, never `todo!()`.
    NotImplemented {
        /// What isn't built.
        what: &'static str,
        /// What it waits on (a spec, a crate, a decision).
        waiting_on: &'static str,
    },
    /// 503: a dependency (another unit, the database) is unavailable, or the unit is busy.
    Unavailable(&'static str, String),
    /// Another unit refused; its answer is passed on as it came (status, code, words).
    Upstream {
        /// The other unit's HTTP status.
        status: u16,
        /// Its error code.
        code: String,
        /// Its message.
        message: String,
    },
    /// 500: a bug or an unexpected failure. The detail is logged, not returned.
    Internal(String),
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Error::BadRequest(..) => StatusCode::BAD_REQUEST,
            Error::Unauthorized(..) => StatusCode::UNAUTHORIZED,
            Error::Forbidden(..) => StatusCode::FORBIDDEN,
            Error::NotFound(..) => StatusCode::NOT_FOUND,
            Error::Conflict(..) => StatusCode::CONFLICT,
            Error::Gone(..) => StatusCode::GONE,
            Error::TooLarge(..) => StatusCode::PAYLOAD_TOO_LARGE,
            Error::Locked(..) => StatusCode::LOCKED,
            Error::TooMany(..) => StatusCode::TOO_MANY_REQUESTS,
            Error::NotImplemented { .. } => StatusCode::NOT_IMPLEMENTED,
            Error::Unavailable(..) => StatusCode::SERVICE_UNAVAILABLE,
            Error::Upstream { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The error code, including one passed on from another unit.
    #[must_use]
    pub fn code_str(&self) -> &str {
        match self {
            Error::Upstream { code, .. } => code,
            other => other.code(),
        }
    }

    /// The stable error code (`"upstream"` for another unit's refusal; see [`Error::code_str`]).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Error::BadRequest(c, _)
            | Error::Unauthorized(c, _)
            | Error::Forbidden(c, _)
            | Error::NotFound(c, _)
            | Error::Conflict(c, _)
            | Error::Gone(c, _)
            | Error::TooLarge(c, _)
            | Error::Locked(c, _)
            | Error::TooMany(c, _)
            | Error::Unavailable(c, _) => c,
            Error::NotImplemented { .. } => "not_implemented",
            Error::Upstream { .. } => "upstream",
            Error::Internal(_) => "internal",
        }
    }

    /// Words for the person (the app shows its own text per code; this is the fallback).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Error::BadRequest(_, m)
            | Error::Unauthorized(_, m)
            | Error::Forbidden(_, m)
            | Error::NotFound(_, m)
            | Error::Conflict(_, m)
            | Error::Gone(_, m)
            | Error::TooLarge(_, m)
            | Error::Locked(_, m)
            | Error::TooMany(_, m)
            | Error::Unavailable(_, m) => m.clone(),
            Error::NotImplemented { what, waiting_on } => {
                format!("{what} isn't built yet (waiting on {waiting_on}).")
            }
            Error::Upstream { message, .. } => message.clone(),
            Error::Internal(_) => "Something went wrong on the server. Try again.".into(),
        }
    }

    /// Shorthand constructors.
    pub fn bad(code: &'static str, msg: impl Into<String>) -> Self {
        Error::BadRequest(code, msg.into())
    }
    /// 401.
    pub fn unauth(code: &'static str, msg: impl Into<String>) -> Self {
        Error::Unauthorized(code, msg.into())
    }
    /// 403.
    pub fn forbidden(code: &'static str, msg: impl Into<String>) -> Self {
        Error::Forbidden(code, msg.into())
    }
    /// 404.
    pub fn not_found(code: &'static str, msg: impl Into<String>) -> Self {
        Error::NotFound(code, msg.into())
    }
    /// 409.
    pub fn conflict(code: &'static str, msg: impl Into<String>) -> Self {
        Error::Conflict(code, msg.into())
    }
    /// 429.
    pub fn too_many(code: &'static str, msg: impl Into<String>) -> Self {
        Error::TooMany(code, msg.into())
    }
    /// 503.
    pub fn unavailable(code: &'static str, msg: impl Into<String>) -> Self {
        Error::Unavailable(code, msg.into())
    }
    /// 500 (the detail goes to the log only).
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        Error::Internal(detail.to_string())
    }
    /// 503 `busy`: what a locked-down account sees for a sensitive change (looks temporary).
    #[must_use]
    pub fn busy() -> Self {
        Error::Unavailable(
            "busy",
            "HumID is busy right now. Try again in a few minutes.".into(),
        )
    }
    /// The one refusal for a holder proof that doesn't verify.
    #[must_use]
    pub fn bad_proof() -> Self {
        Error::Unauthorized("bad_proof", "The live check was refused.".into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.status().as_u16(),
            self.code_str(),
            self.message()
        )
    }
}

impl std::error::Error for Error {}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if let Error::Internal(detail) = &self {
            tracing::error!(%detail, "internal error");
        }
        let body = serde_json::json!({ "error": self.code_str(), "message": self.message() });
        (self.status(), axum::Json(body)).into_response()
    }
}

impl From<humid_pq2::Error> for Error {
    fn from(e: humid_pq2::Error) -> Self {
        match e {
            humid_pq2::Error::Verify | humid_pq2::Error::Decrypt => Error::bad_proof(),
            humid_pq2::Error::Encoding | humid_pq2::Error::Length | humid_pq2::Error::Label => {
                Error::bad("bad_encoding", "Malformed key, signature or sealed data.")
            }
            other => Error::internal(format!("crypto: {other}")),
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        // A serialization failure or deadlock is the caller's to retry, not a 500.
        if let Some(code) = e.code() {
            if *code == tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
                || *code == tokio_postgres::error::SqlState::T_R_DEADLOCK_DETECTED
            {
                return Error::unavailable("busy", "Busy. Try again.");
            }
            if *code == tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                return Error::conflict("exists", "That already exists.");
            }
        }
        Error::internal(format!("database: {e}"))
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        tracing::warn!(error = %e, "database pool");
        Error::unavailable("database_unavailable", "The database is unavailable.")
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        // L-14: the detail goes to the debug log, never to the caller
        tracing::debug!(error = %e, "malformed request");
        Error::bad("bad_json", "Malformed request.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_implemented_is_501_with_a_reason() {
        let e = Error::NotImplemented {
            what: "HTP/2",
            waiting_on: "the HTP/2 spec",
        };
        assert_eq!(e.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(e.code(), "not_implemented");
        assert!(e.message().contains("HTP/2 spec"));
    }

    #[test]
    fn internal_detail_is_not_returned() {
        let e = Error::internal("secret detail");
        assert!(!e.message().contains("secret"));
    }

    #[test]
    fn crypto_verify_failure_is_a_proof_refusal() {
        let e: Error = humid_pq2::Error::Verify.into();
        assert_eq!(e.code(), "bad_proof");
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
}
