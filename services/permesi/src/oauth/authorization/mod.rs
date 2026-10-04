//! PostgreSQL-backed Authorization Code + S256 PKCE state machine.
//!
//! Flow Overview: validate registration/redirect/protocol, persist a browser-bound
//! request, reuse the existing full session after login/MFA, verify tenant membership,
//! obtain exact consent, and atomically complete the request while inserting a hashed
//! short-lived code. Every resume and redemption reloads current authority under locks.
//! No process-local request/code storage, sticky routing, or token issuance is used.
//! Internal Principal permissions are not inputs to this module. Current resource
//! policy permits active org members to consent to registered delegation only within
//! that client's application; downstream APIs still enforce resource/object policy.

pub(crate) mod crypto;
pub mod redemption;
pub(crate) mod request;
mod storage;

use crate::oauth::redirect_uri::RedirectUri;

/// Stable protocol errors with no submitted identifiers or authorization detail.
#[derive(Clone, Copy)]
pub(crate) enum ProtocolError {
    InvalidRequest,
    InvalidScope,
    UnsupportedResponseType,
    AccessDenied,
    LoginRequired,
    ConsentRequired,
    InvalidGrant,
}

impl ProtocolError {
    /// Returns only registered protocol error tokens; descriptions are intentionally omitted.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InvalidGrant => "invalid_grant",
        }
    }
}

/// Value-free errors; redirect presence proves the exact allow-list boundary was crossed.
pub(crate) struct Error {
    pub protocol: ProtocolError,
    pub redirect: Option<RedirectUri>,
    pub state: Option<String>,
    pub database: bool,
}

impl Error {
    /// Constructs a direct protocol error without any implicit redirect authority.
    pub(crate) fn protocol(protocol: ProtocolError) -> Self {
        Self {
            protocol,
            redirect: None,
            state: None,
            database: false,
        }
    }
    /// Attaches a redirect only after an exact active-registration comparison succeeds.
    pub(crate) fn with_redirect(mut self, redirect: RedirectUri, state: Option<String>) -> Self {
        self.redirect = Some(redirect);
        self.state = state;
        self
    }
}

impl From<sqlx::Error> for Error {
    /// Logs only SQLSTATE class under the existing route/span, discarding all error text,
    /// SQL and parameters so diagnostics cannot expose authorization or secret material.
    fn from(error: sqlx::Error) -> Self {
        let code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .filter(|code| {
                code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
            });
        let class = code
            .as_deref()
            .and_then(|code| code.get(..2))
            .unwrap_or("none");
        tracing::error!(sqlstate_class = class, "OAuth database operation failed");
        Self {
            database: true,
            ..Self::protocol(ProtocolError::InvalidRequest)
        }
    }
}

impl From<getrandom::Error> for Error {
    /// Treats entropy failure as an internal failure; no predictable fallback is permitted.
    fn from(_: getrandom::Error) -> Self {
        Self {
            database: true,
            ..Self::protocol(ProtocolError::InvalidRequest)
        }
    }
}

pub(crate) use storage::{AuthorizationService, Decision, Outcome, SessionBinding};

impl std::fmt::Debug for Error {
    /// Omits redirect, state and SQL detail even when an error is formatted by a caller.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuth authorization failed")
    }
}
impl std::fmt::Display for Error {
    /// Uses a stable value-free message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuth authorization failed")
    }
}
impl std::error::Error for Error {}
