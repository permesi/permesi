//! Session kind markers for enforcing MFA bootstrap and challenge gating.
//!
//! Flow Overview:
//! - Tokens without a prefix are full sessions.
//! - `mfa_setup_` tokens are bootstrap sessions limited to MFA setup routes.
//! - `mfa_challenge_` tokens are MFA challenge sessions limited to verification routes.
//!
//! Security boundaries: session kind is derived from the token prefix; the token
//! is still validated against server-side storage before any access is granted.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Prefix for MFA bootstrap session tokens.
pub(crate) const MFA_BOOTSTRAP_PREFIX: &str = "mfa_setup_";
/// Prefix for MFA challenge session tokens.
pub(crate) const MFA_CHALLENGE_PREFIX: &str = "mfa_challenge_";

/// Session kinds used to gate MFA bootstrap and challenge flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// Full session with normal access.
    Full,
    /// Bootstrap session limited to MFA setup and recovery flows.
    MfaBootstrap,
    /// Challenge session limited to MFA verification flows.
    MfaChallenge,
}

impl SessionKind {
    /// Classify a session token by its prefix.
    pub(crate) fn from_token(token: &str) -> Self {
        if token.starts_with(MFA_BOOTSTRAP_PREFIX) {
            Self::MfaBootstrap
        } else if token.starts_with(MFA_CHALLENGE_PREFIX) {
            Self::MfaChallenge
        } else {
            Self::Full
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MFA_BOOTSTRAP_PREFIX, MFA_CHALLENGE_PREFIX, SessionKind};

    #[test]
    fn session_kind_from_token_classifies_prefixes() {
        assert_eq!(
            SessionKind::from_token(&format!("{MFA_BOOTSTRAP_PREFIX}token")),
            SessionKind::MfaBootstrap
        );
        assert_eq!(
            SessionKind::from_token(&format!("{MFA_CHALLENGE_PREFIX}token")),
            SessionKind::MfaChallenge
        );
        assert_eq!(SessionKind::from_token("plain"), SessionKind::Full);
    }
}
