pub mod health;
pub use self::health::health;

pub mod user_register;
pub use self::user_register::register;

pub mod user_login;
pub use self::user_login::login;

// common functions for the handlers
use admission_token::{AdmissionTokenClaims, Jwks, verify_rs256};
use regex::Regex;
use std::time::SystemTime;
use tracing::{error, instrument};

pub fn valid_email(email: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").is_ok_and(|re| re.is_match(email))
}

pub fn valid_password(password: &str) -> bool {
    // length must be between 64 hex characters
    Regex::new(r"^[0-9a-fA-F]{64}$").is_ok_and(|re| re.is_match(password))
}

#[derive(Debug, Clone)]
pub struct AdmissionVerifier {
    jwks: Jwks,
    issuer: String,
    audience: String,
}

impl AdmissionVerifier {
    #[must_use]
    pub fn new(jwks: Jwks, issuer: String, audience: String) -> Self {
        Self {
            jwks,
            issuer,
            audience,
        }
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[instrument]
pub fn verify_token(verifier: &AdmissionVerifier, token: &str) -> bool {
    verify_token_claims(verifier, token).is_some()
}

pub fn verify_token_claims(
    verifier: &AdmissionVerifier,
    token: &str,
) -> Option<AdmissionTokenClaims> {
    match verify_rs256(
        token,
        &verifier.jwks,
        &verifier.issuer,
        &verifier.audience,
        now_unix_seconds(),
    ) {
        Ok(claims) => Some(claims),
        Err(e) => {
            error!("Admission token verification failed: {e}");
            None
        }
    }
}
