//! Request/response types for auth endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use super::session_kind::SessionKind;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OpaqueSignupStartRequest {
    pub email: String,
    pub registration_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupStartResponse {
    pub registration_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OpaqueSignupFinishRequest {
    pub email: String,
    pub registration_record: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupFinishResponse {
    pub message: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginStartRequest {
    pub email: String,
    pub credential_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginStartResponse {
    /// Unguessable single-attempt reference; only its hash is stored in shared PostgreSQL.
    pub login_id: String,
    pub credential_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginFinishRequest {
    pub login_id: String,
    /// Compatibility field; authority comes from the server-bound exchange identity.
    pub email: String,
    pub credential_finalization: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueReauthStartRequest {
    pub credential_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueReauthFinishRequest {
    pub login_id: String,
    pub credential_finalization: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaquePasswordStartRequest {
    pub registration_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaquePasswordStartResponse {
    pub registration_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaquePasswordFinishRequest {
    pub registration_record: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct SessionResponse {
    pub user_id: String,
    pub email: String,
    pub is_operator: bool,
    pub session_kind: SessionKind,
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
}

/// Payload for verifying an MFA recovery code during challenge.
#[derive(ToSchema, Serialize, Deserialize)]
pub struct MfaRecoveryRequest {
    pub code: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct MfaTotpEnrollStartResponse {
    pub secret: String,
    pub qr_code_url: String,
    pub credential_id: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct MfaTotpEnrollFinishRequest {
    pub code: String,
    pub credential_id: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct MfaTotpVerifyRequest {
    pub code: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct WebauthnRegisterStartResponse {
    pub reg_id: String,
    pub challenge: serde_json::Value,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct WebauthnRegisterFinishRequest {
    pub reg_id: String,
    pub label: String,
    /// `PublicKeyCredential` JSON returned by `navigator.credentials.create()`.
    #[schema(value_type = Object)]
    pub response: RegisterPublicKeyCredential,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct WebauthnAuthenticateStartResponse {
    pub auth_id: String,
    pub challenge: serde_json::Value,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct WebauthnAuthenticateFinishRequest {
    pub auth_id: String,
    /// `PublicKeyCredential` JSON returned by `navigator.credentials.get()`.
    #[schema(value_type = Object)]
    pub response: PublicKeyCredential,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminStatusResponse {
    pub bootstrap_open: bool,
    pub operator: bool,
    pub cooldown_seconds: u64,
}

#[derive(ToSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminBootstrapRequest {
    pub openbao_token: String,
    pub note: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminBootstrapResponse {
    pub ok: bool,
    pub bootstrap_complete: bool,
}

#[derive(ToSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminElevateRequest {
    pub openbao_token: String,
}

/// The elevation is held server-side against the session; nothing here is a credential.
#[derive(ToSchema, Serialize, Deserialize)]
pub struct AdminElevateResponse {
    /// When the session's elevation ends (RFC 3339, UTC, to the microsecond).
    pub expires_at: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminInfraResponse {
    pub database: DatabaseStats,
    pub openbao: OpenBaoStatus,
    pub platform: PlatformStats,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct DatabaseStats {
    pub status: String,
    pub pool_size: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub permesi_size_bytes: Option<i64>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpenBaoStatus {
    pub status: String,
    pub version: String,
    pub sealed: bool,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct PlatformStats {
    /// Operator designations, enabled or not; `null` when the count could not be read.
    #[schema(required = true)]
    pub operator_count: Option<i64>,
    /// Bootstrap and elevation attempts in the last hour; `null` when unreadable.
    #[schema(required = true)]
    pub recent_attempts_count: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};

    #[test]
    fn opaque_signup_start_request_round_trips() -> Result<()> {
        let request = OpaqueSignupStartRequest {
            email: "alice@example.com".to_string(),
            registration_request: "opaque".to_string(),
        };
        let value = serde_json::to_value(&request)?;
        let email = value
            .get("email")
            .and_then(serde_json::Value::as_str)
            .context("missing email")?;
        assert_eq!(email, "alice@example.com");
        let decoded: OpaqueSignupStartRequest = serde_json::from_value(value)?;
        assert_eq!(decoded.registration_request, "opaque");
        Ok(())
    }

    #[test]
    fn resend_verification_request_round_trips() -> Result<()> {
        let request = ResendVerificationRequest {
            email: "bob@example.com".to_string(),
        };
        let value = serde_json::to_value(&request)?;
        let decoded: ResendVerificationRequest = serde_json::from_value(value)?;
        assert_eq!(decoded.email, "bob@example.com");
        Ok(())
    }

    #[test]
    fn opaque_reauth_start_request_round_trips() -> Result<()> {
        let request = OpaqueReauthStartRequest {
            credential_request: "opaque".to_string(),
        };
        let value = serde_json::to_value(&request)?;
        let decoded: OpaqueReauthStartRequest = serde_json::from_value(value)?;
        assert_eq!(decoded.credential_request, "opaque");
        Ok(())
    }

    #[test]
    fn opaque_password_finish_request_round_trips() -> Result<()> {
        let request = OpaquePasswordFinishRequest {
            registration_record: "record".to_string(),
        };
        let value = serde_json::to_value(&request)?;
        let decoded: OpaquePasswordFinishRequest = serde_json::from_value(value)?;
        assert_eq!(decoded.registration_record, "record");
        Ok(())
    }
}
