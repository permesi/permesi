//! Request/response types for auth endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupStartRequest {
    pub email: String,
    pub registration_request: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueSignupStartResponse {
    pub registration_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
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
    pub login_id: String,
    pub credential_response: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct OpaqueLoginFinishRequest {
    pub login_id: String,
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

#[derive(ToSchema, Serialize, Deserialize, Debug)]
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
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminStatusResponse {
    pub bootstrap_open: bool,
    pub operator: bool,
    pub cooldown_seconds: u64,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AdminBootstrapRequest {
    pub vault_token: String,
    pub note: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminBootstrapResponse {
    pub ok: bool,
    pub bootstrap_complete: bool,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AdminElevateRequest {
    pub vault_token: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminElevateResponse {
    pub admin_token: String,
    pub expires_at: String,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct AdminInfraResponse {
    pub database: DatabaseStats,
    pub vault: VaultStatus,
    pub platform: PlatformStats,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct DatabaseStats {
    pub status: String,
    pub pool_size: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct VaultStatus {
    pub status: String,
    pub version: String,
    pub sealed: bool,
}

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct PlatformStats {
    pub operator_count: i64,
    pub recent_attempts_count: i64,
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
