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
}
