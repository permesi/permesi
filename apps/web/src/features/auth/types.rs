//! Request and response types for auth-related API calls. These payloads carry
//! OPAQUE transcripts and verification tokens, so they must never be logged.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for starting OPAQUE signup; carries the registration request.
/// The request contains protocol transcripts and must never be logged.
pub struct OpaqueSignupStartRequest {
    pub email: String,
    pub registration_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Response for OPAQUE signup start; contains the registration response.
/// The response contains protocol transcripts and must never be logged.
pub struct OpaqueSignupStartResponse {
    pub registration_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for completing OPAQUE signup; contains the registration record.
/// The record contains protocol transcripts and must never be logged.
pub struct OpaqueSignupFinishRequest {
    pub email: String,
    pub registration_record: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for starting OPAQUE login; contains the credential request.
/// The request contains protocol transcripts and must never be logged.
pub struct OpaqueLoginStartRequest {
    pub email: String,
    pub credential_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Response for OPAQUE login start; contains the credential response.
/// The response contains protocol transcripts and must never be logged.
pub struct OpaqueLoginStartResponse {
    pub login_id: String,
    pub credential_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for completing OPAQUE login; contains the finalization message.
/// The message contains protocol transcripts and must never be logged.
pub struct OpaqueLoginFinishRequest {
    pub login_id: String,
    pub email: String,
    pub credential_finalization: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for starting OPAQUE re-auth; contains the credential request.
/// The request contains protocol transcripts and must never be logged.
pub struct OpaqueReauthStartRequest {
    pub credential_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for completing OPAQUE re-auth; contains the finalization message.
/// The message contains protocol transcripts and must never be logged.
pub struct OpaqueReauthFinishRequest {
    pub login_id: String,
    pub credential_finalization: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for starting OPAQUE password change; contains the registration request.
/// The request contains protocol transcripts and must never be logged.
pub struct OpaquePasswordStartRequest {
    pub registration_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Response for OPAQUE password change start; contains the registration response.
/// The response contains protocol transcripts and must never be logged.
pub struct OpaquePasswordStartResponse {
    pub registration_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for completing OPAQUE password change; contains the registration record.
/// The record contains protocol transcripts and must never be logged.
pub struct OpaquePasswordFinishRequest {
    pub registration_record: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for verifying an email token; the token must never be logged.
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Payload for requesting a new verification email; email must not be logged.
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Session summary returned by the API to hydrate auth state.
/// This mirrors cookie-backed session state and contains no secrets.
pub struct UserSession {
    pub user_id: String,
    pub email: String,
    pub is_operator: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminStatusResponse {
    pub bootstrap_open: bool,
    pub operator: bool,
    pub cooldown_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminBootstrapRequest {
    pub vault_token: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminBootstrapResponse {
    pub ok: bool,
    pub bootstrap_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminElevateRequest {
    pub vault_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminElevateResponse {
    pub admin_token: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminInfraResponse {
    pub database: DatabaseStats,
    pub vault: VaultStatus,
    pub platform: PlatformStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub status: String,
    pub pool_size: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub permesi_size_bytes: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultStatus {
    pub status: String,
    pub version: String,
    pub sealed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformStats {
    pub operator_count: i64,
    pub recent_attempts_count: i64,
}
