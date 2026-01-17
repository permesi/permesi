//! Request and response types for auth-related API calls. These payloads carry
//! OPAQUE transcripts and verification tokens, so they must never be logged.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueSignupStartRequest {
    pub email: String,
    pub registration_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueSignupStartResponse {
    pub registration_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueSignupFinishRequest {
    pub email: String,
    pub registration_record: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueLoginStartRequest {
    pub email: String,
    pub credential_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueLoginStartResponse {
    pub login_id: String,
    pub credential_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueLoginFinishRequest {
    pub login_id: String,
    pub email: String,
    pub credential_finalization: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueReauthStartRequest {
    pub credential_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueReauthFinishRequest {
    pub login_id: String,
    pub credential_finalization: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaquePasswordStartRequest {
    pub registration_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaquePasswordStartResponse {
    pub registration_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaquePasswordFinishRequest {
    pub registration_record: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Full,
    MfaBootstrap,
    MfaChallenge,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Session summary returned by the API to hydrate auth state.
/// This mirrors cookie-backed session state and contains no secrets.
pub struct UserSession {
    pub user_id: String,
    pub email: String,
    pub is_operator: bool,
    pub session_kind: SessionKind,
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaTotpEnrollStartResponse {
    pub secret: String,
    pub qr_code_url: String,
    pub credential_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaTotpEnrollFinishRequest {
    pub code: String,
    pub credential_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaTotpVerifyRequest {
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnRegisterStartResponse {
    pub reg_id: String,
    pub challenge: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnRegisterFinishRequest {
    pub reg_id: String,
    pub label: String,
    pub response: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnAuthenticateStartResponse {
    pub auth_id: String,
    pub challenge: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnAuthenticateFinishRequest {
    pub auth_id: String,
    pub response: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyLoginStartRequest {
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyLoginStartResponse {
    pub auth_id: String,
    pub challenge: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyLoginFinishRequest {
    pub auth_id: String,
    pub response: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaRecoveryRequest {
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub commit: String,
    pub name: String,
    pub version: String,
    pub database: String,
    pub admission_keyset: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let health = HealthResponse {
            commit: "abcdef1".to_string(),
            name: "permesi".to_string(),
            version: "0.1.0".to_string(),
            database: "ok".to_string(),
            admission_keyset: "ok".to_string(),
        };

        let json = serde_json::to_string(&health).expect("Failed to serialize");
        assert!(json.contains("abcdef1"));
        assert!(json.contains("permesi"));

        let deserialized: HealthResponse =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.commit, "abcdef1");
        assert_eq!(deserialized.name, "permesi");
        assert_eq!(deserialized.database, "ok");
    }
}
