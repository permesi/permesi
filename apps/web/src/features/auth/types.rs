use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueSignupStartRequest {
    pub username: String,
    pub email: String,
    pub registration_request: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueSignupStartResponse {
    pub registration_response: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpaqueSignupFinishRequest {
    pub username: String,
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
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: String,
    pub access_token: String,
}
