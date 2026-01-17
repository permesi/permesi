//! Types for passkey (WebAuthn) API requests and responses.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone)]
pub struct PasskeyRegisterOptionsResponse {
    pub reg_id: String,
    pub challenge: serde_json::Value,
    pub preview_mode: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegisterFinishRequest {
    pub reg_id: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasskeyRegisterFinishResponse {
    pub stored: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasskeyCredentialSummary {
    pub id: String,
    pub label: Option<String>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasskeyCredentialListResponse {
    pub preview_mode: bool,
    pub credentials: Vec<PasskeyCredentialSummary>,
}
