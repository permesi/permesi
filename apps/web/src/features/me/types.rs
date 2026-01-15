//! Types for /me API responses.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeProfile {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub locale: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub mfa_enabled: bool,
    pub totp_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityKeySummary {
    pub credential_id: String,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}
