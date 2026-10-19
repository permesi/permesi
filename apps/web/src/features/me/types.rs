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

/// Saved delegated consent bound to one client and organization.
#[derive(Clone, Debug, Deserialize)]
pub struct SavedGrant {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub application_name: String,
    pub organization_slug: String,
    pub organization_name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
}

/// Bounded keyset page of the current user's active OAuth grants.
#[derive(Clone, Debug, Deserialize)]
pub struct SavedGrantPage {
    pub grants: Vec<SavedGrant>,
    pub next_cursor: Option<String>,
}
