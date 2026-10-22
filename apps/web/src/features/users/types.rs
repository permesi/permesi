//! User data types consumed by frontend routes and API clients.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Summary representation returned by the users list endpoint.
pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Detailed representation returned by the user detail endpoint.
pub struct UserDetail {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub locale: Option<String>,
    pub role: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Server-issued operator designation state; browser controls are only UX hints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorStatus {
    pub designation: String,
    pub pending_enable: bool,
    pub requested_by_me: bool,
    pub requested_by_email: Option<String>,
    pub requested_reason: Option<String>,
    pub requested_at: Option<String>,
    pub can_approve: bool,
}
