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
