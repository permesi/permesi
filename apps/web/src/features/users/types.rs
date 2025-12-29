use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSummary {
    pub id: String,
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserDetail {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
}
