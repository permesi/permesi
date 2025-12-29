use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: String,
    pub access_token: String,
}
