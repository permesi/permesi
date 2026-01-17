use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SecurityKey {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub label: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKeyAuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Option<Vec<u8>>,
    pub action: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub label: Option<String>,
    pub passkey_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Option<Vec<u8>>,
    pub action: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}
