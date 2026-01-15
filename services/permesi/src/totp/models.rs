use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum TotpDekStatus {
    Active,
    DecryptOnly,
    Retired,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TotpDek {
    pub dek_id: Uuid,
    pub status: TotpDekStatus,
    pub wrapped_dek: String,
    pub kek_mount: String,
    pub kek_key: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct TotpCredential {
    pub credential_id: Uuid,
    pub user_id: Uuid,
    pub label: Option<String>,
    pub digits: i16,
    pub period: i16,
    pub algo: String,
    pub dek_id: Uuid,
    pub seed_ciphertext: Vec<u8>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpAuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Option<Uuid>,
    pub action: String,
    pub ip_address: Option<String>, // INET types can be tricky, using String for simplicity in struct
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}
