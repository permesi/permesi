use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, postgres::PgRow};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKey {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub label: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl<'r> FromRow<'r, PgRow> for SecurityKey {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            credential_id: row.try_get("credential_id")?,
            user_id: row.try_get("user_id")?,
            label: row.try_get("label")?,
            public_key: row.try_get("public_key")?,
            sign_count: row.try_get("sign_count")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub label: Option<String>,
    pub passkey_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl<'r> FromRow<'r, PgRow> for PasskeyCredential {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            credential_id: row.try_get("credential_id")?,
            user_id: row.try_get("user_id")?,
            label: row.try_get("label")?,
            passkey_data: row.try_get("passkey_data")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
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
