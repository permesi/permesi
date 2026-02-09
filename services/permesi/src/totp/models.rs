use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, postgres::PgRow};
use uuid::Uuid;

/// Status of a TOTP data-encryption key row loaded from `totp_deks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpDekStatus {
    Active,
    DecryptOnly,
    Retired,
}

impl TotpDekStatus {
    /// Parse the persisted `totp_deks.status` textual value into a typed enum.
    fn from_db(value: &str) -> Result<Self, sqlx::Error> {
        match value {
            "active" => Ok(Self::Active),
            "decrypt_only" => Ok(Self::DecryptOnly),
            "retired" => Ok(Self::Retired),
            _ => Err(sqlx::Error::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid totp_deks.status value: {value}"),
            )))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpDek {
    pub dek_id: Uuid,
    pub status: TotpDekStatus,
    pub wrapped_dek: String,
    pub kek_mount: String,
    pub kek_key: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

impl<'r> FromRow<'r, PgRow> for TotpDek {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let status: String = row.try_get("status")?;
        Ok(Self {
            dek_id: row.try_get("dek_id")?,
            status: TotpDekStatus::from_db(&status)?,
            wrapped_dek: row.try_get("wrapped_dek")?,
            kek_mount: row.try_get("kek_mount")?,
            kek_key: row.try_get("kek_key")?,
            created_at: row.try_get("created_at")?,
            rotated_at: row.try_get("rotated_at")?,
        })
    }
}

#[derive(Debug, Clone)]
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

impl<'r> FromRow<'r, PgRow> for TotpCredential {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            credential_id: row.try_get("credential_id")?,
            user_id: row.try_get("user_id")?,
            label: row.try_get("label")?,
            digits: row.try_get("digits")?,
            period: row.try_get("period")?,
            algo: row.try_get("algo")?,
            dek_id: row.try_get("dek_id")?,
            seed_ciphertext: row.try_get("seed_ciphertext")?,
            confirmed_at: row.try_get("confirmed_at")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
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
