//! Client identity and validated registration configuration.
//!
//! Public client identifiers are independent random UUIDs, never credentials. Client
//! classification is immutable: converting between public and confidential requires
//! a new registration. Confidential credential issuance and authentication are deferred.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgRow};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ValidationError, redirect_uri::RedirectUri, scope::OAuthScope};

/// Whether a deployment can protect credentials; this does not enable any grant type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Public,
    Confidential,
}

impl ClientType {
    /// Returns the exact database classification; unknown types are never inferred.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Confidential => "confidential",
        }
    }
}

/// Credential-free database record; HTTP responses use a separate explicit DTO.
#[derive(Debug)]
pub struct Client {
    pub id: Uuid,
    pub application_id: Uuid,
    pub client_id: Uuid,
    pub name: String,
    pub client_type: ClientType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

impl sqlx::FromRow<'_, PgRow> for Client {
    /// Decodes reviewed fields and fails closed on an unknown classification.
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let client_type = match row.try_get::<&str, _>("client_type")? {
            "public" => ClientType::Public,
            "confidential" => ClientType::Confidential,
            _ => {
                return Err(sqlx::Error::ColumnDecode {
                    index: "client_type".into(),
                    source: Box::new(ValidationError("Unknown OAuth client type.")),
                });
            }
        };
        Ok(Self {
            id: row.try_get("id")?,
            application_id: row.try_get("application_id")?,
            client_id: row.try_get("client_id")?,
            name: row.try_get("name")?,
            client_type,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            disabled_at: row.try_get("disabled_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

impl Client {
    /// Authorizes use of this client's lifecycle state only when neither disabled nor
    /// deleted. Callers must also verify active ancestry, allowed scopes, and tenant access.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.disabled_at.is_none() && self.deleted_at.is_none()
    }
}

/// Validated configuration passed to persistence, never a session permission set.
pub(crate) struct ClientConfiguration {
    pub name: String,
    pub client_type: ClientType,
    pub redirects: Vec<RedirectUri>,
    pub scopes: Vec<OAuthScope>,
}

impl ClientConfiguration {
    /// Validates all registration inputs before a transaction begins; duplicates fail closed.
    pub(crate) fn new(
        name: &str,
        client_type: ClientType,
        redirects: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            name: validate_name(name)?,
            client_type,
            redirects: RedirectUri::validate_list(redirects, client_type)?,
            scopes: OAuthScope::validate_list(scopes)?,
        })
    }
}

/// Trims a human-readable name, rejects empty/oversized/control-containing values.
pub(crate) fn validate_name(value: &str) -> Result<String, ValidationError> {
    let name = value.trim();
    if name.is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(ValidationError(
            "Name must contain 1–255 characters without controls.",
        ));
    }
    Ok(name.to_owned())
}

/// Loads a usable client by public identifier, requiring active client and ancestry.
/// This proves registration status only; it does not authenticate a client or authorize
/// any user, OAuth scope, or grant. Future protocol services must enforce those separately.
///
/// # Errors
/// Returns database errors to the caller; no credential fields are selected.
pub async fn load_active_client(
    pool: &PgPool,
    client_id: Uuid,
) -> Result<Option<Client>, sqlx::Error> {
    sqlx::query_as(
        "SELECT c.* FROM oauth_clients c
         JOIN applications a ON a.id = c.application_id
         JOIN environments e ON e.id = a.environment_id
         JOIN projects p ON p.id = e.project_id
         JOIN organizations o ON o.id = p.org_id
         WHERE c.client_id = $1 AND c.disabled_at IS NULL AND c.deleted_at IS NULL
         AND a.deleted_at IS NULL AND e.deleted_at IS NULL
         AND p.deleted_at IS NULL AND o.deleted_at IS NULL",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
}
