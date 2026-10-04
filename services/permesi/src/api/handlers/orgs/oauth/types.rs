//! Explicit request/response DTOs with no credential or internal permission fields.
//!
//! Unknown request fields are rejected so IDs, client classification changes, and
//! client-supplied roles cannot be silently accepted as configuration.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::oauth::{
    client::{Client, ClientType},
    scope::ScopeRecord,
};

#[derive(Deserialize)]
pub(crate) struct ApplicationPath {
    pub org_slug: String,
    pub project_slug: String,
    pub env_slug: String,
    pub app_id: Uuid,
}

#[derive(Deserialize)]
pub(crate) struct ClientPath {
    #[serde(flatten)]
    pub application: ApplicationPath,
    pub client_id: Uuid,
}

#[derive(Deserialize)]
pub(crate) struct ScopePath {
    #[serde(flatten)]
    pub application: ApplicationPath,
    pub scope_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateClientRequest {
    pub name: String,
    pub client_type: ClientType,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchClientRequest {
    pub name: Option<String>,
    pub disabled: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedirectsRequest {
    pub redirect_uris: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientScopesRequest {
    pub scopes: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ClientResponse {
    pub id: String,
    pub application_id: String,
    /// Public identifier used in management paths and future protocol requests.
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub created_at: String,
    pub updated_at: String,
    pub disabled_at: Option<String>,
}

impl From<Client> for ClientResponse {
    /// Copies only reviewed registration fields; hashes/credentials cannot be serialized.
    fn from(client: Client) -> Self {
        Self {
            id: client.id.to_string(),
            application_id: client.application_id.to_string(),
            client_id: client.client_id.to_string(),
            name: client.name,
            client_type: client.client_type,
            created_at: client.created_at.to_rfc3339(),
            updated_at: client.updated_at.to_rfc3339(),
            disabled_at: client.disabled_at.map(|time| time.to_rfc3339()),
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateScopeRequest {
    /// Case-sensitive OAuth token in resource:action format (for example jobs:read).
    /// Exactly one colon and two nonempty parts are required; protocol/internal names are reserved.
    #[schema(example = "jobs:read", min_length = 1, max_length = 128)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchScopeRequest {
    pub description: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ScopeResponse {
    pub id: String,
    pub application_id: String,
    /// Original OAuth token; application resource/action semantics are derived, never duplicated.
    pub name: String,
    pub description: String,
    /// "protocol" entries have server-defined semantics and are read-only.
    pub kind: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<ScopeRecord> for ScopeResponse {
    /// Exposes registry metadata without client configuration or grant/user records.
    fn from(scope: ScopeRecord) -> Self {
        Self {
            id: scope.id.to_string(),
            application_id: scope.application_id.to_string(),
            name: scope.name,
            description: scope.description,
            kind: scope.kind,
            created_at: scope.created_at.to_rfc3339(),
            updated_at: scope.updated_at.to_rfc3339(),
        }
    }
}
