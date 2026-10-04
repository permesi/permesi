//! OAuth management DTOs; only issuance responses carry a one-time credential.

use serde::{Deserialize, Serialize};

/// Immutable client classification; it does not imply any implemented grant flow.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    #[default]
    Public,
    Confidential,
}

impl ClientType {
    /// Returns the administrator-facing label without suggesting protocol support.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Confidential => "Confidential",
        }
    }

    /// Explains credential storage capability, independent of token grant types.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Public => {
                "For browser, mobile, desktop and CLI applications that cannot safely store credentials."
            }
            Self::Confidential => {
                "For server-side applications capable of securely storing credentials."
            }
        }
    }
}

/// Registration metadata; management paths use the public `client_id`, not `id`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ClientResponse {
    pub id: String,
    pub application_id: String,
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub created_at: String,
    pub updated_at: String,
    pub disabled_at: Option<String>,
}

impl ClientResponse {
    /// Displays lifecycle state explicitly rather than relying only on color.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        if self.disabled_at.is_some() {
            "Disabled"
        } else {
            "Active"
        }
    }
}

/// Minimal creation payload; redirect and scope configuration use their own APIs.
#[derive(Clone, Debug, Serialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub client_type: ClientType,
}

/// Only names and lifecycle state can change after creation.
#[derive(Clone, Debug, Serialize)]
pub struct PatchClientRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

/// Replaces the complete exact-match redirect allow-list atomically.
#[derive(Clone, Debug, Serialize)]
pub struct RedirectsRequest {
    pub redirect_uris: Vec<String>,
}

/// Replaces the client's maximum delegated scope allow-list, not user permissions.
#[derive(Clone, Debug, Serialize)]
pub struct ClientScopesRequest {
    pub scopes: Vec<String>,
}

/// Scope kind is server-defined; unknown future kinds fail closed as read-only.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Application,
    Protocol,
    #[serde(other)]
    Unknown,
}

/// Delegated scope registry metadata, distinct from internal Principal scopes.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ScopeResponse {
    pub id: String,
    pub application_id: String,
    pub name: String,
    pub description: String,
    pub kind: ScopeKind,
    pub created_at: String,
    pub updated_at: String,
}

impl ScopeResponse {
    /// Allows editing only API scopes identified by the server; protocol entries
    /// and unknown kinds remain immutable. This is UX, not an authorization check.
    #[must_use]
    pub fn editable(&self) -> bool {
        self.kind == ScopeKind::Application
    }

    /// Distinguishes protocol registry entries from application delegated scopes.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self.kind {
            ScopeKind::Application => "Application",
            ScopeKind::Protocol => "System · OIDC",
            ScopeKind::Unknown => "System",
        }
    }
}

/// Creates an application scope; the server reserves protocol/internal names.
#[derive(Clone, Debug, Serialize)]
pub struct CreateScopeRequest {
    pub name: String,
    pub description: String,
}

/// Scope names are immutable; only the description may change.
#[derive(Clone, Debug, Serialize)]
pub struct PatchScopeRequest {
    pub description: String,
}

/// Usable credential metadata; revoked/expired values are omitted server-side.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub id: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// One-time secret response, deliberately without Debug or browser persistence.
#[derive(Clone, Deserialize)]
pub struct IssuedSecret {
    pub credential: SecretMetadata,
    pub client_secret: String,
    pub previous: Option<SecretMetadata>,
}

/// Empty strict creation request; hashing/overlap policy is operator controlled.
#[derive(Serialize)]
pub struct CreateSecretRequest {}

/// Rotation must identify the current credential reviewed by the manager.
#[derive(Serialize)]
pub struct RotateSecretRequest {
    pub current_secret_id: String,
}
