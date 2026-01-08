//! Request/response types for organization-scoped APIs.
//!
//! These payloads are shared between handlers and `OpenAPI` generation.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrgRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub tier: EnvironmentTier,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationRequest {
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnvironmentResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub tier: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentTier {
    Production,
    #[default]
    NonProduction,
}

impl EnvironmentTier {
    /// Returns the canonical string representation used in API payloads and SQL writes.
    /// The returned value must match the `environment_tier` enum values in the database.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::NonProduction => "non_production",
        }
    }
}
