//! Request and response types for organization API endpoints.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub slug: String,
    pub tier: String, // "production" or "non_production"
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateApplicationRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OrgResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_at: String,
}

/// Server-derived role eligibility for presentation; mutations independently authorize.
/// The immutable ID pins an organization confirmation across slug reuse.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct OrgCapabilities {
    pub organization_id: String,
    pub can_manage_resources: bool,
    pub can_delete_organization: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ProjectResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EnvironmentResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub tier: String,
    pub created_at: String,
}

/// Reads the active environment list for production-tier selection UX only.
/// This grants no authority; the backend and partial unique index enforce the invariant.
#[must_use]
pub fn production_tier_present(environments: &[EnvironmentResponse]) -> bool {
    environments
        .iter()
        .any(|environment| environment.tier == "production")
}

/// Tenant application metadata; OAuth clients remain separate child resources.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ApplicationResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::{EnvironmentResponse, OrgCapabilities, production_tier_present};

    /// Missing or malformed eligibility cannot silently default to permissive controls.
    #[test]
    fn org_capabilities_require_explicit_server_booleans_and_identity() {
        for body in [
            r"{}",
            r#"{"organization_id":"org","can_manage_resources":true}"#,
            r#"{"organization_id":"org","can_manage_resources":"true","can_delete_organization":true}"#,
        ] {
            assert!(serde_json::from_str::<OrgCapabilities>(body).is_err());
        }
    }

    #[test]
    fn production_tier_selection_uses_classification_not_name_or_slug() {
        assert!(!production_tier_present(&[]));
        let mut environments = vec![EnvironmentResponse {
            id: "dev".to_owned(),
            slug: "production".to_owned(),
            name: "Production".to_owned(),
            tier: "non_production".to_owned(),
            created_at: String::new(),
        }];
        assert!(!production_tier_present(&environments));
        environments.push(EnvironmentResponse {
            id: "live".to_owned(),
            slug: "live".to_owned(),
            name: "Customer traffic".to_owned(),
            tier: "production".to_owned(),
            created_at: String::new(),
        });
        assert!(production_tier_present(&environments));
    }
}
