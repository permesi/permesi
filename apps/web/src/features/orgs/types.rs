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
#[allow(dead_code)]
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
