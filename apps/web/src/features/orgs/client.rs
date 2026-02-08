//! Client wrappers for organization-related API endpoints.

use crate::app_lib::{
    AppError, get_json_with_credentials, post_json_with_headers_with_credentials,
    post_json_with_headers_with_credentials_response,
};
use crate::features::orgs::types::{
    CreateApplicationRequest, CreateEnvironmentRequest, CreateOrgRequest, CreateProjectRequest,
    EnvironmentResponse, OrgResponse, ProjectResponse,
};

/// Fetches all organizations the current user belongs to.
pub async fn list_orgs() -> Result<Vec<OrgResponse>, AppError> {
    get_json_with_credentials("/v1/orgs").await
}

/// Creates a new organization and assigns the creator as the owner.
pub async fn create_org(request: &CreateOrgRequest) -> Result<OrgResponse, AppError> {
    post_json_with_headers_with_credentials_response("/v1/orgs", request, &[]).await
}

/// Lists all projects within a specific organization.
pub async fn list_projects(org_slug: &str) -> Result<Vec<ProjectResponse>, AppError> {
    let path = format!("/v1/orgs/{}/projects", org_slug);
    get_json_with_credentials(&path).await
}

/// Creates a new project inside an organization.
pub async fn create_project(
    org_slug: &str,
    request: &CreateProjectRequest,
) -> Result<ProjectResponse, AppError> {
    let path = format!("/v1/orgs/{}/projects", org_slug);
    post_json_with_headers_with_credentials_response(&path, request, &[]).await
}

/// Lists all environments for a project.
pub async fn list_environments(
    org_slug: &str,
    project_slug: &str,
) -> Result<Vec<EnvironmentResponse>, AppError> {
    let path = format!("/v1/orgs/{}/projects/{}/envs", org_slug, project_slug);
    get_json_with_credentials(&path).await
}

/// Creates a new environment (e.g. Production, Staging) for a project.
pub async fn create_environment(
    org_slug: &str,
    project_slug: &str,
    request: &CreateEnvironmentRequest,
) -> Result<EnvironmentResponse, AppError> {
    let path = format!("/v1/orgs/{}/projects/{}/envs", org_slug, project_slug);
    post_json_with_headers_with_credentials_response(&path, request, &[]).await
}

/// Creates a new application placeholder under an environment.
#[allow(dead_code)]
pub async fn create_application(
    org_slug: &str,
    project_slug: &str,
    env_slug: &str,
    request: &CreateApplicationRequest,
) -> Result<(), AppError> {
    let path = format!(
        "/v1/orgs/{}/projects/{}/envs/{}/apps",
        org_slug, project_slug, env_slug
    );
    post_json_with_headers_with_credentials(&path, request, &[]).await
}
