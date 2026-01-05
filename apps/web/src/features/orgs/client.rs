//! Client wrappers for organization-related API endpoints.

use crate::app_lib::{
    AppError, get_json_with_headers_with_credentials, post_json_with_headers_with_credentials,
    post_json_with_headers_with_credentials_response,
};
use crate::features::auth::state::use_auth;
use crate::features::orgs::types::{
    CreateApplicationRequest, CreateEnvironmentRequest, CreateOrgRequest, CreateProjectRequest,
    EnvironmentResponse, OrgResponse, ProjectResponse,
};
use leptos::prelude::Get;

/// Fetches all organizations the current user belongs to.
pub async fn list_orgs() -> Result<Vec<OrgResponse>, AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    get_json_with_headers_with_credentials("/v1/orgs", &headers).await
}

/// Creates a new organization and assigns the creator as the owner.
pub async fn create_org(request: &CreateOrgRequest) -> Result<OrgResponse, AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    post_json_with_headers_with_credentials_response("/v1/orgs", request, &headers).await
}

/// Lists all projects within a specific organization.
pub async fn list_projects(org_slug: &str) -> Result<Vec<ProjectResponse>, AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    let path = format!("/v1/orgs/{}/projects", org_slug);
    get_json_with_headers_with_credentials(&path, &headers).await
}

/// Creates a new project inside an organization.
pub async fn create_project(
    org_slug: &str,
    request: &CreateProjectRequest,
) -> Result<ProjectResponse, AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    let path = format!("/v1/orgs/{}/projects", org_slug);
    post_json_with_headers_with_credentials_response(&path, request, &headers).await
}

/// Lists all environments for a project.
pub async fn list_environments(
    org_slug: &str,
    project_slug: &str,
) -> Result<Vec<EnvironmentResponse>, AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    let path = format!("/v1/orgs/{}/projects/{}/envs", org_slug, project_slug);
    get_json_with_headers_with_credentials(&path, &headers).await
}

/// Creates a new environment (e.g. Production, Staging) for a project.
pub async fn create_environment(
    org_slug: &str,
    project_slug: &str,
    request: &CreateEnvironmentRequest,
) -> Result<EnvironmentResponse, AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    let path = format!("/v1/orgs/{}/projects/{}/envs", org_slug, project_slug);
    post_json_with_headers_with_credentials_response(&path, request, &headers).await
}

/// Creates a new application placeholder under an environment.
#[allow(dead_code)]
pub async fn create_application(
    org_slug: &str,
    project_slug: &str,
    env_slug: &str,
    request: &CreateApplicationRequest,
) -> Result<(), AppError> {
    let auth = use_auth();
    let token = auth.session_token.get();
    let headers = auth_headers(token.as_deref());
    let path = format!(
        "/v1/orgs/{}/projects/{}/envs/{}/apps",
        org_slug, project_slug, env_slug
    );
    post_json_with_headers_with_credentials(&path, request, &headers).await
}

fn auth_headers(token: Option<&str>) -> Vec<(String, String)> {
    token
        .map(|token| vec![("Authorization".to_string(), format!("Bearer {token}"))])
        .unwrap_or_default()
}
