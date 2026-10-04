//! Thin wrappers over the committed OAuth management endpoints.
//!
//! All requests use the existing API base, session cookies, abort timeout, and
//! error decoder. Credential plaintext is returned only by explicit issuance calls.

use super::{
    paths::ApplicationPaths,
    types::{
        ClientResponse, ClientScopesRequest, CreateClientRequest, CreateScopeRequest,
        PatchClientRequest, PatchScopeRequest, RedirectsRequest, ScopeResponse,
    },
};
use crate::app_lib::api::{patch_json_with_credentials, put_json_with_credentials};
use crate::app_lib::{
    AppError, delete_json_with_headers_with_credentials, get_json_with_credentials,
    post_json_with_headers_with_credentials_response,
};

/// Lists client registrations in the selected application.
pub async fn list_clients(context: &ApplicationPaths) -> Result<Vec<ClientResponse>, AppError> {
    get_json_with_credentials(&context.clients_api()).await
}

/// Creates a registration only; credentials are not issued by this API.
pub async fn create_client(
    context: &ApplicationPaths,
    request: &CreateClientRequest,
) -> Result<ClientResponse, AppError> {
    post_json_with_headers_with_credentials_response(&context.clients_api(), request, &[]).await
}

/// Loads a client by its public OAuth identifier, preserving full ancestry.
pub async fn get_client(context: &ApplicationPaths, id: &str) -> Result<ClientResponse, AppError> {
    get_json_with_credentials(&context.client_api(id)).await
}

/// Updates name or lifecycle state; classification and identifiers are immutable.
pub async fn patch_client(
    context: &ApplicationPaths,
    id: &str,
    request: &PatchClientRequest,
) -> Result<ClientResponse, AppError> {
    patch_json_with_credentials(&context.client_api(id), request).await
}

/// Soft-deletes a registration; the server revokes dependent authority atomically.
pub async fn delete_client(context: &ApplicationPaths, id: &str) -> Result<(), AppError> {
    delete_json_with_headers_with_credentials(&context.client_api(id), &[]).await
}

/// Loads exact URI strings without URL normalization.
pub async fn get_redirects(context: &ApplicationPaths, id: &str) -> Result<Vec<String>, AppError> {
    get_json_with_credentials(&context.redirects_api(id)).await
}

/// Replaces the complete URI allow-list; server validation is authoritative.
pub async fn replace_redirects(
    context: &ApplicationPaths,
    id: &str,
    values: Vec<String>,
) -> Result<Vec<String>, AppError> {
    put_json_with_credentials(
        &context.redirects_api(id),
        &RedirectsRequest {
            redirect_uris: values,
        },
    )
    .await
}

/// Loads the client's configured maximum delegated scope names.
pub async fn get_client_scopes(
    context: &ApplicationPaths,
    id: &str,
) -> Result<Vec<String>, AppError> {
    get_json_with_credentials(&context.client_scopes_api(id)).await
}

/// Replaces allowed names; unknown application scopes are rejected by the server.
pub async fn replace_client_scopes(
    context: &ApplicationPaths,
    id: &str,
    values: Vec<String>,
) -> Result<Vec<String>, AppError> {
    put_json_with_credentials(
        &context.client_scopes_api(id),
        &ClientScopesRequest { scopes: values },
    )
    .await
}

/// Lists application and immutable OIDC protocol registry entries together.
pub async fn list_scopes(context: &ApplicationPaths) -> Result<Vec<ScopeResponse>, AppError> {
    get_json_with_credentials(&context.scopes_api()).await
}

/// Creates an application-defined delegated scope; reserved names remain server-controlled.
pub async fn create_scope(
    context: &ApplicationPaths,
    request: &CreateScopeRequest,
) -> Result<ScopeResponse, AppError> {
    post_json_with_headers_with_credentials_response(&context.scopes_api(), request, &[]).await
}

/// Changes an application scope description without renaming its authority token.
pub async fn patch_scope(
    context: &ApplicationPaths,
    id: &str,
    description: String,
) -> Result<ScopeResponse, AppError> {
    patch_json_with_credentials(&context.scope_api(id), &PatchScopeRequest { description }).await
}

/// Deletes an application scope; protocol entries cannot be removed server-side.
pub async fn delete_scope(context: &ApplicationPaths, id: &str) -> Result<(), AppError> {
    delete_json_with_headers_with_credentials(&context.scope_api(id), &[]).await
}

/// Lists current and unexpired retiring metadata; plaintext is never recoverable.
pub async fn list_secrets(
    context: &ApplicationPaths,
    id: &str,
) -> Result<Vec<super::types::SecretMetadata>, AppError> {
    get_json_with_credentials(&context.secrets_api(id)).await
}

/// Creates a secret once; callers must never retry automatically after an ambiguous failure.
pub async fn create_secret(
    context: &ApplicationPaths,
    id: &str,
) -> Result<super::types::IssuedSecret, AppError> {
    post_json_with_headers_with_credentials_response(
        &context.secrets_api(id),
        &super::types::CreateSecretRequest {},
        &[],
    )
    .await
}

/// Rotates the exact reviewed credential, returning the replacement only once.
pub async fn rotate_secret(
    context: &ApplicationPaths,
    id: &str,
    current: String,
) -> Result<super::types::IssuedSecret, AppError> {
    post_json_with_headers_with_credentials_response(
        &format!("{}/rotate", context.secrets_api(id)),
        &super::types::RotateSecretRequest {
            current_secret_id: current,
        },
        &[],
    )
    .await
}

/// Immediately revokes an owned credential; identifiers come from server metadata.
pub async fn revoke_secret(
    context: &ApplicationPaths,
    id: &str,
    secret: &str,
) -> Result<(), AppError> {
    delete_json_with_headers_with_credentials(&context.secret_api(id, secret), &[]).await
}
