//! Client registration, lifecycle, redirects, and delegated scope allow-lists.
//!
//! All routes resolve session membership and active ancestry before calling domain services.
//! Mutations require org owner/admin; inaccessible resources return 404 and DTOs exclude secrets.
//!
//! Flow Overview: resolve session/tenant ancestry, check immutable client ownership before
//! bounded PostgreSQL advisory coordination, then reload the locked registration and mutate.
//! The validated OAuth policy bounds coordination statements and individual lock waits.
//! After coordination, bulk mutations use the database's prior statement-timeout policy.

use super::{
    resolve_application,
    types::{
        ApplicationPath, ClientPath, ClientResponse, ClientScopesRequest, CreateClientRequest,
        PatchClientRequest, RedirectsRequest,
    },
};
use crate::oauth::{client::ClientConfiguration, oidc::OAuthState, service};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::sync::Arc;

#[utoipa::path(
    post, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients",
    request_body = CreateClientRequest,
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 201, description = "Operation succeeded.", body = ClientResponse),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 415, description = "JSON content type required."),
        (status = 422, description = "JSON payload deserialization failed."),
        (status = 409, description = "Configuration already exists."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-clients"
)]
/// Creates a client and validated allow-lists atomically; only org owners/admins may write.
pub(crate) async fn create_client(
    Path(path): Path<ApplicationPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(payload): Json<CreateClientRequest>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    let config = match ClientConfiguration::new(
        &payload.name,
        payload.client_type,
        payload.redirect_uris,
        payload.scopes,
    ) {
        Ok(config) => config,
        Err(error) => return service::Error::from(error).into_response(),
    };
    match service::create_client(&pool, &context, config).await {
        Ok(client) => (StatusCode::CREATED, Json(ClientResponse::from(client))).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    get, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = [ClientResponse]),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-clients"
)]
/// Lists non-deleted registrations for an active org member, including disabled clients.
pub(crate) async fn list_clients(
    Path(path): Path<ApplicationPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path, false).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::list_clients(&pool, &context).await {
        Ok(clients) => Json(
            clients
                .into_iter()
                .map(ClientResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    get, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = ClientResponse),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-clients"
)]
/// Returns registration fields only when this client belongs to the resolved application.
pub(crate) async fn get_client(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, false).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::get_client(&pool, &context, path.client_id).await {
        Ok(client) => Json(ClientResponse::from(client)).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    patch, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}",
    request_body = PatchClientRequest,
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = ClientResponse),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 415, description = "JSON content type required."),
        (status = 422, description = "JSON payload deserialization failed."),
        (status = 409, description = "Configuration already exists."),
        (status = 500, description = "Persistence failure."),
        (status = 503, description = "Database deadline exhausted.")
    ), tag = "oauth-clients"
)]
/// Updates name or disabled state for org managers; identifiers and classification are immutable.
pub(crate) async fn patch_client(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    Json(payload): Json<PatchClientRequest>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::patch_client(
        &pool,
        &context,
        path.client_id,
        oauth.config.lock_timeout_ms,
        payload.name,
        payload.disabled,
    )
    .await
    {
        Ok(client) => Json(ClientResponse::from(client)).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    delete, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 204, description = "Operation succeeded."),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure."),
        (status = 503, description = "Database deadline exhausted.")
    ), tag = "oauth-clients"
)]
/// Soft-deletes an application-bound client and revokes consent/credentials for org managers.
pub(crate) async fn delete_client(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::delete_client(
        &pool,
        &context,
        path.client_id,
        oauth.config.lock_timeout_ms,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    get, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/redirect-uris",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = [String]),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-clients"
)]
/// Returns exact registered redirects to active org members without normalization.
pub(crate) async fn get_redirects(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, false).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::get_redirects(&pool, &context, path.client_id).await {
        Ok(values) => Json(values).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    put, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/redirect-uris",
    request_body = RedirectsRequest,
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = [String]),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 415, description = "JSON content type required."),
        (status = 422, description = "JSON payload deserialization failed."),
        (status = 500, description = "Persistence failure."),
        (status = 503, description = "Database deadline exhausted.")
    ), tag = "oauth-clients"
)]
/// Replaces redirect registrations atomically for org managers; invalid/duplicate URIs fail.
pub(crate) async fn replace_redirects(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    Json(payload): Json<RedirectsRequest>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::replace_redirects(
        &pool,
        &context,
        path.client_id,
        oauth.config.lock_timeout_ms,
        payload.redirect_uris,
    )
    .await
    {
        Ok(values) => Json(values).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    get, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/scopes",
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = [String]),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 500, description = "Persistence failure.")
    ), tag = "oauth-clients"
)]
/// Returns only configured delegated scope names to an active member of this organization.
pub(crate) async fn get_client_scopes(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, false).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::get_client_scopes(&pool, &context, path.client_id).await {
        Ok(values) => Json(values).into_response(),
        Err(error) => error.into_response(),
    }
}

#[utoipa::path(
    put, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/scopes",
    request_body = ClientScopesRequest,
    params(
        ("org_slug" = String, Path, description = "org slug"),
        ("project_slug" = String, Path, description = "project slug"),
        ("env_slug" = String, Path, description = "env slug"),
        ("app_id" = String, Path, description = "UUID"),
        ("client_id" = String, Path, description = "UUID")
    ),
    responses(
        (status = 200, description = "Operation succeeded.", body = [String]),
        (status = 400, description = "Invalid input or OAuth configuration."),
        (status = 401, description = "Missing or invalid full session."),
        (status = 404, description = "Resource inaccessible or absent."),
        (status = 415, description = "JSON content type required."),
        (status = 422, description = "JSON payload deserialization failed."),
        (status = 500, description = "Persistence failure."),
        (status = 503, description = "Database deadline exhausted.")
    ), tag = "oauth-clients"
)]
/// Replaces a client's application-bound allow-list for org managers; unknown scopes fail.
pub(crate) async fn replace_client_scopes(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    Json(payload): Json<ClientScopesRequest>,
) -> Response {
    let context = match resolve_application(&pool, &headers, &path.application, true).await {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    match service::replace_client_scopes(
        &pool,
        &context,
        path.client_id,
        oauth.config.lock_timeout_ms,
        payload.scopes,
    )
    .await
    {
        Ok(values) => Json(values).into_response(),
        Err(error) => error.into_response(),
    }
}
