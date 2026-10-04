//! Session-authenticated confidential credential APIs with one-time issuance disclosure.
//!
//! Flow Overview: existing tenant resolution authorizes reads/owner-admin mutations;
//! trusted Origin and shared per-user/client quotas guard writes before expensive hashing.
//! The domain rechecks authority in its transaction. All responses prohibit caching;
//! persistence/cryptographic failures disclose no secret, PHC or submitted values.

use super::{
    resolve_application,
    types::{
        ClientPath, CreateSecretRequest, IssuedSecretResponse, RotateSecretRequest, SecretPath,
        SecretResponse,
    },
};
use crate::{
    api::handlers::auth::{AuthState, RateLimitAction, RateLimitDecision},
    oauth::{credentials::CredentialError, oidc::OAuthState, service::ApplicationContext},
};
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::sync::Arc;

/// Maps failures to generic responses; SQLSTATE is the only database diagnostic logged.
fn failure(error: CredentialError) -> Response {
    let status = match error {
        CredentialError::NotFound => StatusCode::NOT_FOUND,
        CredentialError::Invalid => StatusCode::BAD_REQUEST,
        CredentialError::Conflict => StatusCode::CONFLICT,
        CredentialError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        CredentialError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        CredentialError::Database(error) => {
            let code = error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code);
            tracing::error!(code = ?code, "Credential database operation failed");
            if matches!(code.as_deref(), Some("55P03" | "57014")) {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    };
    secured(status.into_response())
}

/// Prevents credential/metadata caching on success and failure, including malformed JSON.
fn secured(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Covers extractor failures before handlers execute, including malformed path UUIDs.
pub(crate) async fn prevent_cache(response: Response) -> Response {
    secured(response)
}

/// Reuses session/tenant ACLs and trusted configured origins; writes consume shared HMAC
/// counters only after authorization, so foreign users cannot exhaust a client's quota.
async fn context(
    pool: &PgPool,
    headers: &HeaderMap,
    path: &ClientPath,
    auth: &AuthState,
    action: Option<RateLimitAction>,
) -> Result<ApplicationContext, StatusCode> {
    let context = resolve_application(pool, headers, &path.application, action.is_some()).await?;
    if let Some(action) = action {
        if let Some(origin) = headers.get(header::ORIGIN) {
            let valid = origin.to_str().is_ok_and(|origin| {
                auth.config()
                    .cors_allowed_origins()
                    .iter()
                    .any(|configured| {
                        url::Url::parse(configured)
                            .is_ok_and(|url| url.origin().ascii_serialization() == origin)
                    })
            });
            if !valid {
                return Err(StatusCode::FORBIDDEN);
            }
        } else if headers
            .get("sec-fetch-site")
            .is_some_and(|site| site != "same-origin")
        {
            return Err(StatusCode::FORBIDDEN);
        }
        // Bogus or foreign client IDs must not create shared quota records.
        crate::oauth::service::get_client(pool, &context, path.client_id)
            .await
            .map_err(|error| match error {
                crate::oauth::service::Error::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            })?;
        if auth
            .rate_limiter()
            .check_email(
                &format!(
                    "oauth-credential-management/{}/{}",
                    context.user_id, path.client_id
                ),
                action,
            )
            .await
            == RateLimitDecision::Limited
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(context)
}

#[utoipa::path(
    get, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/secrets",
    params(
        ("org_slug" = String, Path, description = "Org slug"),
        ("project_slug" = String, Path, description = "Project slug"),
        ("env_slug" = String, Path, description = "Environment slug"),
        ("app_id" = String, Path, description = "Application UUID"),
        ("client_id" = String, Path, description = "Public client UUID")
    ),
    responses((status = 200, description = "Credential operation succeeded.", body = [SecretResponse]), (status = 400, description = "Client cannot receive credentials."), (status = 401, description = "Full session required."), (status = 404, description = "Resource inaccessible."), (status = 500, description = "Persistence failure."), (status = 503, description = "Service capacity or database deadline exhausted.")), tag = "oauth-clients"
)]
/// Lists usable credential metadata for active organization members.
pub(crate) async fn list_secrets(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
) -> Response {
    let context = match context(&pool, &headers, &path, &auth, None).await {
        Ok(context) => context,
        Err(status) => return secured(status.into_response()),
    };
    match oauth
        .credentials
        .list(&pool, &context, path.client_id)
        .await
    {
        Ok(rows) => secured(
            Json(
                rows.into_iter()
                    .map(SecretResponse::from)
                    .collect::<Vec<_>>(),
            )
            .into_response(),
        ),
        Err(error) => failure(error),
    }
}

#[utoipa::path(
    post, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/secrets",
    request_body = CreateSecretRequest,
    params(
        ("org_slug" = String, Path, description = "Org slug"),
        ("project_slug" = String, Path, description = "Project slug"),
        ("env_slug" = String, Path, description = "Environment slug"),
        ("app_id" = String, Path, description = "Application UUID"),
        ("client_id" = String, Path, description = "Public client UUID")
    ),
    responses((status = 201, description = "Credential operation succeeded.", body = IssuedSecretResponse), (status = 400, description = "Client cannot receive credentials."), (status = 401, description = "Full session required."), (status = 404, description = "Resource inaccessible."), (status = 500, description = "Persistence failure."), (status = 503, description = "Service capacity or database deadline exhausted."), (status = 403, description = "Untrusted browser origin."), (status = 429, description = "Shared mutation budget exhausted."), (status = 409, description = "Stale current credential or overlap active."), (status = 415, description = "JSON content type required."), (status = 422, description = "Invalid JSON payload.")), tag = "oauth-clients"
)]
/// Issues initial plaintext once for an owner/admin; an existing current credential conflicts.
pub(crate) async fn create_secret(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    payload: Result<Json<CreateSecretRequest>, JsonRejection>,
) -> Response {
    let payload = match payload {
        Ok(Json(payload)) => payload,
        Err(error) => return secured(error.status().into_response()),
    };
    let _ = payload;
    let context = match context(
        &pool,
        &headers,
        &path,
        &auth,
        Some(RateLimitAction::ClientCredentials),
    )
    .await
    {
        Ok(context) => context,
        Err(status) => return secured(status.into_response()),
    };
    match oauth
        .credentials
        .issue(&pool, &context, path.client_id, None)
        .await
    {
        Ok(value) => {
            secured((StatusCode::CREATED, Json(IssuedSecretResponse::from(value))).into_response())
        }
        Err(error) => failure(error),
    }
}

#[utoipa::path(
    post, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/secrets/rotate",
    request_body = RotateSecretRequest,
    params(
        ("org_slug" = String, Path, description = "Org slug"),
        ("project_slug" = String, Path, description = "Project slug"),
        ("env_slug" = String, Path, description = "Environment slug"),
        ("app_id" = String, Path, description = "Application UUID"),
        ("client_id" = String, Path, description = "Public client UUID")
    ),
    responses((status = 201, description = "Credential operation succeeded.", body = IssuedSecretResponse), (status = 400, description = "Client cannot receive credentials."), (status = 401, description = "Full session required."), (status = 404, description = "Resource inaccessible."), (status = 500, description = "Persistence failure."), (status = 503, description = "Service capacity or database deadline exhausted."), (status = 403, description = "Untrusted browser origin."), (status = 429, description = "Shared mutation budget exhausted."), (status = 409, description = "Stale current credential or overlap active."), (status = 415, description = "JSON content type required."), (status = 422, description = "Invalid JSON payload.")), tag = "oauth-clients"
)]
/// Atomically retires the expected credential and reveals one replacement to an owner/admin.
pub(crate) async fn rotate_secret(
    Path(path): Path<ClientPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    payload: Result<Json<RotateSecretRequest>, JsonRejection>,
) -> Response {
    let payload = match payload {
        Ok(Json(payload)) => payload,
        Err(error) => return secured(error.status().into_response()),
    };
    let context = match context(
        &pool,
        &headers,
        &path,
        &auth,
        Some(RateLimitAction::ClientCredentials),
    )
    .await
    {
        Ok(context) => context,
        Err(status) => return secured(status.into_response()),
    };
    match oauth
        .credentials
        .issue(
            &pool,
            &context,
            path.client_id,
            Some(payload.current_secret_id),
        )
        .await
    {
        Ok(value) => {
            secured((StatusCode::CREATED, Json(IssuedSecretResponse::from(value))).into_response())
        }
        Err(error) => failure(error),
    }
}

#[utoipa::path(
    delete, path = "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth/clients/{client_id}/secrets/{secret_id}",
    params(
        ("org_slug" = String, Path, description = "Org slug"),
        ("project_slug" = String, Path, description = "Project slug"),
        ("env_slug" = String, Path, description = "Environment slug"),
        ("app_id" = String, Path, description = "Application UUID"),
        ("client_id" = String, Path, description = "Public client UUID")
        ,("secret_id" = String, Path, description = "Credential UUID")
    ),
    responses((status = 204, description = "Credential operation succeeded."), (status = 400, description = "Client cannot receive credentials."), (status = 401, description = "Full session required."), (status = 404, description = "Resource inaccessible."), (status = 500, description = "Persistence failure."), (status = 503, description = "Service capacity or database deadline exhausted."), (status = 403, description = "Untrusted browser origin."), (status = 429, description = "Shared mutation budget exhausted.")), tag = "oauth-clients"
)]
/// Revokes at commit with a separate shared budget; repeated owned revocation succeeds.
pub(crate) async fn revoke_secret(
    Path(path): Path<SecretPath>,
    headers: HeaderMap,
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
) -> Response {
    let context = match context(
        &pool,
        &headers,
        &path.client,
        &auth,
        Some(RateLimitAction::ClientCredentialRevocation),
    )
    .await
    {
        Ok(context) => context,
        Err(status) => return secured(status.into_response()),
    };
    match oauth
        .credentials
        .revoke(&pool, &context, path.client.client_id, path.secret_id)
        .await
    {
        Ok(()) => secured(StatusCode::NO_CONTENT.into_response()),
        Err(error) => failure(error),
    }
}
