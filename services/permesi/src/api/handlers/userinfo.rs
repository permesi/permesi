//! OIDC `UserInfo` adapter using an exact issued access token, never a session cookie.
//!
//! Flow Overview: GET or POST accepts only a bounded Authorization Bearer header.
//! The domain resolves the token's hash-only receipt and current tenant authority,
//! then releases only claims selected by the issued OIDC scopes. Query/body tokens,
//! duplicate credentials and all untrusted JWT payloads are rejected or ignored.

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

use super::auth::{AuthState, RateLimitAction, RateLimitConfig, extract_client_ip};
use crate::oauth::{
    oidc::{MAX_ACCESS_JWT_BYTES, OAuthState},
    userinfo::{self, UserInfoError},
};
use service_utils::api_error::ApiError;

/// Returns the token subject and only profile claims allowed by issued OIDC scopes.
#[utoipa::path(get,path="/userinfo",responses((status=200,description="Current OIDC subject and authorized profile claims",body=userinfo::UserInfo),(status=401,description="Missing, invalid, expired or unauthorized access token"),(status=429,description="Shared UserInfo budget exhausted"),(status=503,description="UserInfo dependency unavailable")),security(("oidc_access_token"=[])),tag="oauth")]
pub(crate) async fn get(
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    request: Request,
) -> Response {
    respond(&pool, &oauth, &auth, request).await
}

/// Supports OIDC POST with header-carried Bearer credentials, without form or URL tokens.
#[utoipa::path(post,path="/userinfo",responses((status=200,description="Current OIDC subject and authorized profile claims",body=userinfo::UserInfo),(status=401,description="Missing, invalid, expired or unauthorized access token"),(status=429,description="Shared UserInfo budget exhausted"),(status=503,description="UserInfo dependency unavailable")),security(("oidc_access_token"=[])),tag="oauth")]
pub(crate) async fn post(
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    request: Request,
) -> Response {
    respond(&pool, &oauth, &auth, request).await
}

/// Bounds the complete disclosure path and prevents caching even for rejected requests.
async fn respond(
    pool: &PgPool,
    oauth: &OAuthState,
    auth: &AuthState,
    request: Request,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_millis(oauth.config.tokens.timeout_ms),
        resolve(pool, oauth, auth, request),
    )
    .await;
    let response = match result {
        Ok(Ok(info)) => Json(info).into_response(),
        Ok(Err(UserInfoError::InvalidToken)) => unauthorized(),
        Ok(Err(UserInfoError::Limited)) => {
            ApiError::from_status(StatusCode::TOO_MANY_REQUESTS).into_response()
        }
        Ok(Err(UserInfoError::Unavailable)) | Err(_) => {
            ApiError::from_status(StatusCode::SERVICE_UNAVAILABLE).into_response()
        }
    };
    prevent_cache(response).await
}

/// Rejects ambiguous transport before asking the domain for claim disclosure.
async fn resolve(
    pool: &PgPool,
    oauth: &OAuthState,
    auth: &AuthState,
    request: Request,
) -> Result<userinfo::UserInfo, UserInfoError> {
    let (parts, body) = request.into_parts();
    let policy = &oauth.config.tokens;
    let limiter = auth.rate_limiter().configured(RateLimitConfig::new(
        policy.rate_window,
        policy.ip_attempts,
        policy.client_ip_attempts,
    ));
    if let Some(status) = limiter
        .check_ip(
            extract_client_ip(&parts.headers).as_deref(),
            RateLimitAction::UserInfo,
        )
        .await
        .denial_status()
    {
        return Err(if status == StatusCode::SERVICE_UNAVAILABLE {
            UserInfoError::Unavailable
        } else {
            UserInfoError::Limited
        });
    }
    if parts.uri.query().is_some() {
        return Err(UserInfoError::InvalidToken);
    }
    let token = bearer(&parts.headers)?;
    let body = axum::body::to_bytes(body, 1)
        .await
        .map_err(|_| UserInfoError::InvalidToken)?;
    if !body.is_empty() {
        return Err(UserInfoError::InvalidToken);
    }
    userinfo::resolve(pool, oauth, token).await
}

/// Authorizes one header-carried access token; duplicate or malformed headers fail closed.
fn bearer(headers: &HeaderMap) -> Result<&str, UserInfoError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let header = values.next().ok_or(UserInfoError::InvalidToken)?;
    if values.next().is_some() {
        return Err(UserInfoError::InvalidToken);
    }
    let value = header.to_str().map_err(|_| UserInfoError::InvalidToken)?;
    let (scheme, token) = value.split_once(' ').ok_or(UserInfoError::InvalidToken)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.len() > MAX_ACCESS_JWT_BYTES
        || token
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"-._~+/=".contains(&byte))
    {
        return Err(UserInfoError::InvalidToken);
    }
    Ok(token)
}

/// Emits a generic Bearer challenge without token bytes or parsing diagnostics.
fn unauthorized() -> Response {
    let mut response = ApiError::from_status(StatusCode::UNAUTHORIZED).into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

/// Applies to all route outcomes, including extractor and method failures.
pub(crate) async fn prevent_cache(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
