//! Bounded OAuth token adapter; session cookies never authenticate delegated clients.
//!
//! Flow Overview: enforce a complete-request deadline and body limit, parse strict form /
//! Basic inputs, apply shared PostgreSQL budgets, and call the transaction-owning exchange.
//! Only committed output reaches JSON. Every response prevents caching and contains no
//! redirects, SQL/Vault diagnostics, submitted secrets or internal authorization details.

use super::auth::{AuthState, RateLimitAction, RateLimitConfig, extract_client_ip};
use crate::oauth::{
    oidc::OAuthState,
    tokens::{self, TokenError, TokenResponse, request},
};
use axum::{
    Json,
    extract::{Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{CACHE_CONTROL, PRAGMA, WWW_AUTHENTICATE},
    },
    response::{IntoResponse as _, Response},
};
use serde::Serialize;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use utoipa::ToSchema;

/// OAuth error envelope deliberately excludes submitted values and diagnostic text.
#[derive(Serialize, ToSchema)]
struct TokenFailure {
    error: &'static str,
}

#[utoipa::path(post,path="/token",request_body(content=String,content_type="application/x-www-form-urlencoded",description="grant_type=authorization_code with code, redirect_uri, code_verifier; or grant_type=refresh_token with refresh_token and optional narrowing scope. Public clients supply client_id; confidential clients use HTTP Basic"),responses((status=200,description="Committed RS256 access token, optional initial OIDC ID token and rotating refresh token after explicit offline consent",body=TokenResponse),(status=400,description="Invalid request, client, grant, scope or unsupported grant type",body=TokenFailure),(status=401,description="Invalid HTTP Basic client authentication",body=TokenFailure),(status=429,description="Shared token exchange budget exhausted",body=TokenFailure),(status=503,description="Issuer or exchange dependency unavailable",body=TokenFailure)),tag="oauth")]
/// Exchanges S256 codes or single-use refresh tokens; failures before commit roll back the owned transaction.
pub(crate) async fn token(
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    request: Request,
) -> Response {
    let supplied_auth = request
        .headers()
        .contains_key(axum::http::header::AUTHORIZATION);
    let result = tokio::time::timeout(
        Duration::from_millis(oauth.config.tokens.timeout_ms),
        handle(&pool, &oauth, &auth, request),
    )
    .await
    .unwrap_or(Err(TokenError::Unavailable));
    match result {
        Ok(response) => no_cache(Json(response).into_response()),
        Err(error) => failure(error, supplied_auth),
    }
}

/// Bounds memory and throttles before Argon2 or signing; uses no browser/tenant authority.
async fn handle(
    pool: &PgPool,
    oauth: &OAuthState,
    auth: &AuthState,
    request: Request,
) -> Result<TokenResponse, TokenError> {
    if oauth.config.issuer.is_none() {
        return Err(TokenError::Unavailable);
    }
    let (parts, body) = request.into_parts();
    let ip = extract_client_ip(&parts.headers);
    let policy = &oauth.config.tokens;
    let limiter = auth.rate_limiter().configured(RateLimitConfig::new(
        policy.rate_window,
        policy.ip_attempts,
        policy.client_ip_attempts,
    ));
    if let Some(status) = limiter
        .check_ip(ip.as_deref(), RateLimitAction::TokenExchange)
        .await
        .denial_status()
    {
        return Err(if status == StatusCode::SERVICE_UNAVAILABLE {
            TokenError::Unavailable
        } else {
            TokenError::Limited
        });
    }
    let body = axum::body::to_bytes(body, oauth.config.tokens.max_body_bytes)
        .await
        .map_err(|_| TokenError::InvalidRequest)?;
    let (request, authentication) = request::parse(&parts.headers, &body)?;
    if let Some(status) = limiter
        .check_email(
            &format!(
                "token-client/{}/ip/{}",
                authentication.client_id(),
                ip.as_deref().unwrap_or("unknown")
            ),
            RateLimitAction::TokenExchange,
        )
        .await
        .denial_status()
    {
        return Err(if status == StatusCode::SERVICE_UNAVAILABLE {
            TokenError::Unavailable
        } else {
            TokenError::Limited
        });
    }
    tokens::exchange(pool, oauth, request, authentication).await
}

/// Uses RFC 6749 status/challenge semantics without revealing registration or credential state.
fn failure(error: TokenError, supplied_auth: bool) -> Response {
    let status = match error {
        TokenError::InvalidClient if supplied_auth => StatusCode::UNAUTHORIZED,
        TokenError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        TokenError::Limited => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::BAD_REQUEST,
    };
    let mut response = (
        status,
        Json(TokenFailure {
            error: error.as_str(),
        }),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Basic realm=\"permesi\""),
        );
    }
    no_cache(response)
}

/// Applies to the complete token router, including method and extractor failures.
pub(crate) async fn prevent_cache(response: Response) -> Response {
    no_cache(response)
}

/// Every exchange response is non-cacheable and has no navigation target.
fn no_cache(mut response: Response) -> Response {
    let headers: &mut HeaderMap = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(PRAGMA, axum::http::HeaderValue::from_static("no-cache"));
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}
