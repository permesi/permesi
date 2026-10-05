//! Browser authorization adapter using existing sessions and a database state machine.
//!
//! Flow Overview: GET validates and stores the request, then resumes with the existing
//! session or hands an opaque handle to the Web login route. Resume serves minimal
//! consent or issues a code using saved consent. POST requires browser binding, the
//! bound full session, and a one-use CSRF capability; form input cannot carry scopes.
//! Redirects use the exact registered string plus encoded protocol parameters only.
//! No submitted URL, code, cookie, nonce, SQL error, or authorization context is logged.

use super::auth::{
    AuthState, RateLimitAction, RateLimitDecision, SessionKind, extract_client_ip,
    hash_session_token,
    session::{authenticate_session, extract_session_token},
};
use crate::oauth::{
    authorization::{
        AuthorizationService, Decision, Error, Outcome, ProtocolError, SessionBinding,
        crypto::SecretValue,
        request::{AuthorizationInput, RequestedScope},
    },
    oidc::{Discovery, OAuthState, TokenSecurityMetadata},
    redirect_uri::RedirectUri,
};
use axum::{
    Form, Json,
    extract::{
        Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, LOCATION, REFERRER_POLICY, SET_COOKIE},
    },
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::PgPool;
use std::{fmt::Write as _, sync::Arc};
use uuid::Uuid;

const BROWSER_COOKIE: &str = "__Host-permesi_oauth";

#[utoipa::path(get, path="/.well-known/openid-configuration", responses((status=200, description="Implemented authorization-code, token and signing metadata", body=Discovery),(status=503,description="OAuth issuer is not configured")), tag="oauth")]
/// Returns static public issuer metadata without database budgets or header-derived identity.
pub(crate) async fn discovery(State(oauth): State<Arc<OAuthState>>) -> Response {
    let Some(issuer) = &oauth.config.issuer else {
        return secured(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    public_metadata(
        Json(Discovery {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/jwks.json"),
            response_types_supported: vec!["code"],
            response_modes_supported: vec!["query"],
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: vec!["RS256"],
            code_challenge_methods_supported: vec!["S256"],
            grant_types_supported: vec!["authorization_code"],
            token_security: TokenSecurityMetadata {
                token_endpoint_auth_methods_supported: vec!["client_secret_basic", "none"],
                authorization_response_iss_parameter_supported: true,
            },
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            claims_parameter_supported: false,
        })
        .into_response(),
        oauth.config.jwks_cache_ttl,
    )
}

#[utoipa::path(get,path="/jwks.json",responses((status=200,description="Retained Vault RSA public signing versions",body=crate::oauth::oidc::Jwks),(status=429,description="Shared JWKS refresh budget exhausted"),(status=503,description="OAuth/key source unavailable")),tag="oauth")]
/// Publishes cached public Vault key versions without using the authentication database.
/// Single-flight refresh and negative caching bound upstream reads; malformed keys fail closed.
pub(crate) async fn jwks(
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    headers: HeaderMap,
) -> Response {
    if oauth.config.issuer.is_none() {
        return secured(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    let refresh = requests_jwks_refresh(&headers);
    if refresh && oauth_rate_limited(&auth, &headers, RateLimitAction::JwksRefresh).await {
        return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    let keys = if refresh {
        oauth.refresh_jwks().await
    } else {
        oauth.jwks().await
    };
    match keys {
        Ok(keys) => public_metadata(Json(keys).into_response(), oauth.config.jwks_cache_ttl),
        Err(_) => secured(StatusCode::SERVICE_UNAVAILABLE.into_response()),
    }
}

/// Parses case-insensitive HTTP cache directives across repeated header fields.
/// Quoted zero is accepted; this selects a refresh, never bypasses its shared budget.
fn requests_jwks_refresh(headers: &HeaderMap) -> bool {
    headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| {
            let directive = directive.trim();
            let (name, value) = directive.split_once('=').unwrap_or((directive, ""));
            name.trim().eq_ignore_ascii_case("no-cache")
                || (name.trim().eq_ignore_ascii_case("max-age")
                    && matches!(value.trim(), "0" | "\"0\""))
        })
}

#[utoipa::path(get,path="/authorize",params(AuthorizationInput),responses((status=200,description="Minimal consent page",body=String,content_type="text/html"),(status=303,description="Validated client redirect or existing Web login",headers(("Location"=String,description="Exact registered redirect with code/state or protocol error, or configured login"))),(status=400,description="Invalid request without a trusted redirect"),(status=429,description="Shared authorization request rate limit exceeded"),(status=503,description="OAuth issuer is not configured")),tag="oauth")]
/// Persists validated requests before login; raw code plaintext exists only in a client redirect.
pub(crate) async fn authorize(
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    headers: HeaderMap,
    input: Result<Query<AuthorizationInput>, QueryRejection>,
) -> Response {
    if oauth.config.issuer.is_none() {
        return secured(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    if oauth_rate_limited(&auth, &headers, RateLimitAction::Authorize).await {
        return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    let Ok(Query(input)) = input else {
        return direct_invalid();
    };
    let Ok(browser) = browser_token(&headers).map_or_else(SecretValue::generate, Ok) else {
        return secured(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    let service = AuthorizationService {
        pool: &pool,
        config: &oauth.config,
    };
    let id = match service.start(input, &browser).await {
        Ok(id) => id,
        Err(error) => return error_response(error, oauth.config.issuer.as_deref()),
    };
    let mut response = advance(&service, id, &browser, &headers, Decision::Resume, &auth).await;
    let cookie = format!(
        "{BROWSER_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        browser.expose(),
        oauth.config.request_ttl
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

/// An opaque request locator is the only browser-visible authorization resume input.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in=Query)]
pub(crate) struct ResumeInput {
    #[param(value_type=String, format="uuid")]
    pub request_id: Uuid,
}

#[utoipa::path(get,path="/authorize/resume",params(ResumeInput),responses((status=200,description="Minimal consent page",body=String,content_type="text/html"),(status=303,description="Client or login redirect"),(status=400,description="Invalid, expired or browser-mismatched request"),(status=429,description="Shared OAuth rate limit exceeded"),(status=503,description="OAuth issuer unavailable")),tag="oauth")]
/// Resumes stored authority after login/MFA on any replica, requiring the binding cookie.
pub(crate) async fn resume(
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    headers: HeaderMap,
    input: Result<Query<ResumeInput>, QueryRejection>,
) -> Response {
    if oauth.config.issuer.is_none() {
        return secured(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    if oauth_rate_limited(&auth, &headers, RateLimitAction::Authorize).await {
        return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    let (Ok(Query(input)), Some(browser)) = (input, browser_token(&headers)) else {
        return direct_invalid();
    };
    advance(
        &AuthorizationService {
            pool: &pool,
            config: &oauth.config,
        },
        input.request_id,
        &browser,
        &headers,
        Decision::Resume,
        &auth,
    )
    .await
}

/// Consent form accepts only a stored request, CSRF capability and binary decision.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentInput {
    #[schema(value_type=String, format="uuid")]
    request_id: Uuid,
    csrf: String,
    decision: String,
}

#[utoipa::path(post,path="/authorize/consent",request_body(content=ConsentInput,content_type="application/x-www-form-urlencoded"),responses((status=303,description="Validated redirect with code or access_denied"),(status=400,description="Invalid consent form or binding"),(status=429,description="Shared OAuth rate limit exceeded"),(status=503,description="OAuth issuer unavailable")),tag="oauth")]
/// Requires server-generated CSRF plus bound browser/full session; scope additions are rejected.
pub(crate) async fn consent(
    State(pool): State<PgPool>,
    State(oauth): State<Arc<OAuthState>>,
    State(auth): State<Arc<AuthState>>,
    headers: HeaderMap,
    input: Result<Form<ConsentInput>, FormRejection>,
) -> Response {
    let Some(issuer) = &oauth.config.issuer else {
        return secured(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    if !consent_origin_allowed(&headers, issuer) {
        return direct_invalid();
    }
    if oauth_rate_limited(&auth, &headers, RateLimitAction::Authorize).await {
        return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    let (Ok(Form(input)), Some(browser)) = (input, browser_token(&headers)) else {
        return direct_invalid();
    };
    let Ok(csrf) = SecretValue::parse(&input.csrf) else {
        return direct_invalid();
    };
    let decision = match input.decision.as_str() {
        "allow" => Decision::Allow(csrf),
        "cancel" => Decision::Cancel(csrf),
        _ => return direct_invalid(),
    };
    let response = advance(
        &AuthorizationService {
            pool: &pool,
            config: &oauth.config,
        },
        input.request_id,
        &browser,
        &headers,
        decision,
        &auth,
    )
    .await;
    if response.status() == StatusCode::BAD_REQUEST {
        return secured((StatusCode::BAD_REQUEST, Html("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Authorization unavailable</title><h1>Authorization unavailable</h1><p>This request has expired or is no longer available. Return to the application and start sign-in again.</p></html>")).into_response());
    }
    response
}

/// Permits issuer-origin consent posts and browser-proven same-origin opaque posts.
/// This checks only origin isolation; browser/session binding and CSRF remain required.
/// Opaque posts require same-origin Fetch Metadata; native consent forms use same-origin
/// referrer policy so browsers without Fetch Metadata can send their actual Origin. Non-browser callers without Origin still require every stored proof.
fn consent_origin_allowed(headers: &HeaderMap, issuer: &str) -> bool {
    match headers.get("origin") {
        None => true,
        Some(origin) => match origin.to_str() {
            Ok(origin) if origin == issuer => true,
            Ok("null") => headers
                .get("sec-fetch-site")
                .is_some_and(|site| site == "same-origin"),
            _ => false,
        },
    }
}

/// Extracts the existing full session without using internal roles as OAuth authority.
async fn session_binding(
    headers: &HeaderMap,
    pool: &PgPool,
) -> Result<Option<SessionBinding>, StatusCode> {
    let session = authenticate_session(headers, pool).await?;
    Ok(session
        .filter(|s| s.kind == SessionKind::Full)
        .and_then(|s| {
            extract_session_token(headers).map(|token| SessionBinding {
                user_id: s.user_id,
                hash: hash_session_token(&token),
            })
        }))
}

/// Adapts domain outcomes with a shared budget bound to request and browser digest.
/// A foreign browser cannot exhaust the authentic browser's budget by learning the locator.
/// PostgreSQL remains responsible for verifying every browser/session/consent binding.
async fn advance(
    service: &AuthorizationService<'_>,
    id: Uuid,
    browser: &SecretValue,
    headers: &HeaderMap,
    decision: Decision,
    auth: &AuthState,
) -> Response {
    let Some(issuer) = service.config.issuer.as_deref() else {
        return secured(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    if auth
        .rate_limiter()
        .check_email(
            &format!("oauth-request/{id}/{}", hex::encode(browser.hash())),
            RateLimitAction::Authorize,
        )
        .await
        == RateLimitDecision::Limited
    {
        return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    let session = match session_binding(headers, service.pool).await {
        Ok(session) => session,
        Err(status) => return secured(status.into_response()),
    };
    match service
        .advance(id, browser, session.as_ref(), decision)
        .await
    {
        Ok(Outcome::Login {
            request_id,
            expires_at,
        }) => redirect_response(&format!(
            "{}/login?oauth_request={request_id}&oauth_expires={}",
            auth.config().frontend_base_url().trim_end_matches('/'),
            expires_at.timestamp_millis()
        )),
        Ok(Outcome::Consent {
            request_id,
            csrf,
            client,
            application,
            organization,
            scopes,
        }) => consent_page(
            request_id,
            &csrf,
            &client,
            &application,
            &organization,
            &scopes,
        ),
        Ok(Outcome::Redirect {
            redirect,
            code,
            state,
        }) => protocol_redirect(&redirect, "code", code.expose(), state.as_deref(), issuer),
        Ok(Outcome::Denied { redirect, state }) => protocol_redirect(
            &redirect,
            "error",
            "access_denied",
            state.as_deref(),
            issuer,
        ),
        Err(error) => error_response(error, Some(issuer)),
    }
}

/// Extracts a canonical host-only browser-binding cookie, rejecting duplicate occurrences.
fn browser_token(headers: &HeaderMap) -> Option<SecretValue> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let mut values = cookie
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| *name == BROWSER_COOKIE);
    let (_, value) = values.next()?;
    if values.next().is_some() {
        return None;
    }
    SecretValue::parse(value).ok()
}

/// Returns errors directly unless a validated exact redirect was explicitly attached.
fn error_response(error: Error, issuer: Option<&str>) -> Response {
    if error.database {
        return secured(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    match (error.redirect, issuer) {
        (Some(redirect), Some(issuer)) => protocol_redirect(
            &redirect,
            "error",
            error.protocol.as_str(),
            error.state.as_deref(),
            issuer,
        ),
        _ => direct_invalid(),
    }
}

/// Builds response parameters without parsing/reserializing the original redirect URI.
/// Original path/query bytes remain exact; code/error, unchanged state and RFC 9207 iss are added.
fn protocol_redirect(
    redirect: &RedirectUri,
    key: &str,
    value: &str,
    state: Option<&str>,
    issuer: &str,
) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(key, value);
    query.append_pair("iss", issuer);
    if let Some(state) = state {
        query.append_pair("state", state);
    }
    let separator = if redirect.as_str().contains('?') {
        '&'
    } else {
        '?'
    };
    redirect_response(&format!(
        "{}{separator}{}",
        redirect.as_str(),
        query.finish()
    ))
}

/// Emits a redirect without ever logging the Location header or response body.
fn redirect_response(location: &str) -> Response {
    let Ok(location) = HeaderValue::from_str(location) else {
        return secured(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    secured((StatusCode::SEE_OTHER, [(LOCATION, location)]).into_response())
}

/// Renders stored scopes read-only with fully escaped display text and no script execution.
/// Form navigation is unrestricted by CSP because browsers cannot match IPv6 callbacks;
/// the state machine independently permits only the exact registered redirect URI.
fn consent_page(
    id: Uuid,
    csrf: &SecretValue,
    client: &str,
    application: &str,
    organization: &str,
    scopes: &[RequestedScope],
) -> Response {
    let mut items = String::new();
    for scope in scopes {
        let label = match scope.name.as_str() {
            "openid" => "Sign in and identify your account",
            "profile" => "Read your profile",
            "email" => "Read your verified email address",
            "address" => "Read your address",
            "phone" => "Read your phone number",
            _ => {
                if scope.description.is_empty() {
                    &scope.name
                } else {
                    &scope.description
                }
            }
        };
        let _ = write!(items, "<li>{}</li>", escape_html(label));
    }
    let mut response = secured(Html(format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Authorize access · Permesi</title><style>body{{font:18px system-ui;max-width:38rem;margin:4rem auto;padding:1rem}}button{{cursor:pointer;padding:.7rem 1.2rem;margin:.5rem}}button:hover{{background:#ddd}}button:focus-visible{{outline:3px solid #345}}</style></head><body><h1>Authorize access</h1><p>{} / {}</p><p>Organization: {}</p><h2>Requesting access to</h2><ul>{items}</ul><form method=\"post\" action=\"/authorize/consent\"><input type=\"hidden\" name=\"request_id\" value=\"{id}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button class=\"cursor-pointer\" name=\"decision\" value=\"allow\">Allow</button><button class=\"cursor-pointer\" name=\"decision\" value=\"cancel\">Cancel</button></form></body></html>", escape_html(application), escape_html(client), escape_html(organization), csrf.expose())).into_response());
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}

/// Escapes registry/client display text so an administrator cannot inject consent markup.
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Uses stable direct errors without reflecting request fields or leaking context.
fn direct_invalid() -> Response {
    secured(
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": ProtocolError::InvalidRequest.as_str()})),
        )
            .into_response(),
    )
}

/// Applies shared IP protection before OAuth transactions or Vault/cache work.
async fn oauth_rate_limited(
    auth: &AuthState,
    headers: &HeaderMap,
    action: RateLimitAction,
) -> bool {
    auth.rate_limiter()
        .check_ip(extract_client_ip(headers).as_deref(), action)
        .await
        == RateLimitDecision::Limited
}

/// Makes only nonsecret positive discovery/JWKS responses cacheable for the bounded TTL.
fn public_metadata(response: Response, ttl: i64) -> Response {
    let mut response = secured(response);
    if let Ok(value) = HeaderValue::from_str(&format!("public, max-age={ttl}")) {
        response.headers_mut().insert(CACHE_CONTROL, value);
    }
    response
}

/// Prevents caching, referrer/code leakage and framing; consent has no external resources.
fn secured(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests;
