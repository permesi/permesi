//! `OPAQUE` login endpoints.

use anyhow::anyhow;
use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, ServerLogin,
    ServerLoginStartParameters, ServerRegistration,
};
use rand::rngs::OsRng;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use super::rate_limit::{RateLimitAction, RateLimitDecision};
use super::state::{AuthState, OpaqueSuite};
use super::storage::lookup_login_record;
use super::types::{OpaqueLoginFinishRequest, OpaqueLoginStartRequest, OpaqueLoginStartResponse};
use super::utils::{decode_base64_field, extract_client_ip, normalize_email, valid_email};
use super::zero_token::{ZeroTokenError, require_zero_token, zero_token_error_response};

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/login/start",
    request_body = OpaqueLoginStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE login started", body = OpaqueLoginStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_login_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueLoginStartRequest>>,
) -> impl IntoResponse {
    let request: OpaqueLoginStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = request.email.trim().to_string();
    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&email_normalized, RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let credential_bytes = match decode_base64_field(&request.credential_request) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(credential_request) = CredentialRequest::<OpaqueSuite>::deserialize(&credential_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        )
            .into_response();
    };

    let response =
        match build_login_start_response(&pool, &auth_state, &email_normalized, credential_request)
            .await
        {
            Ok(response) => response,
            Err((status, message)) => return (status, message).into_response(),
        };

    (StatusCode::OK, Json(response)).into_response()
}

async fn build_login_start_response(
    pool: &PgPool,
    auth_state: &AuthState,
    email_normalized: &str,
    credential_request: CredentialRequest<OpaqueSuite>,
) -> Result<OpaqueLoginStartResponse, (StatusCode, String)> {
    let login_record = match lookup_login_record(pool, email_normalized).await {
        Ok(record) => record,
        Err(err) => {
            error!("Login lookup failed: {err}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            ));
        }
    };

    let (password_file, user_id) = match login_record {
        Some(record) if record.status == "active" => {
            let password_file = ServerRegistration::deserialize(&record.opaque_record)
                .map_err(|_| anyhow!("Invalid stored registration record"));
            match password_file {
                Ok(file) => (Some(file), Some(record.user_id)),
                Err(err) => {
                    error!("Invalid registration record: {err}");
                    (None, None)
                }
            }
        }
        _ => (None, None),
    };

    let params = ServerLoginStartParameters {
        context: None,
        identifiers: Identifiers {
            client: Some(email_normalized.as_bytes()),
            server: Some(auth_state.opaque().server_id()),
        },
    };

    let mut rng = OsRng;
    let Ok(start_result) = ServerLogin::start(
        &mut rng,
        auth_state.opaque().server_setup(),
        password_file,
        credential_request,
        email_normalized.as_bytes(),
        params,
    ) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        ));
    };

    let login_id = auth_state
        .opaque()
        .store_login_state(start_result.state, user_id)
        .await;
    let credential_response =
        base64::engine::general_purpose::STANDARD.encode(start_result.message.serialize());

    Ok(OpaqueLoginStartResponse {
        login_id: login_id.to_string(),
        credential_response,
    })
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/login/finish",
    request_body = OpaqueLoginFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Login success"),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Unauthorized", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_login_finish(
    headers: HeaderMap,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueLoginFinishRequest>>,
) -> impl IntoResponse {
    let request: OpaqueLoginFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let Ok(login_id) = Uuid::parse_str(request.login_id.trim()) else {
        return (StatusCode::BAD_REQUEST, "Invalid login id".to_string()).into_response();
    };

    let credential_bytes = match decode_base64_field(&request.credential_finalization) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(credential_finalization) =
        CredentialFinalization::<OpaqueSuite>::deserialize(&credential_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid credential finalization".to_string(),
        )
            .into_response();
    };

    let Some(login_state) = auth_state.opaque().take_login_state(login_id).await else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    };

    if login_state.user_id.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    match login_state.state.finish(credential_finalization) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::rate_limit::{NoopRateLimiter, RateLimiter};
    use super::super::state::{AuthConfig, AuthState, OpaqueState};
    use super::{opaque_login_finish, opaque_login_start};
    use anyhow::Result;
    use axum::extract::Extension;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use std::time::Duration;

    fn auth_state() -> Result<Arc<AuthState>> {
        let config = AuthConfig::new(
            "http://genesis.test/v1/zero-token/validate".to_string(),
            "https://permesi.dev".to_string(),
        );
        let opaque = OpaqueState::from_seed(
            [1u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(30),
        );
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        Ok(Arc::new(AuthState::new(config, opaque, limiter)?))
    }

    #[tokio::test]
    async fn opaque_login_start_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = opaque_login_start(
            HeaderMap::new(),
            Extension(pool),
            Extension(auth_state()?),
            None,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn opaque_login_finish_missing_payload() -> Result<()> {
        let response = opaque_login_finish(HeaderMap::new(), Extension(auth_state()?), None)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
