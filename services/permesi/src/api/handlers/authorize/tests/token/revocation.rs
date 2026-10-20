//! RFC 7009 refresh-family revocation through real HTTP, PostgreSQL and Vault authority.
use super::*;
use crate::api::handlers::auth::{
    AuthState, OpaqueState, RateLimitConfig, RateLimiter, SubjectKey, mfa::MfaConfig,
};
use std::{sync::Arc, time::Duration};

/// Sends an unauthenticated-by-cookie revocation request and checks non-cacheable output.
async fn revoke(
    router: &Router,
    fields: &[(&str, &str)],
    basic: Option<&str>,
) -> Result<(StatusCode, Vec<u8>)> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.extend_pairs(fields.iter().copied());
    let mut request = Request::builder()
        .method("POST")
        .uri("/revoke")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(value) = basic {
        request = request.header("authorization", value);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::from(form.finish()))?)
        .await?;
    let status = response.status();
    ensure!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .is_some_and(|v| v == "no-store")
            && response
                .headers()
                .get("pragma")
                .is_some_and(|v| v == "no-cache")
            && response.headers().get(LOCATION).is_none(),
        "unsafe revocation response"
    );
    if status == StatusCode::UNAUTHORIZED {
        ensure!(
            response.headers().get("www-authenticate").is_some(),
            "missing Basic challenge"
        );
    }
    Ok((
        status,
        to_bytes(response.into_body(), 65536).await?.to_vec(),
    ))
}

/// The exact authenticated client can revoke an old lineage hash on another replica.
#[tokio::test]
async fn revocation_disables_family_across_replicas_without_a_token_oracle() -> Result<()> {
    let t = TokenFixture::new().await?;
    let issued = refresh::issue(&t).await?;
    let root = issued["refresh_token"].as_str().context("refresh token")?;
    let b = refresh::replica(&t).await?;
    let (status, rotated) = refresh::refresh(&b, t.f.client, root, None).await?;
    assert_eq!(status, StatusCode::OK);
    let successor = rotated["refresh_token"].as_str().context("successor")?;
    let client = t.f.client.to_string();
    let unknown_opaque = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    for presented in ["unknown", unknown_opaque.as_str(), root, root, successor] {
        let (status, body) = revoke(
            &b,
            &[
                ("token", presented),
                ("client_id", &client),
                ("token_type_hint", "refresh_token"),
            ],
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty(), "revocation disclosed token state");
    }
    let (status, error) = refresh::refresh(&t.f.router, t.f.client, successor, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, json!({"error":"invalid_grant"}));
    let stored: (String, Vec<u8>) = sqlx::query_as(
        "SELECT f.revocation_reason,t.token_hash FROM oauth_refresh_families f
         JOIN oauth_refresh_tokens t ON t.family_id=f.id WHERE t.previous_hash IS NOT NULL",
    )
    .fetch_one(&t.f.pool)
    .await?;
    assert_eq!(stored.0, "client");
    assert_ne!(stored.1, successor.as_bytes(), "raw bearer persisted");
    Ok(())
}

/// A different public client or failed confidential proof cannot burn another client's token.
#[tokio::test]
async fn revocation_rejects_foreign_client_without_changing_family() -> Result<()> {
    let t = TokenFixture::new().await?;
    let issued = refresh::issue(&t).await?;
    let token = issued["refresh_token"].as_str().context("refresh token")?;
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO oauth_clients(application_id,client_id,name,client_type) VALUES($1,$2,'Other','public')")
        .bind(t.f.application).bind(other).execute(&t.f.pool).await?;
    let (status, body) = revoke(
        &t.f.router,
        &[("token", token), ("client_id", &other.to_string())],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(
        body.is_empty(),
        "foreign-client revocation disclosed token state"
    );
    let (status, _) = revoke(&t.f.router, &[("token", token)], Some("Basic bWFsZm9ybWVk")).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, rotated) = refresh::refresh(&t.f.router, t.f.client, token, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(rotated.get("refresh_token").is_some());
    Ok(())
}

/// Revocation and rotation serialize on the same family; no successor survives either order.
#[tokio::test]
async fn revocation_racing_rotation_never_leaves_a_live_successor() -> Result<()> {
    let t = TokenFixture::new().await?;
    let issued = refresh::issue(&t).await?;
    let root = issued["refresh_token"].as_str().context("refresh token")?;
    let b = refresh::replica(&t).await?;
    let client = t.f.client.to_string();
    let revocation_fields = [("token", root), ("client_id", client.as_str())];
    let (revoke_result, refresh_result) = tokio::join!(
        revoke(&b, &revocation_fields, None),
        refresh::refresh(&t.f.router, t.f.client, root, None)
    );
    assert_eq!(revoke_result?.0, StatusCode::OK);
    let (status, rotated) = refresh_result?;
    if status == StatusCode::OK {
        let successor = rotated["refresh_token"].as_str().context("successor")?;
        let (next_status, _) = refresh::refresh(&b, t.f.client, successor, None).await?;
        assert_eq!(next_status, StatusCode::BAD_REQUEST);
    } else {
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM oauth_refresh_families")
            .fetch_one(&t.f.pool)
            .await?;
    assert!(revoked);
    Ok(())
}

/// The canonical non-superuser runtime role can commit revocation across a schema reapply.
#[tokio::test]
async fn revocation_runtime_role_preserves_hash_only_authority() -> Result<()> {
    let t = TokenFixture::new().await?;
    let issued = refresh::issue(&t).await?;
    let token = issued["refresh_token"].as_str().context("refresh token")?;
    let runtime = runtime_router(&t.f).await?;
    let client = t.f.client.to_string();
    let (status, body) =
        revoke(&runtime, &[("token", token), ("client_id", &client)], None).await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(body.is_empty(), "runtime revocation disclosed token state");
    let (status, _) = refresh::refresh(&t.f.router, t.f.client, token, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

/// Confidential revocation requires a current Basic proof, not a body identifier or stale secret.
#[tokio::test]
async fn revocation_confidential_client_requires_current_basic_secret() -> Result<()> {
    let mut t = TokenFixture::new().await?;
    let client = Uuid::new_v4();
    let internal: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (application_id,client_id,name,client_type)
         VALUES ($1,$2,'Revocation confidential','confidential') RETURNING id",
    )
    .bind(t.f.application)
    .bind(client)
    .fetch_one(&t.f.pool)
    .await?;
    sqlx::query("INSERT INTO oauth_client_redirect_uris (client_id,redirect_uri) VALUES ($1,$2)")
        .bind(internal)
        .bind(REDIRECT)
        .execute(&t.f.pool)
        .await?;
    sqlx::query(
        "INSERT INTO oauth_client_scopes (client_id,application_id,scope_id)
                 SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2",
    )
    .bind(internal)
    .bind(t.f.application)
    .execute(&t.f.pool)
    .await?;
    sqlx::query("INSERT INTO org_roles (org_id,name) VALUES ($1,'owner')")
        .bind(t.f.organization)
        .execute(&t.f.pool)
        .await?;
    sqlx::query("INSERT INTO org_member_roles (org_id,user_id,role_name) VALUES ($1,$2,'owner')")
        .bind(t.f.organization)
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    t.f.client = client;
    t.f.client_internal = internal;
    let context = crate::oauth::service::ApplicationContext::resolved(t.f.application, t.f.user);
    let credential =
        t.f.state
            .oauth
            .credentials
            .issue(&t.f.pool, &context, client, None)
            .await?;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{client}:{}",
            credential.client_secret.expose_secret()
        ))
    );
    let issued = refresh::issue_as(&t, Some(&basic)).await?;
    let token = issued["refresh_token"].as_str().context("refresh token")?;
    let client_name = client.to_string();
    let fields = [("token", token), ("client_id", client_name.as_str())];
    assert_eq!(
        revoke(&t.f.router, &fields, None).await?.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        revoke(&t.f.router, &fields, Some("Basic bad")).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let current =
        t.f.state
            .oauth
            .credentials
            .issue(&t.f.pool, &context, client, Some(credential.credential.id))
            .await?;
    t.f.state
        .oauth
        .credentials
        .revoke(&t.f.pool, &context, client, credential.credential.id)
        .await?;
    assert_eq!(
        revoke(&t.f.router, &fields, Some(&basic)).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let current_basic = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{client}:{}",
            current.client_secret.expose_secret()
        ))
    );
    assert_eq!(
        revoke(&t.f.router, &fields, Some(&current_basic)).await?.0,
        StatusCode::OK
    );
    let (status, _) = exchange(
        &t.f.router,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", &client_name),
        ],
        Some(&current_basic),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

/// Known access and ID JWTs report unsupported type instead of falsely claiming revocation.
#[tokio::test]
async fn revocation_reports_issued_access_type_without_touching_refresh() -> Result<()> {
    let t = TokenFixture::new().await?;
    let issued = refresh::issue(&t).await?;
    let access = issued["access_token"].as_str().context("access token")?;
    let id_token = issued["id_token"].as_str().context("ID token")?;
    let refresh_token = issued["refresh_token"].as_str().context("refresh token")?;
    let client = t.f.client.to_string();
    let (status, body) = revoke(
        &t.f.router,
        &[("token", access), ("client_id", &client)],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        json!({"error":"unsupported_token_type"})
    );
    let (status, body) = revoke(
        &t.f.router,
        &[("token", id_token), ("client_id", &client)],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        json!({"error":"unsupported_token_type"})
    );
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO oauth_clients(application_id,client_id,name,client_type) VALUES($1,$2,'Other','public')")
        .bind(t.f.application).bind(other).execute(&t.f.pool).await?;
    let (status, body) = revoke(
        &t.f.router,
        &[("token", access), ("client_id", &other.to_string())],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.is_empty(),
        "foreign access response disclosed token state"
    );
    let (status, body) = revoke(
        &t.f.router,
        &[("token", id_token), ("client_id", &other.to_string())],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "foreign ID response disclosed token state");
    let (status, _) = refresh::refresh(&t.f.router, t.f.client, refresh_token, None).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

/// Issuance exhaustion cannot block one emergency revocation; revocation has its own bound.
#[tokio::test]
async fn revocation_shared_budget_is_distinct_and_fail_closed() -> Result<()> {
    let t = TokenFixture::new().await?;
    let issued = refresh::issue(&t).await?;
    let token = issued["refresh_token"].as_str().context("refresh token")?;
    let mut state = runtime_state(&t.f).await?;
    let mut oauth = (*state.oauth).clone();
    oauth.config.tokens.ip_attempts = 1;
    oauth.config.tokens.client_ip_attempts = 10;
    state.oauth = Arc::new(oauth);
    state.auth = Arc::new(AuthState::new(
        state.auth.config().clone(),
        OpaqueState::from_seed([1; 32], "test".into(), Duration::from_secs(30), 10),
        Arc::new(RateLimiter::postgres(
            state.pool.clone(),
            RateLimitConfig::new(60, 1, 10),
            SubjectKey::derive(&[9; 32])?,
        )),
        MfaConfig::new(),
    ));
    let service = router(&state);
    let client = t.f.client.to_string();
    let unsupported = [
        ("grant_type", "unsupported"),
        ("client_id", client.as_str()),
    ];
    assert_eq!(
        exchange(&service, &unsupported, None).await?.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        exchange(&service, &unsupported, None).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let request = [("token", token), ("client_id", client.as_str())];
    assert_eq!(revoke(&service, &request, None).await?.0, StatusCode::OK);
    assert_eq!(
        revoke(&service, &request, None).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let attempts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT action,attempts FROM auth_rate_limits
         WHERE action IN ('token_exchange','token_revocation') AND dimension='ip' ORDER BY action",
    )
    .fetch_all(&t.f.pool)
    .await?;
    assert_eq!(
        attempts,
        vec![("token_exchange".into(), 2), ("token_revocation".into(), 2)]
    );
    Ok(())
}
