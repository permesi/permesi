//! Real OIDC `UserInfo` disclosure and negative-path tests.

use super::*;
use crate::api::handlers::auth::{
    AuthState, OpaqueState, RateLimitConfig, RateLimiter, SubjectKey, mfa::MfaConfig,
};
use std::{sync::Arc, time::Duration};

/// Exchanges exact OIDC scopes through the normal consent and Vault signing path.
async fn oidc_tokens(t: &TokenFixture, scopes: &str) -> Result<Value> {
    let page =
        t.f.start(&[
            ("scope", Some(scopes.into())),
            ("nonce", Some("userinfo-nonce".into())),
        ])
        .await?;
    let reply = if page.status == StatusCode::OK {
        t.f.decide(&page, "allow", "").await?
    } else {
        page
    };
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let code = parameter(reply.location.as_deref().context("callback")?, "code")?;
    let (status, response) = exchange(
        &t.f.router,
        &fields(&code, &t.f.client.to_string(), REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(response)
}

/// Calls the production `UserInfo` route without session authority or form credentials.
async fn call_userinfo(
    router: &Router,
    method: &str,
    uri: &str,
    authorization: Option<&str>,
    body: &str,
) -> Result<(StatusCode, Value, HeaderMap)> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = authorization {
        builder = builder.header("authorization", value);
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(body.to_owned()))?)
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 8192).await?;
    let payload = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, payload, headers))
}

/// GET/POST return only issued OIDC claims and never internal roles, tenant IDs or secrets.
#[tokio::test]
async fn userinfo_discloses_only_issued_oidc_scopes() -> Result<()> {
    let t = TokenFixture::new().await?;
    sqlx::query("UPDATE users SET display_name='Owner profile',email_verified_at=clock_timestamp() WHERE id=$1")
        .bind(t.f.user).execute(&t.f.pool).await?;
    let response = oidc_tokens(&t, "openid profile email jobs:read").await?;
    let access = response["access_token"].as_str().context("access token")?;
    let id_token = response["id_token"].as_str().context("ID token")?;
    let hash = Sha256::digest(access.as_bytes()).to_vec();
    let issued_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT issued_at FROM oauth_token_issuances WHERE access_token_hash=$1",
    )
    .bind(hash)
    .fetch_one(&t.f.pool)
    .await?;
    assert!(
        t.f.state
            .oauth
            .verify_access_token(access, issued_at.timestamp())
            .await
            .is_ok()
    );
    assert!(
        t.f.state
            .oauth
            .verify_access_token(access, issued_at.timestamp() - 1)
            .await
            .is_err()
    );
    let (encoded_header, tail) = access.split_once('.').context("JWS header")?;
    let mut header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_header)?)?;
    header["alg"] = Value::String("none".into());
    let downgraded = format!(
        "{}.{tail}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?)
    );
    assert!(
        t.f.state
            .oauth
            .verify_access_token(&downgraded, issued_at.timestamp())
            .await
            .is_err()
    );
    let authorization = format!("Bearer {access}");
    for method in ["GET", "POST"] {
        let (status, claims, headers) =
            call_userinfo(&t.f.router, method, "/userinfo", Some(&authorization), "").await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(CACHE_CONTROL).context("cache policy")?,
            "no-store"
        );
        assert_eq!(claims["sub"], t.f.user.to_string());
        assert_eq!(claims["name"], "Owner profile");
        assert_eq!(claims["email"], "owner@authorization.test");
        assert_eq!(claims["email_verified"], true);
        assert!(claims.get("organization_id").is_none());
        assert!(claims.get("scope").is_none());
        assert!(claims.get("roles").is_none());
    }
    let runtime = runtime_router(&t.f).await?;
    assert_eq!(
        call_userinfo(&runtime, "GET", "/userinfo", Some(&authorization), "")
            .await?
            .0,
        StatusCode::OK
    );
    let (status, _, _) = call_userinfo(
        &t.f.router,
        "GET",
        "/userinfo",
        Some(&format!("Bearer {id_token}")),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let minimal = oidc_tokens(&t, "openid jobs:read").await?;
    let bearer = format!(
        "Bearer {}",
        minimal["access_token"].as_str().context("minimal access")?
    );
    let (status, claims, _) =
        call_userinfo(&t.f.router, "GET", "/userinfo", Some(&bearer), "").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(claims.as_object().context("claims")?.len(), 1);
    assert_eq!(claims["sub"], t.f.user.to_string());
    Ok(())
}

/// Missing, substituted, expired, revoked and body/query credentials disclose nothing.
#[tokio::test]
async fn userinfo_rejects_untrusted_or_inactive_authority() -> Result<()> {
    let t = TokenFixture::new().await?;
    let response = oidc_tokens(&t, "openid profile jobs:read").await?;
    let access = response["access_token"].as_str().context("access token")?;
    let bearer = format!("Bearer {access}");
    for (uri, header, body) in [
        ("/userinfo", None, ""),
        ("/userinfo?access_token=secret", Some(bearer.as_str()), ""),
        ("/userinfo", Some("Bearer invalid"), ""),
        ("/userinfo", Some(bearer.as_str()), "access_token=secret"),
    ] {
        let (status, claims, headers) =
            call_userinfo(&t.f.router, "GET", uri, header, body).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(claims["error"]["code"], "unauthenticated");
        assert_eq!(
            headers.get(CACHE_CONTROL).context("cache policy")?,
            "no-store"
        );
    }
    let duplicated =
        t.f.router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header("authorization", &bearer)
                    .header("authorization", &bearer)
                    .body(Body::empty())?,
            )
            .await?;
    assert_eq!(duplicated.status(), StatusCode::UNAUTHORIZED);
    let plain_code = t.f.issue().await?;
    let (status, plain) = exchange(
        &t.f.router,
        &fields(&plain_code, &t.f.client.to_string(), REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let plain_bearer = format!(
        "Bearer {}",
        plain["access_token"].as_str().context("plain access")?
    );
    assert_eq!(
        call_userinfo(&t.f.router, "GET", "/userinfo", Some(&plain_bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let expiring = oidc_tokens(&t, "openid profile jobs:read").await?;
    let expiring_bearer = expiring["access_token"]
        .as_str()
        .context("expiring access")?;
    let hash = Sha256::digest(expiring_bearer.as_bytes()).to_vec();
    sqlx::query("UPDATE oauth_token_issuances SET issued_at=clock_timestamp()-INTERVAL '2 minutes',access_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE access_token_hash=$1")
        .bind(&hash).execute(&t.f.pool).await?;
    assert_eq!(
        call_userinfo(
            &t.f.router,
            "GET",
            "/userinfo",
            Some(&format!("Bearer {expiring_bearer}")),
            ""
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    let grant_id: Uuid =
        sqlx::query_scalar("SELECT id FROM oauth_grants WHERE user_id=$1 AND revoked_at IS NULL")
            .bind(t.f.user)
            .fetch_one(&t.f.pool)
            .await?;
    let revoke =
        t.f.call(
            &t.f.router,
            "DELETE",
            &format!("/v1/me/oauth/grants/{grant_id}"),
            Some(&t.f.token),
            None,
            None,
        )
        .await?;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);
    assert_eq!(
        call_userinfo(&t.f.router, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// Current tenant membership and client lifecycle are checked after issuance on every replica.
#[tokio::test]
async fn userinfo_rejects_membership_and_client_authority_loss() -> Result<()> {
    let t = TokenFixture::new().await?;
    let response = oidc_tokens(&t, "openid email jobs:read").await?;
    let bearer = format!(
        "Bearer {}",
        response["access_token"].as_str().context("access token")?
    );
    let b = refresh::replica(&t).await?;
    assert_eq!(
        call_userinfo(&b, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::OK
    );
    sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
        .bind(t.f.organization)
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        call_userinfo(&b, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE org_memberships SET status='active' WHERE org_id=$1 AND user_id=$2")
        .bind(t.f.organization)
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    sqlx::query("UPDATE oauth_clients SET disabled_at=clock_timestamp() WHERE id=$1")
        .bind(t.f.client_internal)
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        call_userinfo(&b, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// Each inactive ancestor or subject independently closes claim disclosure.
#[tokio::test]
async fn userinfo_rejects_inactive_user_and_tenant_ancestors() -> Result<()> {
    let t = TokenFixture::new().await?;
    let response = oidc_tokens(&t, "openid profile jobs:read").await?;
    let bearer = format!(
        "Bearer {}",
        response["access_token"].as_str().context("access token")?
    );
    let replica = refresh::replica(&t).await?;
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        call_userinfo(&replica, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE users SET status='active' WHERE id=$1")
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        call_userinfo(&replica, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let fresh = oidc_tokens(&t, "openid profile jobs:read").await?;
    let bearer = format!(
        "Bearer {}",
        fresh["access_token"].as_str().context("fresh token")?
    );
    assert_eq!(
        call_userinfo(&replica, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::OK
    );
    for (delete, restore, id) in [
        (
            "UPDATE applications SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE applications SET deleted_at=NULL WHERE id=$1",
            t.f.application,
        ),
        (
            "UPDATE environments SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE environments SET deleted_at=NULL WHERE id=$1",
            t.f.environment,
        ),
        (
            "UPDATE projects SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE projects SET deleted_at=NULL WHERE id=$1",
            t.f.project,
        ),
        (
            "UPDATE organizations SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE organizations SET deleted_at=NULL WHERE id=$1",
            t.f.organization,
        ),
    ] {
        sqlx::query(delete).bind(id).execute(&t.f.pool).await?;
        assert_eq!(
            call_userinfo(&replica, "GET", "/userinfo", Some(&bearer), "")
                .await?
                .0,
            StatusCode::UNAUTHORIZED,
            "{delete}"
        );
        sqlx::query(restore).bind(id).execute(&t.f.pool).await?;
    }
    assert_eq!(
        call_userinfo(&replica, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::OK
    );
    Ok(())
}

/// Password/MFA authority rotation invalidates `UserInfo` on every replica without changing profile data.
#[tokio::test]
async fn userinfo_rejects_stale_credential_revision() -> Result<()> {
    let t = TokenFixture::new().await?;
    let response = oidc_tokens(&t, "openid profile email jobs:read").await?;
    let bearer = format!(
        "Bearer {}",
        response["access_token"].as_str().context("access token")?
    );
    let b = refresh::replica(&t).await?;
    assert_eq!(
        call_userinfo(&b, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::OK
    );
    sqlx::query("UPDATE users SET authorization_revision=uuidv4() WHERE id=$1")
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    let (status, claims, _) = call_userinfo(&b, "GET", "/userinfo", Some(&bearer), "").await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(claims["error"]["code"], "unauthenticated");
    Ok(())
}

/// Production PostgreSQL limiter admits two requests, isolates its action and then returns JSON 429.
#[tokio::test]
async fn userinfo_postgres_budget_is_enforced_independently() -> Result<()> {
    let t = TokenFixture::new().await?;
    let response = oidc_tokens(&t, "openid profile jobs:read").await?;
    let bearer = format!(
        "Bearer {}",
        response["access_token"].as_str().context("access token")?
    );
    let mut state = runtime_state(&t.f).await?;
    let mut oauth = (*state.oauth).clone();
    oauth.config.tokens.ip_attempts = 2;
    state.oauth = Arc::new(oauth);
    state.auth = Arc::new(AuthState::new(
        state.auth.config().clone(),
        OpaqueState::from_seed([1; 32], "test".into(), Duration::from_secs(30), 10),
        Arc::new(RateLimiter::postgres(
            state.pool.clone(),
            RateLimitConfig::new(60, 2, 10),
            SubjectKey::derive(&[9; 32])?,
        )),
        MfaConfig::new(),
    ));
    let budgeted = router(&state);
    for method in ["GET", "POST"] {
        assert_eq!(
            call_userinfo(&budgeted, method, "/userinfo", Some(&bearer), "")
                .await?
                .0,
            StatusCode::OK
        );
    }
    let (status, body, headers) =
        call_userinfo(&budgeted, "GET", "/userinfo", Some(&bearer), "").await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
    assert_eq!(
        headers.get(CACHE_CONTROL).context("cache policy")?,
        "no-store"
    );
    let userinfo_count: i64 = sqlx::query_scalar(
        "SELECT attempts FROM auth_rate_limits WHERE action='userinfo' AND dimension='ip'",
    )
    .fetch_one(&t.f.pool)
    .await?;
    assert_eq!(userinfo_count, 3);
    let token_exchange_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_rate_limits WHERE action='token_exchange'")
            .fetch_one(&t.f.pool)
            .await?;
    assert_eq!(token_exchange_count, 0);
    Ok(())
}

/// A fabricated hash-only receipt cannot replace an RS256 signature or alter issued scopes.
#[tokio::test]
async fn userinfo_rejects_forged_receipt_and_scope_substitution() -> Result<()> {
    let t = TokenFixture::new().await?;
    let response = oidc_tokens(&t, "openid profile jobs:read").await?;
    let access = response["access_token"].as_str().context("access token")?;
    let (input, signature) = access.rsplit_once('.').context("JWS signature")?;
    let first = signature.chars().next().context("signature byte")?;
    let changed = if first == 'A' { 'B' } else { 'A' };
    let altered = format!(
        "{input}.{changed}{}",
        signature.get(1..).context("signature tail")?
    );
    let original_hash = Sha256::digest(access.as_bytes()).to_vec();
    let altered_hash = Sha256::digest(altered.as_bytes()).to_vec();
    sqlx::query("UPDATE oauth_token_issuances SET access_token_hash=$1 WHERE access_token_hash=$2")
        .bind(&altered_hash)
        .bind(&original_hash)
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        call_userinfo(
            &t.f.router,
            "GET",
            "/userinfo",
            Some(&format!("Bearer {altered}")),
            ""
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE oauth_token_issuances SET access_token_hash=$1,scope_names=ARRAY['openid','email'] WHERE access_token_hash=$2")
        .bind(&original_hash)
        .bind(&altered_hash)
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        call_userinfo(
            &t.f.router,
            "GET",
            "/userinfo",
            Some(&format!("Bearer {access}")),
            ""
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// A narrowed refresh receipt grants only its own scopes, not the family maximum.
#[tokio::test]
async fn userinfo_refresh_narrowing_cannot_restore_profile_claims() -> Result<()> {
    let t = TokenFixture::new().await?;
    sqlx::query("UPDATE users SET display_name='Current name',email_verified_at=clock_timestamp() WHERE id=$1")
        .bind(t.f.user).execute(&t.f.pool).await?;
    let page =
        t.f.start(&[
            (
                "scope",
                Some("openid profile email offline_access jobs:read".into()),
            ),
            ("nonce", Some("refresh-userinfo-nonce".into())),
            ("prompt", Some("consent".into())),
        ])
        .await?;
    assert_eq!(page.status, StatusCode::OK);
    let reply = t.f.decide(&page, "allow", "").await?;
    let code = parameter(reply.location.as_deref().context("callback")?, "code")?;
    let (status, issued) = exchange(
        &t.f.router,
        &fields(&code, &t.f.client.to_string(), REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let refresh = issued["refresh_token"].as_str().context("refresh token")?;
    let client_id = t.f.client.to_string();
    let (status, narrowed) = exchange(
        &t.f.router,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", refresh),
            ("scope", "openid jobs:read"),
        ],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let bearer = format!(
        "Bearer {}",
        narrowed["access_token"]
            .as_str()
            .context("narrowed access")?
    );
    let (status, claims, _) =
        call_userinfo(&t.f.router, "GET", "/userinfo", Some(&bearer), "").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(claims.as_object().context("claims")?.len(), 1);
    assert_eq!(claims["sub"], t.f.user.to_string());
    let successor = narrowed["refresh_token"].as_str().context("successor")?;
    let (status, without_openid) = exchange(
        &t.f.router,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", successor),
            ("scope", "jobs:read"),
        ],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let bearer = format!(
        "Bearer {}",
        without_openid["access_token"]
            .as_str()
            .context("non-OIDC access")?
    );
    assert_eq!(
        call_userinfo(&t.f.router, "GET", "/userinfo", Some(&bearer), "")
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}
