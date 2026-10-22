//! Real runtime-role suspension versus token issuance, ordered by observed PostgreSQL locks.
use super::*;

/// Seeds only the privileged fixture identity; every lifecycle transition uses actual HTTP policy.
async fn operator(t: &TokenFixture) -> Result<(Uuid, String)> {
    let user: Uuid=sqlx::query_scalar("INSERT INTO users(email,opaque_registration_record,status,email_verified_at) VALUES($1,$2,'active',clock_timestamp()) RETURNING id")
        .bind(format!("{}@operator.test",Uuid::new_v4())).bind(vec![3_u8;16]).fetch_one(&t.f.pool).await?;
    sqlx::query("INSERT INTO platform_operators(user_id) VALUES($1)")
        .bind(user)
        .execute(&t.f.pool)
        .await?;
    let cookie = crate::api::handlers::auth::generate_session_token()?;
    sqlx::query("INSERT INTO user_sessions(user_id,session_hash,expires_at,auth_time) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour',clock_timestamp())")
        .bind(user).bind(hash_session_token(&cookie)).execute(&t.f.pool).await?;
    sqlx::query("UPDATE users SET email_verified_at=clock_timestamp() WHERE id=$1")
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    Ok((user, cookie))
}

/// The real handler must commit audit and authority together, with no bearer material in its body.
async fn lifecycle(router: &Router, user: Uuid, cookie: &str, action: &str) -> Result<StatusCode> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/users/{user}/{action}"))
                .header(COOKIE, format!("permesi_session={cookie}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"reason":"administrative"}"#))?,
        )
        .await?;
    let status = response.status();
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert!(to_bytes(response.into_body(), 1024).await?.is_empty());
    Ok(status)
}

/// Detects actual lock ordering without assuming that a sleep means an operation has started.
async fn waiting(pool: &PgPool, statement: &str) -> Result<()> {
    timeout(Duration::from_secs(5),async {
        loop {
            let waiting: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND starts_with(query,$1))")
                .bind(statement).fetch_one(pool).await?;
            if waiting {return Ok::<_,anyhow::Error>(());}
            tokio::task::yield_now().await;
        }
    }).await.context("Expected containment ordering was not observed")?
}

/// A refresh that gets the identity first may commit; containment then retires its new lineage.
#[tokio::test]
async fn containment_after_inflight_refresh_revokes_committed_successor_across_replicas()
-> Result<()> {
    let t = TokenFixture::new().await?;
    let (_, cookie) = operator(&t).await?;
    let root = refresh::issue(&t).await?;
    let original = root["refresh_token"]
        .as_str()
        .context("refresh")?
        .to_owned();
    let a = runtime_router(&t.f).await?;
    let b = runtime_router(&t.f).await?;
    let mut blocker = t.f.pool.begin().await?;
    sqlx::query("SELECT id FROM oauth_refresh_families FOR UPDATE")
        .execute(&mut *blocker)
        .await?;
    let client = t.f.client;
    let rotating = tokio::spawn(async move { refresh::refresh(&a, client, &original, None).await });
    waiting(
        &t.f.pool,
        "SELECT *,expires_at>clock_timestamp() AS alive FROM oauth_refresh_families",
    )
    .await?;
    let target = t.f.user;
    let suspending = tokio::spawn(async move { lifecycle(&b, target, &cookie, "suspend").await });
    waiting(&t.f.pool, "SELECT id,status::text FROM users WHERE id=ANY").await?;
    blocker.commit().await?;
    let (status, next) = timeout(Duration::from_secs(5), rotating).await???;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        timeout(Duration::from_secs(5), suspending).await???,
        StatusCode::NO_CONTENT
    );
    let c = runtime_router(&t.f).await?;
    let (status, error) = refresh::refresh(
        &c,
        t.f.client,
        next["refresh_token"].as_str().context("successor")?,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, json!({"error":"invalid_grant"}));
    let state: (String,i64,i64)=sqlx::query_as("SELECT status::text,(SELECT count(*) FROM oauth_refresh_families WHERE user_id=$1 AND revoked_at IS NULL),(SELECT count(*) FROM user_sessions WHERE user_id=$1) FROM users WHERE id=$1")
        .bind(t.f.user).fetch_one(&t.f.pool).await?;
    assert_eq!(state, ("disabled".into(), 0, 0));
    Ok(())
}

/// Containment holding identity first blocks both code and refresh issuance, even after recovery.
#[tokio::test]
async fn containment_before_issuance_rejects_waiting_codes_and_refresh_without_receipts()
-> Result<()> {
    let t = TokenFixture::new().await?;
    let (actor, cookie) = operator(&t).await?;
    let root = refresh::issue(&t).await?;
    let original = root["refresh_token"]
        .as_str()
        .context("refresh")?
        .to_owned();
    let code = t.f.issue().await?;
    let a = runtime_router(&t.f).await?;
    let b = runtime_router(&t.f).await?;
    let c = runtime_router(&t.f).await?;
    let mut blocker = t.f.pool.begin().await?;
    sqlx::query("SELECT user_id FROM platform_operators WHERE user_id=$1 FOR UPDATE")
        .bind(actor)
        .execute(&mut *blocker)
        .await?;
    let target = t.f.user;
    let operator_cookie = cookie.clone();
    let suspending =
        tokio::spawn(async move { lifecycle(&a, target, &operator_cookie, "suspend").await });
    waiting(
        &t.f.pool,
        "SELECT user_id FROM platform_operators WHERE user_id=$1 AND enabled FOR SHARE",
    )
    .await?;
    let client = t.f.client;
    let code_copy = code.clone();
    let redeeming = tokio::spawn(async move {
        exchange(
            &b,
            &fields(&code_copy, &client.to_string(), REDIRECT, VERIFIER),
            None,
        )
        .await
    });
    waiting(
        &t.f.pool,
        "SELECT id FROM users WHERE id=$1 AND status='active'",
    )
    .await?;
    let refreshing =
        tokio::spawn(async move { refresh::refresh(&c, client, &original, None).await });
    waiting(
        &t.f.pool,
        "SELECT status::text,authorization_revision FROM users",
    )
    .await?;
    blocker.commit().await?;
    assert_eq!(
        timeout(Duration::from_secs(5), suspending).await???,
        StatusCode::NO_CONTENT
    );
    for result in [
        timeout(Duration::from_secs(5), redeeming).await???,
        timeout(Duration::from_secs(5), refreshing).await???,
    ] {
        assert_eq!(result.0, StatusCode::BAD_REQUEST);
        assert_eq!(result.1, json!({"error":"invalid_grant"}));
    }
    assert_eq!(
        lifecycle(&t.f.router, t.f.user, &cookie, "reactivate").await?,
        StatusCode::NO_CONTENT
    );
    let (status, error) = exchange(
        &t.f.router,
        &fields(&code, &client.to_string(), REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, json!({"error":"invalid_grant"}));
    let receipt_count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_token_issuances")
        .fetch_one(&t.f.pool)
        .await?;
    assert_eq!(
        receipt_count, 1,
        "Rejected requests must not issue receipts"
    );
    let code_unchanged: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NULL FROM oauth_authorization_codes WHERE code_hash=$1",
    )
    .bind(Sha256::digest(code.as_bytes()).to_vec())
    .fetch_one(&t.f.pool)
    .await?;
    assert!(
        code_unchanged,
        "Revocation must not masquerade as code consumption"
    );
    Ok(())
}
