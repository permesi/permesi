//! Registration regressions exercise the real PostgreSQL activation boundary.

use super::*;
use axum::response::IntoResponse as _;

/// A verification capability proves email possession, never permission to undo suspension.
#[tokio::test]
async fn verification_never_reactivates_disabled_account() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let email = "disabled@example.com";
    insert_user_and_verification(&db.pool, email, &opaque_test_record()?, &config).await?;
    let user = lookup_user_id(&db.pool, email).await?;
    let token = issue_verification_token(&db.pool, user, email, &config).await?;
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(user)
        .execute(&db.pool)
        .await?;
    let mut tx = db.pool.begin().await?;
    let accepted = consume_verification_token(&mut tx, &hash_verification_token(&token)).await?;
    tx.commit().await?;
    assert!(!accepted, "verification must not override disabled status");
    let protected: (String, bool) =
        sqlx::query_as("SELECT status::text,email_verified_at IS NULL FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(protected, ("disabled".to_owned(), true));
    Ok(())
}

/// Different links for one account cannot each perform an activation transition.
#[tokio::test]
async fn verification_invalidates_sibling_links() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let email = "siblings@example.com";
    insert_user_and_verification(&db.pool, email, &opaque_test_record()?, &config).await?;
    let user = lookup_user_id(&db.pool, email).await?;
    let first = issue_verification_token(&db.pool, user, email, &config).await?;
    let second = issue_verification_token(&db.pool, user, email, &config).await?;
    let mut tx = db.pool.begin().await?;
    assert!(consume_verification_token(&mut tx, &hash_verification_token(&first)).await?);
    tx.commit().await?;
    let mut tx = db.pool.begin().await?;
    assert!(!consume_verification_token(&mut tx, &hash_verification_token(&second)).await?);
    tx.commit().await?;
    Ok(())
}

/// Independent HTTP endpoints and persistence each reject synthetic reserved identities.
#[tokio::test]
async fn signup_rejects_ninety_two_synthetic_accounts_without_side_effects() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = AuthConfig::new("https://permesi.dev".into());
    let state = Arc::new(AuthState::new(
        config.clone(),
        OpaqueState::from_seed(
            [0; 32],
            "api.permesi.dev".into(),
            Duration::from_secs(300),
            1000,
        ),
        Arc::new(RateLimiter::noop()),
        MfaConfig::new(),
    ));
    let (admission, key, kid) = test_admission_context()?;
    let zero = issue_zero_token(&key, &kid)?;
    let app = opaque_router(state, admission, db.pool.clone());
    let record = opaque_test_record()?;
    for index in 0..92 {
        let email = format!("synthetic-{index}@example.com");
        for (path, payload) in [
            (
                "start",
                json!({"email":email,"registration_request":STANDARD.encode(&record)}),
            ),
            (
                "finish",
                json!({"email":email,"registration_record":STANDARD.encode(&record)}),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/auth/opaque/signup/{path}"))
                        .header(CONTENT_TYPE, "application/json")
                        .header("X-Permesi-Zero-Token", &zero)
                        .body(Body::from(payload.to_string()))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        assert!(matches!(
            insert_user_and_verification(&db.pool, &email, &record, &config).await?,
            SignupOutcome::Rejected
        ));
    }
    let counts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM email_verification_tokens),(SELECT count(*) FROM email_outbox)").fetch_one(&db.pool).await?;
    assert_eq!(counts, (0, 0, 0));
    Ok(())
}

/// Same-user resends serialize while unrelated accounts still activate and deadlines roll back.
#[tokio::test]
async fn verification_lock_wait_is_bounded_and_other_accounts_progress() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let record = opaque_test_record()?;
    for email in ["locked@example.com", "other@example.com"] {
        insert_user_and_verification(&db.pool, email, &record, &config).await?;
    }
    let user = lookup_user_id(&db.pool, "locked@example.com").await?;
    let mut blocker = db.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR NO KEY UPDATE")
        .bind(user)
        .execute(&mut *blocker)
        .await?;
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM email_outbox WHERE to_email='locked@example.com'")
            .fetch_one(&db.pool)
            .await?;
    let waiting = enqueue_resend_verification(&db.pool, "locked@example.com", &config);
    let other = enqueue_resend_verification(&db.pool, "other@example.com", &config);
    let started = std::time::Instant::now();
    let (waiting, other) = tokio::join!(waiting, other);
    assert!(waiting.is_err());
    assert!(matches!(other?, ResendOutcome::Cooldown));
    assert!(started.elapsed() < Duration::from_secs(3));
    blocker.rollback().await?;
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM email_outbox WHERE to_email='locked@example.com'")
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(before, after);
    let status: String = sqlx::query_scalar("SELECT status::text FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&db.pool)
        .await?;
    assert_eq!(status, "pending_verification");
    Ok(())
}

/// Separate replicas cannot each queue an email after observing the same expired cooldown.
#[tokio::test]
async fn resend_concurrent_requests_queue_only_one_message() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let email = "resend-race@example.com";
    insert_user_and_verification(&db.pool, email, &opaque_test_record()?, &config).await?;
    sqlx::query(
        "UPDATE email_verification_tokens SET created_at=clock_timestamp()-INTERVAL '1 hour'",
    )
    .execute(&db.pool)
    .await?;
    let (a, b) = tokio::join!(
        enqueue_resend_verification(&db.pool, email, &config),
        enqueue_resend_verification(&db.pool, email, &config)
    );
    let outcomes = [a?, b?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| matches!(v, ResendOutcome::Queued))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| matches!(v, ResendOutcome::Cooldown))
            .count(),
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM email_outbox")
        .fetch_one(&db.pool)
        .await?;
    assert_eq!(count, 2);
    Ok(())
}

/// Active authority is never issued before possession of the mailbox capability is proved.
#[tokio::test]
async fn pending_signup_password_cannot_obtain_session() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let (admission, key, kid) = test_admission_context()?;
    let zero = issue_zero_token(&key, &kid)?;
    let app = opaque_router(auth_state(), admission, db.pool.clone());
    let email = "pending@example.com";
    let password = test_password();
    run_opaque_signup(&app, email, &password, &zero, [31; 32]).await?;
    let mut rng = ChaCha20Rng::from_seed([32; 32]);
    let start = ClientLogin::<OpaqueSuite>::start(&mut rng, &password)?;
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/v1/auth/opaque/login/start").header(CONTENT_TYPE,"application/json").header("X-Permesi-Zero-Token",&zero).body(Body::from(json!({"email":email,"credential_request":STANDARD.encode(start.message.serialize())}).to_string()))?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(SET_COOKIE).is_none());
    let payload: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let proof = CredentialResponse::<OpaqueSuite>::deserialize(
        &STANDARD.decode(
            payload
                .get("credential_response")
                .context("credential response")?
                .as_str()
                .context("credential response")?,
        )?,
    )?;
    let ksf = opaque_argon2::Argon2::default();
    assert!(
        start
            .state
            .finish(
                &mut rng,
                &password,
                proof,
                ClientLoginFinishParameters::new(
                    None,
                    identifiers(email.as_bytes(), b"api.permesi.dev"),
                    Some(&ksf)
                )
            )
            .is_err()
    );
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/v1/auth/opaque/login/finish").header(CONTENT_TYPE,"application/json").header("X-Permesi-Zero-Token",&zero).body(Body::from(json!({"email":email,"login_id":payload.get("login_id").context("login id")?,"credential_finalization":bogus_credential_finalization()}).to_string()))?).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(SET_COOKIE).is_none());
    let protected: (String,bool,i64) = sqlx::query_as("SELECT status::text,email_verified_at IS NULL,(SELECT count(*) FROM user_sessions) FROM users WHERE email=$1").bind(email).fetch_one(&db.pool).await?;
    assert_eq!(protected, ("pending_verification".into(), true, 0));
    Ok(())
}

/// Two different live links on independent connections have exactly one activation winner.
#[tokio::test]
async fn verification_concurrent_sibling_links_have_one_winner() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let email = "activation-race@example.com";
    insert_user_and_verification(&db.pool, email, &opaque_test_record()?, &config).await?;
    let user = lookup_user_id(&db.pool, email).await?;
    let first = issue_verification_token(&db.pool, user, email, &config).await?;
    let second = issue_verification_token(&db.pool, user, email, &config).await?;
    let activate = async |hash: Vec<u8>| {
        let mut tx = super::super::operations::begin(&db.pool, 1000).await?;
        let accepted = consume_verification_token(&mut tx, &hash).await?;
        tx.commit().await?;
        anyhow::Ok(accepted)
    };
    let (a, b) = tokio::join!(
        activate(hash_verification_token(&first)),
        activate(hash_verification_token(&second))
    );
    assert_eq!(usize::from(a?) + usize::from(b?), 1);
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM email_verification_tokens WHERE user_id=$1 AND consumed_at IS NULL",
    )
    .bind(user)
    .fetch_one(&db.pool)
    .await?;
    assert_eq!(live, 0);
    Ok(())
}

/// Expiry uses wall-clock database time after waiting, not the transaction's start timestamp.
#[tokio::test]
async fn verification_expiring_during_lock_wait_fails_closed() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let email = "lock-expiry@example.com";
    insert_user_and_verification(&db.pool, email, &opaque_test_record()?, &config).await?;
    let user = lookup_user_id(&db.pool, email).await?;
    let token = issue_verification_token(&db.pool, user, email, &config).await?;
    let hash = hash_verification_token(&token);
    let mut holder = db.pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR NO KEY UPDATE")
        .bind(user)
        .execute(&mut *holder)
        .await?;
    sqlx::query("UPDATE email_verification_tokens SET expires_at=clock_timestamp()+INTERVAL '100 milliseconds' WHERE token_hash=$1").bind(&hash).execute(&db.pool).await?;
    let mut waiter = db.pool.begin().await?;
    let release = async {
        tokio::time::sleep(Duration::from_millis(180)).await;
        holder.commit().await
    };
    let (accepted, release) = tokio::join!(consume_verification_token(&mut waiter, &hash), release);
    release?;
    assert!(!accepted?);
    waiter.commit().await?;
    let state: (String, bool) =
        sqlx::query_as("SELECT status::text,email_verified_at IS NULL FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(state, ("pending_verification".into(), true));
    Ok(())
}

/// Trusted status, role, scope and membership fields cannot be smuggled into signup DTOs.
#[test]
fn signup_dtos_reject_browser_supplied_authority() {
    for field in [
        "status",
        "email_verified",
        "email_verified_at",
        "role",
        "organization_id",
        "scopes",
    ] {
        let mut start = json!({"email":"a@permesi.dev","registration_request":"opaque"});
        let mut finish = json!({"email":"a@permesi.dev","registration_record":"opaque"});
        if let Some(object) = start.as_object_mut() {
            object.insert(field.into(), json!(true));
        }
        if let Some(object) = finish.as_object_mut() {
            object.insert(field.into(), json!(true));
        }
        assert!(
            serde_json::from_value::<super::super::types::OpaqueSignupStartRequest>(start).is_err()
        );
        assert!(
            serde_json::from_value::<super::super::types::OpaqueSignupFinishRequest>(finish)
                .is_err()
        );
    }
}

/// A valid verification uses one pooled connection at a time, including shared account limits.
#[tokio::test]
async fn verification_succeeds_with_single_connection_pool() -> Result<()> {
    let db = TestDb::new().await?.context("PostgreSQL is required")?;
    let config = auth_config();
    let email = "single-connection@example.com";
    insert_user_and_verification(&db.pool, email, &opaque_test_record()?, &config).await?;
    let user = lookup_user_id(&db.pool, email).await?;
    let token = issue_verification_token(&db.pool, user, email, &config).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*db.pool.connect_options()).clone())
        .await?;
    let limiter = RateLimiter::postgres(
        pool.clone(),
        RateLimitConfig::new(600, 100, 10),
        super::super::SubjectKey::derive(&[4; 32])?,
    );
    let state = Arc::new(AuthState::new(
        config,
        OpaqueState::from_seed(
            [0; 32],
            "api.permesi.dev".into(),
            Duration::from_secs(300),
            100,
        ),
        Arc::new(limiter),
        MfaConfig::new(),
    ));
    let (admission, key, kid) = test_admission_context()?;
    let zero = issue_zero_token(&key, &kid)?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Permesi-Zero-Token", zero.parse()?);
    let response = super::super::verification::verify_email(
        headers,
        axum::extract::State(pool),
        axum::extract::State(state),
        axum::extract::State(admission),
        Some(axum::Json(super::super::types::VerifyEmailRequest {
            token,
        })),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let state: (String, bool) =
        sqlx::query_as("SELECT status::text,email_verified_at IS NOT NULL FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(state, ("active".into(), true));
    Ok(())
}
