//! Actual HTTP password/recovery regressions for revocation races and dependency rollback.
//! Fixtures use real registration uploads and PostgreSQL locks, never mocked principals.

use super::*;
use crate::api::handlers::{
    auth::{opaque::password::opaque_password_finish, storage},
    me,
};

/// A valid upload reaches password mutation without exposing its bytes in diagnostics.
fn registration_upload() -> Result<String> {
    let mut rng = opaque_rand_core::OsRng;
    let password = test_password();
    let setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
    let start = ClientRegistration::<OpaqueSuite>::start(&mut rng, &password)?;
    let response =
        ServerRegistration::start(&setup, start.message, b"password-lifecycle@example.com")?;
    let ksf = opaque_argon2::Argon2::default();
    let finish = start.state.finish(
        &mut rng,
        &password,
        response.message,
        ClientRegistrationFinishParameters::new(
            identifiers(b"password-lifecycle@example.com", b"api.permesi.dev"),
            Some(&ksf),
        ),
    )?;
    Ok(STANDARD.encode(finish.message.serialize()))
}

/// Captures password and authorization revision together for rollback assertions.
async fn password_snapshot(pool: &PgPool, user: Uuid) -> Result<(Vec<u8>, Uuid)> {
    Ok(sqlx::query_as(
        "SELECT opaque_registration_record,authorization_revision FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_one(pool)
    .await?)
}

/// Creates genuine current full authority; the fixture's clock history permits later expiry tests.
async fn current_user(pool: &PgPool) -> Result<(Uuid, String)> {
    let user = sqlx::query_scalar("INSERT INTO users (email,opaque_registration_record,status) VALUES ($1,$2,'active') RETURNING id")
        .bind(format!("{}@example.com",Uuid::new_v4())).bind(opaque_test_record()?).fetch_one(pool).await?;
    let cookie = storage::insert_session(pool, user, 3600).await?;
    sqlx::query("UPDATE user_sessions SET created_at=clock_timestamp()-INTERVAL '12 minutes' WHERE session_hash=$1")
        .bind(hash_session_token(&cookie)).execute(pool).await?;
    Ok((user, cookie))
}

/// Builds the real route with the same admission verification and state extraction as production.
fn password_router(pool: PgPool) -> Result<(Router, String)> {
    let (admission, signer, kid) = test_admission_context()?;
    Ok((
        Router::new()
            .route("/password", post(opaque_password_finish))
            .with_state(OpaqueTestState {
                auth: auth_state(),
                admission,
                pool,
            }),
        issue_zero_token(&signer, &kid)?,
    ))
}

/// Delivers a valid registration upload with the original exact session cookie.
async fn finish_password(
    router: Router,
    cookie: &str,
    zero: &str,
    upload: &str,
) -> Result<axum::response::Response> {
    Ok(router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/password")
                .header(COOKIE, format!("permesi_session={cookie}"))
                .header("X-Permesi-Zero-Token", zero)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"registration_record":upload}).to_string(),
                ))?,
        )
        .await?)
}

/// Observes a real blocked lifecycle writer on either the corrected or original implementation.
async fn wait_for_password_writer(pool: &PgPool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND (query LIKE 'SELECT status::text FROM users WHERE id=$1 FOR NO KEY UPDATE%' OR query LIKE 'UPDATE users SET opaque_registration_record%'))")
                .fetch_one(pool).await?;
            if waiting {return Ok::<_,anyhow::Error>(());}
            tokio::task::yield_now().await;
        }
    }).await.context("password writer did not reach the held identity lock")?
}

/// Revocation, expiry or stale recent authentication after the snapshot cannot authorize rotation.
#[tokio::test]
async fn password_http_revalidates_current_session_after_identity_lock_wait() -> Result<()> {
    for mutation in [
        "DELETE FROM user_sessions WHERE session_hash=$1",
        "UPDATE user_sessions SET auth_time=clock_timestamp()-INTERVAL '11 minutes' WHERE session_hash=$1",
        "UPDATE user_sessions SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE session_hash=$1",
    ] {
        let db = TestDb::new()
            .await?
            .context("Password lifecycle regression requires PostgreSQL")?;
        let (user, cookie) = current_user(&db.pool).await?;
        let before = password_snapshot(&db.pool, user).await?;
        let (router, zero) = password_router(db.pool.clone())?;
        let upload = registration_upload()?;
        let mut blocker = db.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR SHARE")
            .bind(user)
            .execute(&mut *blocker)
            .await?;
        let hash = hash_session_token(&cookie);
        let pending =
            tokio::spawn(async move { finish_password(router, &cookie, &zero, &upload).await });
        if let Err(err) = wait_for_password_writer(&db.pool).await {
            blocker.rollback().await?;
            pending.abort();
            return Err(err);
        }
        sqlx::query(mutation).bind(hash).execute(&db.pool).await?;
        blocker.rollback().await?;
        let response = tokio::time::timeout(Duration::from_secs(5), pending).await???;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert!(
            password_snapshot(&db.pool, user).await? == before,
            "Rejected rotation changed password authority"
        );
    }
    Ok(())
}

/// Failure after updating the password rolls back its revision and sessions and returns generic 503.
#[tokio::test]
async fn password_http_storage_failure_rolls_back_and_returns_unavailable() -> Result<()> {
    let db = TestDb::new()
        .await?
        .context("Password lifecycle regression requires PostgreSQL")?;
    let (user, cookie) = current_user(&db.pool).await?;
    let before = password_snapshot(&db.pool, user).await?;
    let (router, zero) = password_router(db.pool.clone())?;
    let upload = registration_upload()?;
    sqlx::raw_sql("CREATE FUNCTION reject_password_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-storage-sentinel'; END $$; CREATE TRIGGER reject_password_revocation BEFORE DELETE ON user_sessions FOR EACH ROW EXECUTE FUNCTION reject_password_revocation();").execute(&db.pool).await?;
    let response = finish_password(router.clone(), &cookie, &zero, &upload).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert!(to_bytes(response.into_body(), 4096).await?.is_empty());
    assert!(
        password_snapshot(&db.pool, user).await? == before,
        "Failed rotation changed password authority"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
        1
    );
    sqlx::query("DROP TRIGGER reject_password_revocation ON user_sessions")
        .execute(&db.pool)
        .await?;
    let response = finish_password(router, &cookie, &zero, &upload).await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().contains_key(SET_COOKIE));
    assert!(
        password_snapshot(&db.pool, user).await? != before,
        "Successful control did not rotate password authority"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Read/insert/update failures cannot publish partial recovery batches or expose storage errors.
#[tokio::test]
async fn recovery_regeneration_storage_failures_preserve_batch_and_return_unavailable() -> Result<()>
{
    for (fault, restore) in [
        (
            "ALTER TABLE user_mfa_state RENAME TO unavailable_mfa_state",
            "ALTER TABLE unavailable_mfa_state RENAME TO user_mfa_state",
        ),
        (
            "CREATE TRIGGER reject_recovery BEFORE INSERT ON user_mfa_recovery_codes FOR EACH ROW EXECUTE FUNCTION reject_recovery_storage()",
            "DROP TRIGGER reject_recovery ON user_mfa_recovery_codes",
        ),
        (
            "CREATE TRIGGER reject_recovery BEFORE UPDATE ON user_mfa_state FOR EACH ROW EXECUTE FUNCTION reject_recovery_storage()",
            "DROP TRIGGER reject_recovery ON user_mfa_state",
        ),
    ] {
        let db = TestDb::new()
            .await?
            .context("Recovery regression requires PostgreSQL")?;
        let (user, cookie) = current_user(&db.pool).await?;
        let batch = Uuid::new_v4();
        super::super::mfa::storage::upsert_mfa_state(
            &db.pool,
            user,
            super::super::mfa::MfaState::Enabled,
            Some(batch),
        )
        .await?;
        sqlx::query("INSERT INTO user_mfa_recovery_codes (user_id,batch_id,code_hash) VALUES ($1,$2,'original-test-hash')").bind(user).bind(batch).execute(&db.pool).await?;
        let auth = Arc::new(AuthState::new(
            auth_config(),
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_mins(5),
                10000,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new().with_recovery_pepper(Arc::from([7; 32])),
        ));
        let router = Router::new()
            .route("/recovery", post(me::regenerate_recovery_codes))
            .with_state(SessionTestState {
                auth,
                pool: db.pool.clone(),
            });
        sqlx::raw_sql("CREATE FUNCTION reject_recovery_storage() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-storage-sentinel'; END $$;").execute(&db.pool).await?;
        sqlx::raw_sql(fault).execute(&db.pool).await?;
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/recovery")
                .header(COOKIE, format!("permesi_session={cookie}"))
                .body(Body::empty())
        };
        let response = router.clone().oneshot(request()?).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(to_bytes(response.into_body(), 4096).await?.is_empty());
        sqlx::raw_sql(restore).execute(&db.pool).await?;
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT recovery_batch_id FROM user_mfa_state WHERE user_id=$1"
            )
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
            batch
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id=$1"
            )
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
            1
        );
        assert_eq!(router.oneshot(request()?).await?.status(), StatusCode::OK);
    }
    Ok(())
}

/// Existing recent-auth requirements are checked from the locked row on both MFA mutation routes.
#[tokio::test]
async fn mfa_mutation_http_revalidates_recent_auth_after_identity_lock_wait() -> Result<()> {
    for path in ["/recovery", "/totp"] {
        let db = TestDb::new()
            .await?
            .context("MFA mutation regression requires PostgreSQL")?;
        let (user, cookie) = current_user(&db.pool).await?;
        let batch = Uuid::new_v4();
        super::super::mfa::storage::upsert_mfa_state(
            &db.pool,
            user,
            super::super::mfa::MfaState::Enabled,
            Some(batch),
        )
        .await?;
        let auth = Arc::new(AuthState::new(
            auth_config(),
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_mins(5),
                10000,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new().with_recovery_pepper(Arc::from([7; 32])),
        ));
        let router = Router::new()
            .route("/recovery", post(me::regenerate_recovery_codes))
            .route("/totp", delete(me::disable_totp))
            .with_state(SessionTestState {
                auth,
                pool: db.pool.clone(),
            });
        let request = Request::builder()
            .method(if path == "/recovery" {
                "POST"
            } else {
                "DELETE"
            })
            .uri(path)
            .header(COOKIE, format!("permesi_session={cookie}"))
            .body(Body::empty())?;
        let mut blocker = db.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR SHARE")
            .bind(user)
            .execute(&mut *blocker)
            .await?;
        let pending = tokio::spawn(async move { router.oneshot(request).await });
        if let Err(err) = wait_for_password_writer(&db.pool).await {
            blocker.rollback().await?;
            pending.abort();
            return Err(err);
        }
        sqlx::query("UPDATE user_sessions SET auth_time=clock_timestamp()-INTERVAL '11 minutes' WHERE session_hash=$1").bind(hash_session_token(&cookie)).execute(&db.pool).await?;
        blocker.rollback().await?;
        let response = tokio::time::timeout(Duration::from_secs(5), pending).await???;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT recovery_batch_id FROM user_mfa_state WHERE user_id=$1"
            )
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
            batch
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state::text FROM user_mfa_state WHERE user_id=$1"
            )
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
            "enabled"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id=$1"
            )
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
            0
        );
    }
    Ok(())
}
