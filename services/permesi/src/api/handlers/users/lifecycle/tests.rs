//! Actual HTTP, runtime-role privileges, rollback and identity-lock ordering regressions.
use super::*;
use anyhow::{Context as _, Result};
use axum::{Router, body::Body, extract::FromRef, http::Request, routing::post};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgPoolOptions;
use test_support::{postgres::PostgresContainer, runtime};
use tower::ServiceExt as _;

#[derive(Clone, FromRef)]
struct TestState {
    pool: PgPool,
    auth: Arc<AuthState>,
}

struct Fixture {
    _postgres: PostgresContainer,
    admin: PgPool,
    pool: PgPool,
    router: Router,
    actor: Uuid,
    target: Uuid,
    cookie: String,
}

impl Fixture {
    /// Uses a non-superuser runtime login and real cookie; no principal is forged.
    async fn new() -> Result<Self> {
        use crate::api::handlers::auth::{AuthConfig, OpaqueState, RateLimiter, mfa::MfaConfig};
        runtime::ensure_container_runtime()?;
        let postgres = PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        postgres.bootstrap().await?;
        let admin = PgPoolOptions::new()
            .max_connections(6)
            .connect(&postgres.admin_dsn_for_db("permesi"))
            .await?;
        let actor = account(&admin, true).await?;
        let target = account(&admin, true).await?;
        sqlx::query("INSERT INTO platform_operators(user_id) VALUES($1)")
            .bind(actor)
            .execute(&admin)
            .await?;
        let cookie = Uuid::new_v4().to_string();
        session(&admin, actor, &cookie).await?;
        let name = format!("containment_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {name} LOGIN PASSWORD '{password}'; GRANT permesi_runtime TO {name};"
        )))
        .execute(&admin)
        .await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&format!(
                "postgres://{name}:{password}@127.0.0.1:{}/permesi?sslmode=disable",
                postgres.host_port()
            ))
            .await?;
        let auth = Arc::new(AuthState::new(
            AuthConfig::new("https://permesi.test".into()).with_opaque_exchange_timeout_ms(1000),
            OpaqueState::from_seed(
                [31; 32],
                "permesi.test".into(),
                std::time::Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new(),
        ));
        let router = Router::new()
            .route("/v1/users/{id}/suspend", post(suspend))
            .route("/v1/users/{id}/reactivate", post(reactivate))
            .with_state(TestState {
                pool: pool.clone(),
                auth,
            });
        Ok(Self {
            _postgres: postgres,
            admin,
            pool,
            router,
            actor,
            target,
            cookie,
        })
    }

    /// Exercises JSON extraction and the actual handler, without diagnostic body disclosure.
    async fn call(&self, target: Uuid, action: &str, cookie: &str) -> Result<Response> {
        Ok(self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/users/{target}/{action}"))
                    .header("cookie", format!("permesi_session={cookie}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"reason":"administrative"}"#))?,
            )
            .await?)
    }

    /// A status/revision/audit snapshot proves rejected requests did not mutate protected state.
    async fn snapshot(&self) -> Result<(String, Uuid, i64)> {
        Ok(sqlx::query_as("SELECT status::text,authorization_revision,(SELECT count(*) FROM user_lifecycle_audit_log) FROM users WHERE id=$1")
            .bind(self.target).fetch_one(&self.admin).await?)
    }
}

/// Creates either a verified active identity or an unverified pending identity.
async fn account(pool: &PgPool, verified: bool) -> Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO users(email,opaque_registration_record,status,email_verified_at) VALUES($1,$2,CASE WHEN $3 THEN 'active'::user_status ELSE 'pending_verification'::user_status END,CASE WHEN $3 THEN clock_timestamp() ELSE NULL END) RETURNING id")
        .bind(format!("{}@example.test",Uuid::new_v4())).bind(vec![1_u8]).bind(verified).fetch_one(pool).await?)
}

/// Inserts a hashed full-session cookie with current recent authentication.
async fn session(pool: &PgPool, user: Uuid, cookie: &str) -> Result<()> {
    sqlx::query("INSERT INTO user_sessions(user_id,session_hash,expires_at,auth_time) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour',clock_timestamp())")
        .bind(user).bind(Sha256::digest(cookie.as_bytes()).to_vec()).execute(pool).await?;
    Ok(())
}

/// Seeds limited sessions and opaque ciphertext only to test their transactional retirement.
/// Cryptographic issuance/cutoff behavior is exercised separately with genuine proofs.
async fn pending_authority(f: &Fixture) -> Result<()> {
    for query in [
        "INSERT INTO user_mfa_bootstrap_sessions(user_id,session_hash,expires_at) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour')",
        "INSERT INTO user_mfa_challenge_sessions(user_id,session_hash,expires_at) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour')",
    ] {
        sqlx::query(query)
            .bind(f.target)
            .bind(vec![7_u8; 32])
            .execute(&f.admin)
            .await?;
    }
    sqlx::query("INSERT INTO opaque_exchanges(id_hash,purpose,user_id,credential_hash,sealed_state,created_at,expires_at) VALUES($2,'login',$1,$2,$3,clock_timestamp(),clock_timestamp()+INTERVAL '5 minutes')")
        .bind(f.target).bind(vec![7_u8;32]).bind(vec![0_u8;41]).execute(&f.admin).await?;
    sqlx::query("INSERT INTO webauthn_exchanges(id_hash,purpose,origin,rp_id,user_id,session_hash,sealed_state,created_at,expires_at) VALUES($2,'passkey_registration','https://permesi.test','permesi.test',$1,$2,$3,clock_timestamp(),clock_timestamp()+INTERVAL '5 minutes')")
        .bind(f.target).bind(vec![7_u8;32]).bind(vec![0_u8;41]).execute(&f.admin).await?;
    sqlx::query("INSERT INTO email_outbox(to_email,template,payload_json) SELECT email,'verify_email','{\"verify_url\":\"fixture-link\"}'::jsonb FROM users WHERE id=$1")
        .bind(f.target).execute(&f.admin).await?;
    Ok(())
}

/// Queries the exact retired rows; zero is meaningful because each table was seeded above.
async fn assert_pending_retired(f: &Fixture) -> Result<()> {
    for query in [
        "SELECT count(*) FROM user_mfa_bootstrap_sessions WHERE user_id=$1",
        "SELECT count(*) FROM user_mfa_challenge_sessions WHERE user_id=$1",
        "SELECT count(*) FROM opaque_exchanges WHERE user_id=$1",
        "SELECT count(*) FROM webauthn_exchanges WHERE user_id=$1",
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(query)
                .bind(f.target)
                .fetch_one(&f.admin)
                .await?,
            0
        );
    }
    let retired: bool=sqlx::query_scalar("SELECT status='failed' AND payload_json='{}'::jsonb AND claim_id IS NULL AND claim_expires_at IS NULL FROM email_outbox WHERE to_email=(SELECT email FROM users WHERE id=$1)")
        .bind(f.target).fetch_one(&f.admin).await?;
    assert!(retired);
    Ok(())
}

#[tokio::test]
async fn lifecycle_retires_sessions_verifiers_and_pending_proofs_with_runtime_privileges()
-> Result<()> {
    let f = Fixture::new().await?;
    session(&f.admin, f.target, "target-cookie").await?;
    pending_authority(&f).await?;
    sqlx::query("INSERT INTO email_verification_tokens(user_id,token_hash,expires_at) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour')")
        .bind(f.target).bind(vec![9_u8;32]).execute(&f.admin).await?;
    let before = f.snapshot().await?;
    assert_eq!(
        f.call(f.target, "suspend", &f.cookie).await?.status(),
        StatusCode::NO_CONTENT
    );
    let after = f.snapshot().await?;
    assert_eq!(after.0, "disabled");
    assert_ne!(before.1, after.1);
    assert_eq!(after.2, 1);
    let remaining: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM user_sessions WHERE user_id=$1),(SELECT count(*) FROM email_verification_tokens WHERE user_id=$1 AND consumed_at IS NULL)")
        .bind(f.target).fetch_one(&f.admin).await?;
    assert_eq!(remaining, (0, 0));
    assert_pending_retired(&f).await?;
    assert_eq!(
        f.call(f.target, "suspend", &f.cookie).await?.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(f.target, "reactivate", &f.cookie).await?.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(f.snapshot().await?.0, "active");
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM user_sessions WHERE user_id=$1")
        .bind(f.target)
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(retained, 0);
    let outcomes: Vec<String> =
        sqlx::query_scalar("SELECT outcome FROM user_lifecycle_audit_log ORDER BY created_at")
            .fetch_all(&f.admin)
            .await?;
    assert_eq!(outcomes, ["changed", "unchanged", "changed"]);
    assert!(
        sqlx::query("DELETE FROM user_lifecycle_audit_log")
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE user_lifecycle_audit_log SET reason='abuse'")
            .execute(&f.pool)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn lifecycle_reactivation_never_bypasses_mailbox_verification() -> Result<()> {
    let f = Fixture::new().await?;
    let pending = account(&f.admin, false).await?;
    assert_eq!(
        f.call(pending, "suspend", &f.cookie).await?.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(pending, "reactivate", &f.cookie).await?.status(),
        StatusCode::NO_CONTENT
    );
    let status: String = sqlx::query_scalar("SELECT status::text FROM users WHERE id=$1")
        .bind(pending)
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(status, "pending_verification");
    Ok(())
}

#[tokio::test]
async fn lifecycle_denies_nonoperators_stale_sessions_and_self_containment_without_changes()
-> Result<()> {
    let f = Fixture::new().await?;
    let before = f.snapshot().await?;
    assert_eq!(
        f.call(f.target, "suspend", "unknown").await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.call(f.actor, "suspend", &f.cookie).await?.status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE user_sessions SET created_at=clock_timestamp()-INTERVAL '20 minutes',auth_time=clock_timestamp()-INTERVAL '11 minutes' WHERE user_id=$1")
        .bind(f.actor).execute(&f.admin).await?;
    assert_eq!(
        f.call(f.target, "suspend", &f.cookie).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE user_sessions SET auth_time=clock_timestamp() WHERE user_id=$1")
        .bind(f.actor)
        .execute(&f.admin)
        .await?;
    sqlx::query("UPDATE platform_operators SET enabled=FALSE WHERE user_id=$1")
        .bind(f.actor)
        .execute(&f.admin)
        .await?;
    for role in ["owner", "admin", "editor", "member"] {
        sqlx::query("INSERT INTO user_roles(user_id,role) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET role=EXCLUDED.role")
            .bind(f.actor).bind(role).execute(&f.admin).await?;
        for target in [f.target, Uuid::new_v4()] {
            assert_eq!(
                f.call(target, "suspend", &f.cookie).await?.status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    assert_eq!(f.snapshot().await?, before);
    Ok(())
}

#[tokio::test]
async fn lifecycle_audit_failure_rolls_back_status_and_revocation() -> Result<()> {
    let f = Fixture::new().await?;
    session(&f.admin, f.target, "target-cookie").await?;
    sqlx::raw_sql("CREATE FUNCTION fail_containment_audit() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$; CREATE TRIGGER fail_containment_audit BEFORE INSERT ON user_lifecycle_audit_log FOR EACH ROW EXECUTE FUNCTION fail_containment_audit();")
        .execute(&f.admin).await?;
    let before = f.snapshot().await?;
    let response = f.call(f.target, "suspend", &f.cookie).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(f.snapshot().await?, before);
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM user_sessions WHERE user_id=$1")
        .bind(f.target)
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(sessions, 1);
    Ok(())
}

/// Observes a real lock waiter; no sleep is treated as proof of ordering.
async fn wait_for_containment(pool: &PgPool) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let blocked: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id,status::text FROM users WHERE id=ANY%')").fetch_one(pool).await?;
            if blocked {return Ok::<_,anyhow::Error>(());}
            tokio::task::yield_now().await;
        }
    }).await.context("Containment did not wait on the held identity")?
}

#[tokio::test]
async fn lifecycle_rechecks_operator_and_exact_session_after_lock_wait() -> Result<()> {
    for mutation in [
        "UPDATE platform_operators SET enabled=FALSE WHERE user_id=$1",
        "DELETE FROM user_sessions WHERE user_id=$1",
        "UPDATE user_sessions SET created_at=clock_timestamp()-INTERVAL '20 minutes',auth_time=clock_timestamp()-INTERVAL '11 minutes' WHERE user_id=$1",
    ] {
        let f = Fixture::new().await?;
        let mut lock = f.admin.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR SHARE")
            .bind(f.target)
            .execute(&mut *lock)
            .await?;
        let before = f.snapshot().await?;
        let router = f.router.clone();
        let actor_cookie = f.cookie.clone();
        let target = f.target;
        let task = tokio::spawn(async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/users/{target}/suspend"))
                        .header("cookie", format!("permesi_session={actor_cookie}"))
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"reason":"abuse"}"#))?,
                )
                .await
                .map_err(anyhow::Error::from)
        });
        wait_for_containment(&f.admin).await?;
        sqlx::query(mutation)
            .bind(f.actor)
            .execute(&f.admin)
            .await?;
        lock.rollback().await?;
        let response = task.await??;
        assert!(matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ));
        assert_eq!(f.snapshot().await?, before);
    }
    Ok(())
}

#[test]
fn lifecycle_payload_rejects_arbitrary_fields_and_free_text_reasons() {
    for invalid in [
        r#"{"reason":"password-secret"}"#,
        r#"{"reason":"abuse","role":"admin"}"#,
        r"{}",
    ] {
        assert!(serde_json::from_str::<LifecycleRequest>(invalid).is_err());
    }
}

/// Platform operators cannot discover missing IDs until their own current authority is checked.
#[tokio::test]
async fn lifecycle_unknown_target_and_bounded_wait_leave_protected_state_unchanged() -> Result<()> {
    let f = Fixture::new().await?;
    let before = f.snapshot().await?;
    assert_eq!(
        f.call(Uuid::new_v4(), "suspend", &f.cookie).await?.status(),
        StatusCode::NOT_FOUND
    );
    let mut blocker = f.admin.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR SHARE")
        .bind(f.target)
        .execute(&mut *blocker)
        .await?;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        f.call(f.target, "suspend", &f.cookie),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    blocker.rollback().await?;
    assert_eq!(f.snapshot().await?, before);
    Ok(())
}
