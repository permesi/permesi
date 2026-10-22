//! Real PostgreSQL/HTTP regressions for the designation authority boundary.

use super::*;
use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::FromRef,
    http::Request,
    routing::{get, post},
};
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
    db: PgPool,
    runtime_pool: PgPool,
    router: Router,
    first: Uuid,
    second: Uuid,
    third: Uuid,
    first_cookie: String,
    second_cookie: String,
    third_cookie: String,
}

impl Fixture {
    /// Boots a real runtime role so table privileges participate in each route test.
    async fn new() -> Result<Self> {
        use crate::api::handlers::auth::{AuthConfig, OpaqueState, RateLimiter, mfa::MfaConfig};
        runtime::ensure_container_runtime()?;
        let postgres = PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        postgres.bootstrap().await?;
        let db = PgPoolOptions::new()
            .max_connections(8)
            .connect(&postgres.admin_dsn_for_db("permesi"))
            .await?;
        let first = account(&db, true).await?;
        let second = account(&db, true).await?;
        let third = account(&db, true).await?;
        sqlx::query("INSERT INTO platform_operators(user_id) VALUES($1)")
            .bind(first)
            .execute(&db)
            .await?;
        let first_cookie = Uuid::new_v4().to_string();
        let second_cookie = Uuid::new_v4().to_string();
        let third_cookie = Uuid::new_v4().to_string();
        session(&db, first, &first_cookie).await?;
        session(&db, second, &second_cookie).await?;
        session(&db, third, &third_cookie).await?;
        let name = format!("operator_lifecycle_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {name} LOGIN PASSWORD '{password}'; GRANT permesi_runtime TO {name};"
        )))
        .execute(&db)
        .await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
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
        let router = operator_router(pool.clone(), auth);
        Ok(Self {
            _postgres: postgres,
            db,
            runtime_pool: pool,
            router,
            first,
            second,
            third,
            first_cookie,
            second_cookie,
            third_cookie,
        })
    }

    /// Calls the real route using an exact hashed session cookie.
    async fn call(&self, actor_cookie: &str, target: Uuid, action: &str) -> Result<StatusCode> {
        Self::call_on(self.router.clone(), actor_cookie, target, action).await
    }

    /// A second router owns an independent service state while sharing PostgreSQL.
    fn other_router(&self) -> Router {
        use crate::api::handlers::auth::{AuthConfig, OpaqueState, RateLimiter, mfa::MfaConfig};
        let auth = Arc::new(AuthState::new(
            AuthConfig::new("https://permesi.test".into()).with_opaque_exchange_timeout_ms(1000),
            OpaqueState::from_seed(
                [32; 32],
                "permesi.test".into(),
                std::time::Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new(),
        ));
        operator_router(self.runtime_pool.clone(), auth)
    }

    /// Sends one HTTP request through the selected independent service state.
    async fn call_on(
        router: Router,
        actor_cookie: &str,
        target: Uuid,
        action: &str,
    ) -> Result<StatusCode> {
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/users/{target}/operator/{action}"))
                    .header("cookie", format!("permesi_session={actor_cookie}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"reason":"administrative"}"#))?,
            )
            .await?;
        Ok(response.status())
    }
}

/// Shared route wiring for two separately constructed service states.
fn operator_router(pool: PgPool, auth: Arc<AuthState>) -> Router {
    Router::new()
        .route(
            "/v1/users/{id}/suspend",
            post(super::super::lifecycle::suspend),
        )
        .route("/v1/users/{id}/operator", get(get_operator))
        .route(
            "/v1/users/{id}/operator/request-enable",
            post(request_enable),
        )
        .route("/v1/users/{id}/operator/enable", post(enable))
        .route("/v1/users/{id}/operator/disable", post(disable))
        .with_state(TestState { pool, auth })
}

#[tokio::test]
async fn operator_suspension_clears_pending_designation_request() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/users/{}/suspend", f.second))
                .header("cookie", format!("permesi_session={}", f.first_cookie))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"suspected_compromise"}"#))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform_operator_enable_requests WHERE target_id=$1",
    )
    .bind(f.second)
    .fetch_one(&f.db)
    .await?;
    assert_eq!(pending, 0);
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::CONFLICT
    );
    Ok(())
}

#[tokio::test]
async fn operator_disabled_proposer_cannot_authorize_pending_request() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    session(&f.db, f.second, &f.second_cookie).await?;
    assert_eq!(
        f.call(&f.second_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    // Simulate a legacy/manual designation change that left the pending row intact.
    sqlx::query("UPDATE platform_operators SET enabled=FALSE WHERE user_id=$1")
        .bind(f.second)
        .execute(&f.db)
        .await?;
    assert_eq!(
        f.call(&f.first_cookie, f.third, "enable").await?,
        StatusCode::CONFLICT
    );
    let granted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM platform_operators WHERE user_id=$1")
            .bind(f.third)
            .fetch_one(&f.db)
            .await?;
    assert_eq!(granted, 0);
    Ok(())
}

/// Creates a verified active account or a pending one for rejection tests.
async fn account(db: &PgPool, verified: bool) -> Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO users(email,opaque_registration_record,status,email_verified_at) VALUES($1,$2,CASE WHEN $3 THEN 'active'::user_status ELSE 'pending_verification'::user_status END,CASE WHEN $3 THEN clock_timestamp() ELSE NULL END) RETURNING id")
        .bind(format!("{}@example.test",Uuid::new_v4())).bind(vec![1_u8]).bind(verified)
        .fetch_one(db).await?)
}

/// Seeds a current full session accepted by the normal authentication path.
async fn session(db: &PgPool, user: Uuid, cookie: &str) -> Result<()> {
    sqlx::query("INSERT INTO user_sessions(user_id,session_hash,expires_at,auth_time) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour',clock_timestamp())")
        .bind(user).bind(Sha256::digest(cookie.as_bytes()).to_vec()).execute(db).await?;
    Ok(())
}

#[tokio::test]
async fn operator_requires_separate_approval_after_first_expansion() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.third_cookie, f.second, "request-enable").await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/users/{}/operator", f.second))
                .header("cookie", format!("permesi_session={}", f.first_cookie))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let status: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)?;
    let requester_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
        .bind(f.first)
        .fetch_one(&f.db)
        .await?;
    assert_eq!(
        status
            .get("requested_by_email")
            .and_then(|value| value.as_str()),
        Some(requester_email.as_str())
    );
    assert_eq!(
        status
            .get("requested_reason")
            .and_then(|value| value.as_str()),
        Some("administrative")
    );
    assert!(
        status
            .get("requested_at")
            .and_then(|value| value.as_str())
            .is_some()
    );
    // The only bootstrap operator can explicitly add its first new peer.
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::CONFLICT
    );
    session(&f.db, f.second, &f.second_cookie).await?;
    assert_eq!(
        f.call(&f.first_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.third, "enable").await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        Fixture::call_on(f.other_router(), &f.second_cookie, f.third, "enable").await?,
        StatusCode::NO_CONTENT
    );
    let third_enabled: bool =
        sqlx::query_scalar("SELECT enabled FROM platform_operators WHERE user_id=$1")
            .bind(f.third)
            .fetch_one(&f.db)
            .await?;
    assert!(third_enabled);
    let audit_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM platform_operator_audit_log WHERE target_id=$1")
            .bind(f.third)
            .fetch_one(&f.db)
            .await?;
    assert_eq!(audit_count, 2);
    Ok(())
}

#[tokio::test]
async fn operator_request_audits_selected_reason_without_free_text() -> Result<()> {
    let f = Fixture::new().await?;
    let rejected = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/users/{}/operator/request-enable", f.second))
                .header("cookie", format!("permesi_session={}", f.first_cookie))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"free-form incident details"}"#))?,
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let prior_audit: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_operator_audit_log")
        .fetch_one(&f.db)
        .await?;
    assert_eq!(prior_audit, 0);
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/users/{}/operator/request-enable", f.second))
                .header("cookie", format!("permesi_session={}", f.first_cookie))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"incident_recovery"}"#))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let stored: String = sqlx::query_scalar(
        "SELECT reason FROM platform_operator_enable_requests WHERE target_id=$1",
    )
    .bind(f.second)
    .fetch_one(&f.db)
    .await?;
    assert_eq!(stored, "incident_recovery");
    let audited: String = sqlx::query_scalar(
        "SELECT reason FROM platform_operator_audit_log WHERE target_id=$1 AND action='request_enable'",
    )
    .bind(f.second)
    .fetch_one(&f.db)
    .await?;
    assert_eq!(audited, stored);
    Ok(())
}

#[tokio::test]
async fn operator_disable_blocks_old_tokens_and_requires_distinct_restoration() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    session(&f.db, f.second, &f.second_cookie).await?;
    assert_eq!(
        f.call(&f.first_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.second_cookie, f.third, "enable").await?,
        StatusCode::NO_CONTENT
    );
    session(&f.db, f.third, &f.third_cookie).await?;
    let old_revision: Uuid =
        sqlx::query_scalar("SELECT token_revision FROM platform_operators WHERE user_id=$1")
            .bind(f.second)
            .fetch_one(&f.db)
            .await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "disable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "disable").await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(&f.third_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    let new_revision: Uuid =
        sqlx::query_scalar("SELECT token_revision FROM platform_operators WHERE user_id=$1")
            .bind(f.second)
            .fetch_one(&f.db)
            .await?;
    assert_ne!(old_revision, new_revision);
    let surviving_sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_sessions WHERE user_id=$1")
            .bind(f.second)
            .fetch_one(&f.db)
            .await?;
    assert_eq!(surviving_sessions, 0);
    Ok(())
}

#[tokio::test]
async fn operator_bootstrap_exception_does_not_reopen_after_peer_disabled() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "disable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.third, "enable").await?,
        StatusCode::CONFLICT
    );
    let granted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM platform_operators WHERE user_id=$1")
            .bind(f.third)
            .fetch_one(&f.db)
            .await?;
    assert_eq!(granted, 0);
    Ok(())
}

#[tokio::test]
async fn operator_rejects_self_inactive_and_unverified_targets_without_audit() -> Result<()> {
    let f = Fixture::new().await?;
    let pending = account(&f.db, false).await?;
    assert_eq!(
        f.call(&f.first_cookie, f.first, "disable").await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(&f.first_cookie, pending, "request-enable").await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(&f.first_cookie, Uuid::new_v4(), "request-enable")
            .await?,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(f.second)
        .execute(&f.db)
        .await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::CONFLICT
    );
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_operator_audit_log")
        .fetch_one(&f.db)
        .await?;
    assert_eq!(audit_count, 0);
    Ok(())
}

#[tokio::test]
async fn operator_expired_request_cannot_be_approved_or_stolen_while_current() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    session(&f.db, f.second, &f.second_cookie).await?;
    assert_eq!(
        f.call(&f.first_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.second_cookie, f.third, "request-enable").await?,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE platform_operator_enable_requests SET requested_at=clock_timestamp()-INTERVAL '1 hour' WHERE target_id=$1")
        .bind(f.third).execute(&f.db).await?;
    assert_eq!(
        f.call(&f.second_cookie, f.third, "enable").await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.second_cookie, f.third, "enable").await?,
        StatusCode::NO_CONTENT
    );
    Ok(())
}

#[tokio::test]
async fn operator_concurrent_approval_has_one_winner() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.first_cookie, f.second, "enable").await?,
        StatusCode::NO_CONTENT
    );
    session(&f.db, f.second, &f.second_cookie).await?;
    assert_eq!(
        f.call(&f.first_cookie, f.third, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(&f.second_cookie, f.third, "enable").await?,
        StatusCode::NO_CONTENT
    );
    session(&f.db, f.third, &f.third_cookie).await?;
    let fourth = account(&f.db, true).await?;
    assert_eq!(
        f.call(&f.first_cookie, fourth, "request-enable").await?,
        StatusCode::NO_CONTENT
    );
    let (second, third) = tokio::join!(
        f.call(&f.second_cookie, fourth, "enable"),
        f.call(&f.third_cookie, fourth, "enable"),
    );
    let mut statuses = [second?, third?];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::NO_CONTENT, StatusCode::CONFLICT]);
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform_operator_audit_log WHERE target_id=$1 AND action='enable'",
    )
    .bind(fourth)
    .fetch_one(&f.db)
    .await?;
    assert_eq!(approvals, 1);
    Ok(())
}

#[tokio::test]
async fn operator_requires_recent_session_and_rolls_back_on_audit_failure() -> Result<()> {
    let f = Fixture::new().await?;
    sqlx::query(
        "UPDATE user_sessions SET created_at=clock_timestamp()-INTERVAL '2 hours',auth_time=clock_timestamp()-INTERVAL '1 hour' WHERE user_id=$1",
    )
    .bind(f.first)
    .execute(&f.db)
    .await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::UNAUTHORIZED
    );
    session(&f.db, f.first, &Uuid::new_v4().to_string()).await?;
    // The original cookie is still stale even when another full session is fresh.
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE user_sessions SET auth_time=clock_timestamp() WHERE user_id=$1")
        .bind(f.first)
        .execute(&f.db)
        .await?;
    sqlx::query("ALTER TABLE platform_operator_audit_log ADD CONSTRAINT block_fixture_audit CHECK(false) NOT VALID")
        .execute(&f.db).await?;
    assert_eq!(
        f.call(&f.first_cookie, f.second, "request-enable").await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let requests: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform_operator_enable_requests WHERE target_id=$1",
    )
    .bind(f.second)
    .fetch_one(&f.db)
    .await?;
    assert_eq!(requests, 0);
    Ok(())
}
