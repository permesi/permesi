//! Production-router regressions for operator elevation held in PostgreSQL.
//!
//! Every test drives the real routes with a real database and a stub OpenBao. A
//! "replica" is a separate application state on the shared database, which is all two
//! Permesi processes have in common.

use super::*;
use crate::api::handlers::auth::{AdminConfig, AdminState, storage};
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ELEVATE: &str = "/v1/auth/admin/elevate";
const INFRA: &str = "/v1/auth/admin/infra";
const DEFAULT_TTL: i64 = 43_200;

struct Fixture {
    db: TestDb,
    openbao: MockServer,
}

impl Fixture {
    /// A skipped database would leave every security assertion below unexercised.
    async fn new() -> Result<Self> {
        let db = TestDb::new()
            .await?
            .context("Elevation regressions require PostgreSQL; a skip is not coverage")?;
        Ok(Self {
            db,
            openbao: MockServer::start().await,
        })
    }

    /// Makes OpenBao report an operator token with `ttl` seconds left, after `delay`.
    async fn openbao_token(&self, ttl: i64, delay: Duration) {
        stub_openbao(&self.openbao, ttl, delay).await;
    }

    fn replica(&self, ttl: i64) -> Result<Router> {
        replica(&self.db.pool, &self.openbao, ttl)
    }
}

async fn stub_openbao(openbao: &MockServer, ttl: i64, delay: Duration) {
    openbao.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(json!({"data":{"policies":["permesi-operators"],"ttl":ttl}})),
        )
        .mount(openbao)
        .await;
}

/// The production router over its own state: nothing is shared with another replica
/// except the database and OpenBao.
fn replica(pool: &PgPool, openbao: &MockServer, ttl: i64) -> Result<Router> {
    let transport = openbao_client::OpenBaoTransport::from_target(
        crate::APP_USER_AGENT,
        openbao_client::OpenBaoTarget::Tcp {
            base_url: openbao.uri(),
        },
    )?;
    let mut state = crate::api::AppState::for_tests(pool.clone())?;
    state.admin = Arc::new(AdminState::new(
        AdminConfig::new(openbao.uri()).with_admin_ttl_seconds(ttl),
        pool.clone(),
        transport,
    )?);
    Ok(crate::api::with_response_policy(
        crate::api::router().split_for_parts().0.with_state(state),
    ))
}

async fn user(pool: &PgPool) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        "INSERT INTO users(email,opaque_registration_record,status) VALUES($1,$2,'active') RETURNING id",
    )
    .bind(format!("{}@elevation.test", Uuid::new_v4()))
    .bind(vec![1_u8; 16])
    .fetch_one(pool)
    .await?)
}

/// An enabled operator and the cookie of one full session.
async fn operator(pool: &PgPool) -> Result<(Uuid, String)> {
    let user = user(pool).await?;
    sqlx::query("INSERT INTO platform_operators(user_id) VALUES($1)")
        .bind(user)
        .execute(pool)
        .await?;
    Ok((user, storage::insert_session(pool, user, 3600).await?))
}

async fn send(router: &Router, request: Request<Body>) -> Result<(StatusCode, Value)> {
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "operator responses must not be cached ({status})"
    );
    let body = to_bytes(response.into_body(), 64 * 1024).await?;
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

async fn elevate(router: &Router, cookie: &str) -> Result<(StatusCode, Value)> {
    send(
        router,
        Request::builder()
            .method("POST")
            .uri(ELEVATE)
            .header(COOKIE, format!("permesi_session={cookie}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"openbao_token":"s.operator"}).to_string(),
            ))?,
    )
    .await
}

async fn infra(router: &Router, cookie: Option<&str>) -> Result<StatusCode> {
    let mut request = Request::builder().uri(INFRA);
    if let Some(cookie) = cookie {
        request = request.header(COOKIE, format!("permesi_session={cookie}"));
    }
    Ok(send(router, request.body(Body::empty())?).await?.0)
}

async fn logout(router: &Router, cookie: &str) -> Result<StatusCode> {
    Ok(router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header(COOKIE, format!("permesi_session={cookie}"))
                .body(Body::empty())?,
        )
        .await?
        .status())
}

async fn grants(pool: &PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM platform_operator_elevations")
            .fetch_one(pool)
            .await?,
    )
}

/// The defect that made the status page unusable behind two replicas: the elevation was
/// a token signed with a key only the issuing process had. It is now a row every
/// replica reads, so it also survives a restart of the replica that recorded it.
#[tokio::test]
async fn elevation_recorded_by_one_replica_authorizes_the_status_route_on_another() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let (first, second) = (f.replica(DEFAULT_TTL)?, f.replica(DEFAULT_TTL)?);
    let (_, cookie) = operator(&f.db.pool).await?;

    assert_eq!(infra(&first, None).await?, StatusCode::UNAUTHORIZED);
    assert_eq!(infra(&second, Some(&cookie)).await?, StatusCode::FORBIDDEN);

    let (status, body) = elevate(&first, &cookie).await?;
    assert_eq!(status, StatusCode::OK);
    let fields = body.as_object().context("elevation response")?;
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["expires_at"],
        "the response carries no credential"
    );
    let stored: String = sqlx::query_scalar(
        r#"SELECT to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')
           FROM platform_operator_elevations"#,
    )
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(body.pointer("/expires_at"), Some(&Value::String(stored)));

    assert_eq!(infra(&second, Some(&cookie)).await?, StatusCode::OK);
    assert_eq!(infra(&first, Some(&cookie)).await?, StatusCode::OK);
    let restarted = f.replica(DEFAULT_TTL)?;
    assert_eq!(infra(&restarted, Some(&cookie)).await?, StatusCode::OK);
    // The cookie is the only credential; nothing a caller puts in a header elevates.
    assert_eq!(infra(&second, None).await?, StatusCode::UNAUTHORIZED);
    Ok(())
}

/// The elevation used to be a bearer token that kept working after logout. It now
/// belongs to the session that stepped up and to no other, and ends with it.
#[tokio::test]
async fn elevation_belongs_to_one_session_and_ends_at_logout() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let router = f.replica(DEFAULT_TTL)?;
    let pool = &f.db.pool;
    let (operator_id, elevated) = operator(pool).await?;
    let same_user = storage::insert_session(pool, operator_id, 3600).await?;
    let (_, other_operator) = operator(pool).await?;
    let ordinary = storage::insert_session(pool, user(pool).await?, 3600).await?;

    assert_eq!(elevate(&router, &ordinary).await?.0, StatusCode::FORBIDDEN);
    assert_eq!(elevate(&router, &elevated).await?.0, StatusCode::OK);
    assert_eq!(grants(pool).await?, 1);
    assert_eq!(infra(&router, Some(&elevated)).await?, StatusCode::OK);
    for (cookie, expected) in [
        (same_user.clone(), StatusCode::FORBIDDEN),
        (other_operator, StatusCode::FORBIDDEN),
        (ordinary, StatusCode::FORBIDDEN),
        // A limited-session prefix on the elevated cookie is not a full session.
        (format!("mfa_setup_{elevated}"), StatusCode::UNAUTHORIZED),
        (
            format!("mfa_challenge_{elevated}"),
            StatusCode::UNAUTHORIZED,
        ),
        ("unknown".to_string(), StatusCode::UNAUTHORIZED),
    ] {
        assert_eq!(infra(&router, Some(&cookie)).await?, expected, "{cookie}");
    }

    assert_eq!(logout(&router, &elevated).await?, StatusCode::NO_CONTENT);
    assert_eq!(
        infra(&router, Some(&elevated)).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        grants(pool).await?,
        0,
        "the grant is deleted with its session"
    );
    // The user's other session, and a later login, start without elevation.
    assert_eq!(
        infra(&router, Some(&same_user)).await?,
        StatusCode::FORBIDDEN
    );
    let later = storage::insert_session(pool, operator_id, 3600).await?;
    assert_eq!(infra(&router, Some(&later)).await?, StatusCode::FORBIDDEN);
    Ok(())
}

/// A password change revokes every session of the account, and the elevation with them.
#[tokio::test]
async fn password_rotation_ends_the_elevation() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let router = f.replica(DEFAULT_TTL)?;
    let pool = &f.db.pool;
    let (operator_id, cookie) = operator(pool).await?;
    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
    assert_eq!(infra(&router, Some(&cookie)).await?, StatusCode::OK);

    assert!(storage::rotate_password_and_clear_sessions(pool, operator_id, &[2_u8; 16]).await?);

    assert_eq!(
        infra(&router, Some(&cookie)).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(grants(pool).await?, 0);
    let after_login = storage::insert_session(pool, operator_id, 3600).await?;
    assert_eq!(
        infra(&router, Some(&after_login)).await?,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

/// A grant that survives in the table is still refused once the designation, the
/// account, the session or the grant's own lifetime no longer supports it.
#[tokio::test]
async fn elevation_stops_with_the_designation_the_account_or_its_lifetime() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let router = f.replica(DEFAULT_TTL)?;
    let pool = &f.db.pool;
    for (change, expected) in [
        (
            "UPDATE platform_operators SET token_revision=uuidv4() WHERE user_id=$1",
            StatusCode::FORBIDDEN,
        ),
        (
            "UPDATE platform_operators SET enabled=FALSE WHERE user_id=$1",
            StatusCode::FORBIDDEN,
        ),
        (
            "DELETE FROM platform_operators WHERE user_id=$1",
            StatusCode::FORBIDDEN,
        ),
        (
            "UPDATE platform_operator_elevations e
             SET created_at=NOW()-INTERVAL '2 hours',
                 expires_at=NOW()-INTERVAL '1 millisecond'
             FROM user_sessions s WHERE s.id=e.session_id AND s.user_id=$1",
            StatusCode::FORBIDDEN,
        ),
        (
            "UPDATE users SET status='disabled' WHERE id=$1",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "UPDATE user_sessions
             SET created_at=NOW()-INTERVAL '2 hours',
                 auth_time=NOW()-INTERVAL '2 hours',
                 expires_at=NOW()-INTERVAL '1 millisecond'
             WHERE user_id=$1",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (operator_id, cookie) = operator(pool).await?;
        assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
        assert_eq!(infra(&router, Some(&cookie)).await?, StatusCode::OK);
        let changed = sqlx::query(change).bind(operator_id).execute(pool).await?;
        assert_eq!(changed.rows_affected(), 1, "{change}");
        assert_eq!(infra(&router, Some(&cookie)).await?, expected, "{change}");
    }
    Ok(())
}

/// Seconds left on the only grant of `cookie`'s session.
async fn remaining_seconds(pool: &PgPool, cookie: &str) -> Result<f64> {
    Ok(sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM e.expires_at-clock_timestamp())::float8
         FROM platform_operator_elevations e JOIN user_sessions s ON s.id=e.session_id
         WHERE s.session_hash=$1",
    )
    .bind(hash_session_token(cookie))
    .fetch_one(pool)
    .await?)
}

/// The grant lasts no longer than the configured lifetime, the OpenBao token that
/// earned it or the session that holds it; a repeated step-up replaces it.
#[tokio::test]
async fn elevation_lifetime_is_the_smallest_of_configuration_openbao_and_session() -> Result<()> {
    let f = Fixture::new().await?;
    let pool = &f.db.pool;
    for (configured, openbao, session, bound) in [
        (DEFAULT_TTL, 120, 3600, 120.0),
        (60, 3600, 3600, 60.0),
        (DEFAULT_TTL, 3600, 30, 30.0),
    ] {
        f.openbao_token(openbao, Duration::ZERO).await;
        let router = f.replica(configured)?;
        let (_, cookie) = operator(pool).await?;
        sqlx::query(
            "UPDATE user_sessions SET expires_at=clock_timestamp()+$2::bigint*INTERVAL '1 second'
             WHERE session_hash=$1",
        )
        .bind(hash_session_token(&cookie))
        .bind(session)
        .execute(pool)
        .await?;
        assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
        let left = remaining_seconds(pool, &cookie).await?;
        assert!(
            left <= bound && left > bound - 10.0,
            "{configured}/{openbao}/{session}: {left} seconds left"
        );
    }

    // A second step-up on the same session leaves one row, with the newer lifetime.
    f.openbao_token(3600, Duration::ZERO).await;
    let (_, cookie) = operator(pool).await?;
    assert_eq!(elevate(&f.replica(600)?, &cookie).await?.0, StatusCode::OK);
    assert_eq!(elevate(&f.replica(60)?, &cookie).await?.0, StatusCode::OK);
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM platform_operator_elevations e JOIN user_sessions s ON s.id=e.session_id
         WHERE s.session_hash=$1",
    )
    .bind(hash_session_token(&cookie))
    .fetch_one(pool)
    .await?;
    assert_eq!(rows, 1);
    assert!(remaining_seconds(pool, &cookie).await? <= 60.0);
    Ok(())
}

/// An OpenBao token with no time left used to produce a `500`; it is now refused, and
/// nothing is recorded. The second it takes to ask is charged against the token.
#[tokio::test]
async fn openbao_token_without_remaining_lifetime_grants_nothing() -> Result<()> {
    let f = Fixture::new().await?;
    let router = f.replica(DEFAULT_TTL)?;
    for ttl in [-5, 0, 1] {
        f.openbao_token(ttl, Duration::ZERO).await;
        let (_, cookie) = operator(&f.db.pool).await?;
        assert_eq!(
            elevate(&router, &cookie).await?.0,
            StatusCode::FORBIDDEN,
            "ttl {ttl}"
        );
        assert_eq!(infra(&router, Some(&cookie)).await?, StatusCode::FORBIDDEN);
    }
    assert_eq!(grants(&f.db.pool).await?, 0);
    Ok(())
}

/// The statement itself writes nothing for a lifetime that is not positive, for a session
/// of another user, or for a session, account or designation that no longer qualifies.
#[tokio::test]
async fn grant_statement_stands_on_its_own_checks() -> Result<()> {
    use crate::api::handlers::auth::admin_elevation::grant;

    let f = Fixture::new().await?;
    let pool = &f.db.pool;
    let (operator_id, cookie) = operator(pool).await?;
    let (other_operator, _) = operator(pool).await?;
    let hash = hash_session_token(&cookie);
    let mut connection = pool.acquire().await?;
    for ttl in [i64::MIN, -1, 0] {
        assert_eq!(grant(&mut connection, operator_id, &hash, ttl).await?, None);
    }
    assert_eq!(
        grant(&mut connection, other_operator, &hash, 60).await?,
        None
    );
    assert_eq!(grants(pool).await?, 0);
    assert!(
        grant(&mut connection, operator_id, &hash, 1)
            .await?
            .is_some()
    );
    assert_eq!(grants(pool).await?, 1);

    // The statement does not depend on what its caller checked: an expired session, a
    // suspended account and a disabled designation each write nothing.
    for change in [
        "UPDATE user_sessions
         SET created_at=NOW()-INTERVAL '2 hours',
             auth_time=NOW()-INTERVAL '2 hours',
             expires_at=NOW()-INTERVAL '1 millisecond'
         WHERE user_id=$1",
        "UPDATE users SET status='disabled' WHERE id=$1",
        "UPDATE platform_operators SET enabled=FALSE WHERE user_id=$1",
    ] {
        let (user, cookie) = operator(pool).await?;
        let changed = sqlx::query(change).bind(user).execute(pool).await?;
        assert_eq!(changed.rows_affected(), 1, "{change}");
        let hash = hash_session_token(&cookie);
        assert_eq!(
            grant(&mut connection, user, &hash, 60).await?,
            None,
            "{change}"
        );
    }
    assert_eq!(grants(pool).await?, 1);
    Ok(())
}

/// Elevation authenticated the session, waited for OpenBao, then issued without looking
/// at the session again, so a logout during the wait still produced a usable elevation.
#[tokio::test]
async fn session_that_ended_during_the_openbao_call_gets_no_elevation() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::from_millis(600)).await;
    let router = f.replica(DEFAULT_TTL)?;
    let (_, cookie) = operator(&f.db.pool).await?;

    let pending = tokio::spawn({
        let (router, cookie) = (router.clone(), cookie.clone());
        async move { elevate(&router, &cookie).await.map(|(status, _)| status) }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!pending.is_finished(), "the request is waiting on OpenBao");
    assert_eq!(logout(&router, &cookie).await?, StatusCode::NO_CONTENT);

    assert_eq!(pending.await??, StatusCode::UNAUTHORIZED);
    assert_eq!(grants(&f.db.pool).await?, 0);
    Ok(())
}

/// Starts an elevation while `change` runs in a transaction that already holds the
/// account's lifecycle lock, and returns the elevation's status after it commits.
async fn elevate_against(
    f: &Fixture,
    change: Option<&'static str>,
    hold: Duration,
) -> Result<StatusCode> {
    let router = f.replica(DEFAULT_TTL)?;
    let (operator_id, cookie) = operator(&f.db.pool).await?;
    let mut lifecycle = f.db.pool.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id=$1 FOR NO KEY UPDATE")
        .bind(operator_id)
        .execute(&mut *lifecycle)
        .await?;
    let pending = tokio::spawn(async move { elevate(&router, &cookie).await.map(|(s, _)| s) });
    tokio::time::sleep(hold).await;
    if let Some(change) = change {
        assert!(!pending.is_finished(), "the elevation waits for the lock");
        sqlx::query(change)
            .bind(operator_id)
            .execute(&mut *lifecycle)
            .await?;
        lifecycle.commit().await?;
        return pending.await?;
    }
    let status = pending.await??;
    lifecycle.rollback().await?;
    Ok(status)
}

/// The grant is written under the lock every lifecycle change takes first, so a change
/// that got there earlier decides the outcome, and a lock that is not released in time
/// refuses the elevation instead of letting it through.
#[tokio::test]
async fn elevation_waits_for_a_lifecycle_change_and_honours_its_outcome() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let short = Duration::from_millis(250);
    for (change, expected) in [
        (
            "DELETE FROM user_sessions WHERE user_id=$1",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "UPDATE users SET status='disabled' WHERE id=$1",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "UPDATE platform_operators SET enabled=FALSE,token_revision=uuidv4() WHERE user_id=$1",
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            elevate_against(&f, Some(change), short).await?,
            expected,
            "{change}"
        );
    }
    // Held past the one-second database deadline of the test configuration.
    assert_eq!(
        elevate_against(&f, None, Duration::from_millis(1500)).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(grants(&f.db.pool).await?, 0);
    Ok(())
}

/// The tests above connect as the database owner. The service does not: it holds only
/// the grants of `permesi_runtime`, which must be enough to record and replace a grant
/// and to lose it through the session cascade, and not enough to move or delete one.
#[tokio::test]
async fn runtime_role_can_record_and_replace_a_grant_but_not_move_or_delete_one() -> Result<()> {
    runtime::ensure_container_runtime()
        .context("Elevation privileges require PostgreSQL; a skip is not coverage")?;
    let postgres = PostgresContainer::start("bridge").await?;
    postgres.wait_until_ready().await?;
    postgres.bootstrap().await?;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect(&postgres.admin_dsn_for_db("permesi"))
        .await?;
    let name = format!("elevation_test_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {name} LOGIN PASSWORD '{password}'; GRANT permesi_runtime TO {name};"
    )))
    .execute(&owner)
    .await?;
    let service = PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!(
            "postgres://{name}:{password}@127.0.0.1:{}/permesi?sslmode=disable",
            postgres.host_port()
        ))
        .await?;
    let openbao = MockServer::start().await;
    stub_openbao(&openbao, 3600, Duration::ZERO).await;
    let router = replica(&service, &openbao, DEFAULT_TTL)?;
    let (_, cookie) = operator(&owner).await?;
    let (_, kept) = operator(&owner).await?;

    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
    assert_eq!(elevate(&router, &kept).await?.0, StatusCode::OK);
    assert_eq!(infra(&router, Some(&cookie)).await?, StatusCode::OK);
    assert_eq!(grants(&owner).await?, 2);

    for forbidden in [
        "DELETE FROM platform_operator_elevations",
        "UPDATE platform_operator_elevations SET session_id=session_id",
    ] {
        let refused = sqlx::query(forbidden).execute(&service).await;
        let code = refused
            .err()
            .and_then(|error| error.as_database_error()?.code().map(|c| c.to_string()));
        assert_eq!(code.as_deref(), Some("42501"), "{forbidden}");
    }

    assert_eq!(logout(&router, &cookie).await?, StatusCode::NO_CONTENT);
    assert_eq!(
        infra(&router, Some(&cookie)).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        grants(&owner).await?,
        1,
        "only the other session's grant remains"
    );
    assert_eq!(infra(&router, Some(&kept)).await?, StatusCode::OK);
    Ok(())
}
