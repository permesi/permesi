//! Production-router regressions for operator elevation held in PostgreSQL.
//!
//! Every test drives the real routes with a real database and a stub OpenBao. A
//! "replica" is a separate application state on the shared database, which is all two
//! Permesi processes have in common.

use super::*;
use crate::api::handlers::auth::{
    AdminConfig, AdminState,
    admin_elevation::{clock, grant, openbao_deadline},
    authority_guard::{AuthorityGuard, Policy},
    storage,
};
use axum::http::{HeaderMap, header::AUTHORIZATION};
use jiff::SignedDuration;
use jiff_sqlx::ToSqlx;
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

/// Polls `ready` until it holds, so a test acts on an observed state and not on a guess
/// about how long another task needs to reach it.
async fn eventually<F, Fut>(what: &str, mut ready: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    for _ in 0..200 {
        if ready().await? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(anyhow!("timed out waiting until {what}"))
}

/// Whether some backend is blocked on a lock, as the elevation is while a lifecycle
/// change holds the account.
async fn lock_waiter(pool: &PgPool) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                       WHERE datname=current_database() AND wait_event_type='Lock')",
    )
    .fetch_one(pool)
    .await?)
}

/// Whether every attempt the limiter registered for `user` ended as a success.
async fn attempts_succeeded(pool: &PgPool, user: Uuid) -> Result<Option<bool>> {
    Ok(
        sqlx::query_scalar("SELECT bool_and(NOT is_failure) FROM admin_attempts WHERE user_id=$1")
            .bind(user)
            .fetch_one(pool)
            .await?,
    )
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
    // PostgreSQL parses the response itself: the browser is told the stored instant, to
    // the microsecond, and not a rounded one it would act on early.
    let reported = body
        .pointer("/expires_at")
        .and_then(Value::as_str)
        .context("expires_at")?;
    let exact: bool =
        sqlx::query_scalar("SELECT expires_at=$1::timestamptz FROM platform_operator_elevations")
            .bind(reported)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(exact, "{reported} is not the stored expiry");

    assert_eq!(infra(&second, Some(&cookie)).await?, StatusCode::OK);
    assert_eq!(infra(&first, Some(&cookie)).await?, StatusCode::OK);
    let restarted = f.replica(DEFAULT_TTL)?;
    assert_eq!(infra(&restarted, Some(&cookie)).await?, StatusCode::OK);
    // The cookie is the only credential; nothing a caller puts in a header elevates.
    assert_eq!(infra(&second, None).await?, StatusCode::UNAUTHORIZED);
    let (_, plain) = operator(&f.db.pool).await?;
    for (cookie, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(plain.as_str()), StatusCode::FORBIDDEN),
    ] {
        let mut request = Request::builder()
            .uri(INFRA)
            .header(AUTHORIZATION, format!("Bearer {reported}"));
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, format!("permesi_session={cookie}"));
        }
        let (status, _) = send(&second, request.body(Body::empty())?).await?;
        assert_eq!(status, expected, "a bearer header carries no authority");
    }
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
    assert_eq!(attempts_succeeded(pool, operator_id).await?, Some(true));
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

/// A deadline `seconds` from the database's present.
async fn deadline_in(pool: &PgPool, seconds: i64) -> Result<jiff_sqlx::Timestamp> {
    Ok(clock(pool)
        .await?
        .to_jiff()
        .checked_add(SignedDuration::from_secs(seconds))?
        .to_sqlx())
}

/// The statement itself writes nothing for a lifetime that is not positive, for a session
/// of another user, or for a session, account or designation that no longer qualifies.
#[tokio::test]
async fn grant_statement_stands_on_its_own_checks() -> Result<()> {
    let f = Fixture::new().await?;
    let pool = &f.db.pool;
    let (operator_id, cookie) = operator(pool).await?;
    let (other_operator, _) = operator(pool).await?;
    let hash = hash_session_token(&cookie);
    let far = deadline_in(pool, 3600).await?;
    let mut connection = pool.acquire().await?;
    for ttl in [i64::MIN, -1, 0] {
        let refused = grant(&mut connection, operator_id, &hash, ttl, far).await?;
        assert!(refused.is_none(), "lifetime {ttl}");
    }
    let foreign = grant(&mut connection, other_operator, &hash, 60, far).await?;
    assert!(foreign.is_none(), "another user's session");
    assert_eq!(grants(pool).await?, 0);
    assert!(
        grant(&mut connection, operator_id, &hash, 1, far)
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
        let refused = grant(&mut connection, user, &hash, 60, far).await?;
        assert!(refused.is_none(), "{change}");
    }
    assert_eq!(grants(pool).await?, 1);
    Ok(())
}

/// The OpenBao bound is an instant, not a duration added when the row is written: the
/// grant ends exactly at the deadline however late the statement runs, and a deadline
/// that has passed writes nothing. Before, the remaining seconds were added to a later
/// clock reading, so any wait in between extended the elevation past the token.
#[tokio::test]
async fn grant_ends_at_the_deadline_fixed_before_the_openbao_lookup() -> Result<()> {
    let f = Fixture::new().await?;
    let pool = &f.db.pool;
    let (operator_id, cookie) = operator(pool).await?;
    let hash = hash_session_token(&cookie);
    let mut connection = pool.acquire().await?;

    let deadline = deadline_in(pool, 5).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let expires = grant(&mut connection, operator_id, &hash, 3600, deadline)
        .await?
        .context("a live deadline grants")?;
    assert_eq!(expires.to_jiff(), deadline.to_jiff());

    for past in [0, -1, -3600] {
        let deadline = deadline_in(pool, past).await?;
        let refused = grant(&mut connection, operator_id, &hash, 3600, deadline).await?;
        assert!(refused.is_none(), "deadline {past} seconds from now");
    }
    // The refused renewals left the earlier grant and its deadline as they were.
    let stored: jiff_sqlx::Timestamp =
        sqlx::query_scalar("SELECT expires_at FROM platform_operator_elevations")
            .fetch_one(pool)
            .await?;
    assert_eq!(stored.to_jiff(), expires.to_jiff());
    Ok(())
}

/// OpenBao reports whole seconds, rounded, so one second is given up, and a token with
/// a second or less grants nothing. A lifetime far beyond the configured one is capped
/// before any arithmetic.
#[test]
fn openbao_deadline_gives_up_one_second_and_never_overflows() -> Result<()> {
    let anchor: jiff::Timestamp = "2026-01-02T03:04:05.250Z".parse()?;
    let after = |seconds: i64| -> Result<jiff::Timestamp> {
        Ok(anchor.checked_add(SignedDuration::from_secs(seconds))?)
    };
    for ttl in [i64::MIN, -1, 0, 1] {
        assert!(
            openbao_deadline(anchor.to_sqlx(), ttl, DEFAULT_TTL).is_none(),
            "{ttl}"
        );
    }
    for (ttl, configured, expected) in [
        (2, DEFAULT_TTL, 1),
        (120, DEFAULT_TTL, 119),
        (DEFAULT_TTL, DEFAULT_TTL, DEFAULT_TTL - 1),
        (DEFAULT_TTL + 1, DEFAULT_TTL, DEFAULT_TTL),
        (i64::MAX, DEFAULT_TTL, DEFAULT_TTL),
        (i64::MAX, i64::MAX, i64::MAX - 1),
    ] {
        let deadline =
            openbao_deadline(anchor.to_sqlx(), ttl, configured).map(jiff_sqlx::Timestamp::to_jiff);
        // A sum that leaves the calendar grants nothing instead of wrapping.
        assert_eq!(deadline, after(expected).ok(), "{ttl}/{configured}");
    }
    Ok(())
}

/// Time OpenBao takes to answer comes out of the elevation. The stub answers after two
/// seconds for a token with six left, so at most about three remain when the grant is
/// written; anchoring the deadline after the lookup would leave five.
#[tokio::test]
async fn slow_openbao_lookup_shortens_the_elevation() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(6, Duration::from_secs(2)).await;
    let router = f.replica(DEFAULT_TTL)?;
    let (operator_id, cookie) = operator(&f.db.pool).await?;
    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
    let left = remaining_seconds(&f.db.pool, &cookie).await?;
    assert!(left > 1.0 && left <= 3.0, "{left} seconds left");
    assert_eq!(
        attempts_succeeded(&f.db.pool, operator_id).await?,
        Some(true)
    );
    Ok(())
}

/// A step-up after the designation revision changed replaces the unusable grant with a
/// current one, in the same row.
#[tokio::test]
async fn renewed_step_up_replaces_a_grant_from_an_earlier_revision() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let router = f.replica(DEFAULT_TTL)?;
    let pool = &f.db.pool;
    let (operator_id, cookie) = operator(pool).await?;
    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
    let first: (Uuid, jiff_sqlx::Timestamp) =
        sqlx::query_as("SELECT operator_revision,created_at FROM platform_operator_elevations")
            .fetch_one(pool)
            .await?;

    sqlx::query("UPDATE platform_operators SET token_revision=uuidv4() WHERE user_id=$1")
        .bind(operator_id)
        .execute(pool)
        .await?;
    assert_eq!(infra(&router, Some(&cookie)).await?, StatusCode::FORBIDDEN);
    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);
    assert_eq!(infra(&router, Some(&cookie)).await?, StatusCode::OK);

    let second: (Uuid, jiff_sqlx::Timestamp) =
        sqlx::query_as("SELECT operator_revision,created_at FROM platform_operator_elevations")
            .fetch_one(pool)
            .await?;
    assert_ne!(second.0, first.0, "the grant carries the current revision");
    assert!(
        second.1.to_jiff() > first.1.to_jiff(),
        "the grant records when it was renewed"
    );
    assert_eq!(grants(pool).await?, 1);
    Ok(())
}

/// Reauthentication that issues a new session consumes the old one, and the elevation
/// does not follow to the replacement.
#[tokio::test]
async fn replaced_session_does_not_inherit_the_elevation() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
    let router = f.replica(DEFAULT_TTL)?;
    let pool = &f.db.pool;
    let (operator_id, cookie) = operator(pool).await?;
    assert_eq!(elevate(&router, &cookie).await?.0, StatusCode::OK);

    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, format!("permesi_session={cookie}").parse()?);
    let auth = crate::api::AppState::for_tests(pool.clone())?.auth;
    let issued = AuthorityGuard::acquire(pool, &headers, operator_id, Policy::Full, 1000)
        .await
        .map_err(|status| anyhow!("acquire: {status}"))?
        .issue_full(&auth)
        .await
        .map_err(|status| anyhow!("issue: {status}"))?;
    let replacement = issued
        .to_str()?
        .split(';')
        .next()
        .and_then(|pair| pair.strip_prefix("permesi_session="))
        .context("replacement cookie")?
        .to_string();
    assert_ne!(replacement, cookie);

    assert_eq!(
        infra(&router, Some(&cookie)).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        infra(&router, Some(&replacement)).await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(grants(pool).await?, 0);
    Ok(())
}

/// Elevation authenticated the session, waited for OpenBao, then issued without looking
/// at the session again, so a logout during the wait still produced a usable elevation.
#[tokio::test]
async fn session_that_ended_during_the_openbao_call_gets_no_elevation() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::from_millis(500)).await;
    let router = f.replica(DEFAULT_TTL)?;
    let (operator_id, cookie) = operator(&f.db.pool).await?;

    let pending = tokio::spawn({
        let (router, cookie) = (router.clone(), cookie.clone());
        async move { elevate(&router, &cookie).await.map(|(status, _)| status) }
    });
    // Act only once OpenBao has the lookup in hand: the session was valid until then.
    eventually("OpenBao received the lookup", || async {
        let received = f.openbao.received_requests().await.unwrap_or_default();
        Ok(!received.is_empty())
    })
    .await?;
    assert!(!pending.is_finished(), "the request is waiting on OpenBao");
    assert_eq!(logout(&router, &cookie).await?, StatusCode::NO_CONTENT);

    assert_eq!(pending.await??, StatusCode::UNAUTHORIZED);
    assert_eq!(grants(&f.db.pool).await?, 0);
    assert_eq!(
        attempts_succeeded(&f.db.pool, operator_id).await?,
        Some(false),
        "an elevation that was not recorded is not counted as a success"
    );
    Ok(())
}

/// Starts an elevation while a transaction holds the account's lifecycle lock, waits
/// until the elevation is blocked on it, runs `change` there and commits, and returns
/// the elevation's status. Without a change the lock is held until the elevation gives up.
async fn elevate_against(f: &Fixture, change: Option<&'static str>) -> Result<StatusCode> {
    let router = f.replica(DEFAULT_TTL)?;
    let (operator_id, cookie) = operator(&f.db.pool).await?;
    let mut lifecycle = f.db.pool.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id=$1 FOR NO KEY UPDATE")
        .bind(operator_id)
        .execute(&mut *lifecycle)
        .await?;
    let pending = tokio::spawn(async move { elevate(&router, &cookie).await.map(|(s, _)| s) });
    eventually("the elevation waits for the account lock", || {
        lock_waiter(&f.db.pool)
    })
    .await?;
    let Some(change) = change else {
        let status = pending.await??;
        lifecycle.rollback().await?;
        return Ok(status);
    };
    assert!(!pending.is_finished(), "the elevation waits for the lock");
    let changed = sqlx::query(change)
        .bind(operator_id)
        .execute(&mut *lifecycle)
        .await?;
    assert_eq!(changed.rows_affected(), 1, "{change}");
    lifecycle.commit().await?;
    pending.await?
}

/// The grant is written under the lock every lifecycle change takes first, so a change
/// that got there earlier decides the outcome, and a lock that is not released in time
/// refuses the elevation instead of letting it through. The limiter's reservation is
/// marked successful in the same transaction: without it there is no grant either.
#[tokio::test]
async fn elevation_waits_for_a_lifecycle_change_and_honours_its_outcome() -> Result<()> {
    let f = Fixture::new().await?;
    f.openbao_token(3600, Duration::ZERO).await;
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
        (
            "DELETE FROM admin_attempts WHERE user_id=$1",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        assert_eq!(
            elevate_against(&f, Some(change)).await?,
            expected,
            "{change}"
        );
    }
    // Held past the one-second database deadline of the test configuration.
    assert_eq!(
        elevate_against(&f, None).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(grants(&f.db.pool).await?, 0);
    Ok(())
}

/// When the elevation cannot be looked up the read is refused; a storage failure is
/// never read as "elevated".
#[tokio::test]
async fn status_read_is_refused_when_the_elevation_cannot_be_looked_up() -> Result<()> {
    let unreachable = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy("postgres://invalid@127.0.0.1:1/invalid?sslmode=disable")?;
    let openbao = MockServer::start().await;
    let router = replica(&unreachable, &openbao, DEFAULT_TTL)?;
    let cookie = generate_session_token()?;
    assert_eq!(
        infra(&router, Some(&cookie)).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
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
