//! Real PostgreSQL/production-router tests for authorization, consent and transactional
//! redemption. Independent pools model replicas; concurrent committed transactions
//! test replay resistance. Fixtures are isolated and schema errors fail the suite.

#![allow(clippy::too_many_lines, clippy::indexing_slicing)]

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
    },
};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use test_support::{postgres::PostgresContainer, runtime};
use tokio::time::{Duration, sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

use super::*;
use crate::{
    api::AppState,
    oauth::authorization::redemption::{RedeemedCode, RedemptionInput, redeem_authorization_code},
};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
mod lifecycle;
mod token;
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://client.test/callback?existing=%2f";
const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/02_permesi.sql"
));

/// Legacy registrations with reserved query keys fail directly, never through an ambiguous redirect.
#[tokio::test]
async fn authorize_review_regression_reserved_callback_parameters_never_redirect() -> Result<()> {
    let fixture = Fixture::new().await?;
    for query in [
        "iss=https%3A%2F%2Fevil.test",
        "%69ss=attacker",
        "code=attacker",
        "state=attacker",
        "error=attacker",
    ] {
        let redirect = format!("https://client.test/callback?{query}");
        sqlx::query(
            "INSERT INTO oauth_client_redirect_uris (client_id,redirect_uri) VALUES ($1,$2)",
        )
        .bind(fixture.client_internal)
        .bind(&redirect)
        .execute(&fixture.pool)
        .await?;
        let reply = fixture
            .start(&[
                ("redirect_uri", Some(redirect)),
                ("response_type", Some("token".into())),
            ])
            .await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(reply.location.is_none());
    }
    let normal = fixture
        .start(&[("response_type", Some("token".into()))])
        .await?;
    assert_eq!(normal.status, StatusCode::SEE_OTHER);
    let redirect = url::Url::parse(
        normal
            .location
            .as_deref()
            .context("trusted error redirect")?,
    )?;
    assert_eq!(
        redirect
            .query_pairs()
            .filter(|(key, _)| key == "iss")
            .count(),
        1
    );
    Ok(())
}

struct Fixture {
    postgres: PostgresContainer,
    pool: PgPool,
    state: AppState,
    router: Router,
    user: Uuid,
    token: String,
    browser: SecretValue,
    client: Uuid,
    client_internal: Uuid,
    application: Uuid,
    organization: Uuid,
    project: Uuid,
    environment: Uuid,
}

struct Reply {
    status: StatusCode,
    location: Option<String>,
    body: String,
    cookie: Option<String>,
    headers: HeaderMap,
}

impl Fixture {
    /// Creates independent real storage and exercises the production `OpenAPI` router.
    async fn new() -> Result<Self> {
        runtime::ensure_container_runtime()?;
        let postgres = PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        let mut conn = PgConnection::connect(&postgres.admin_dsn()).await?;
        test_support::sql::execute_script(&mut conn, "schema", SCHEMA).await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&postgres.admin_dsn())
            .await?;
        let user: Uuid = sqlx::query_scalar("INSERT INTO users (email,opaque_registration_record,status) VALUES ('owner@authorization.test',$1,'active') RETURNING id").bind(vec![0u8;16]).fetch_one(&pool).await?;
        let organization: Uuid = sqlx::query_scalar("INSERT INTO organizations (slug,name,created_by) VALUES ('authorize-org','Authorization tenant',$1) RETURNING id").bind(user).fetch_one(&pool).await?;
        sqlx::query("INSERT INTO org_memberships (org_id,user_id,status) VALUES ($1,$2,'active')")
            .bind(organization)
            .bind(user)
            .execute(&pool)
            .await?;
        let project = sqlx::query_scalar(
            "INSERT INTO projects (org_id,slug,name) VALUES ($1,'project','Project') RETURNING id",
        )
        .bind(organization)
        .fetch_one(&pool)
        .await?;
        let environment = sqlx::query_scalar("INSERT INTO environments (project_id,slug,name) VALUES ($1,'test','Test') RETURNING id").bind(project).fetch_one(&pool).await?;
        let application = sqlx::query_scalar("INSERT INTO applications (environment_id,name) VALUES ($1,'Jobs application') RETURNING id").bind(environment).fetch_one(&pool).await?;
        let client = Uuid::new_v4();
        let client_internal: Uuid = sqlx::query_scalar("INSERT INTO oauth_clients (application_id,client_id,name,client_type) VALUES ($1,$2,'Web client','public') RETURNING id").bind(application).bind(client).fetch_one(&pool).await?;
        sqlx::query(
            "INSERT INTO oauth_client_redirect_uris (client_id,redirect_uri) VALUES ($1,$2)",
        )
        .bind(client_internal)
        .bind(REDIRECT)
        .execute(&pool)
        .await?;
        for (name, description) in [
            ("jobs:read", "Read jobs"),
            ("jobs:write", "Write jobs"),
            ("runs:read", "Read execution history"),
        ] {
            sqlx::query("INSERT INTO oauth_scopes (application_id,name,description,kind) VALUES ($1,$2,$3,'application')").bind(application).bind(name).bind(description).execute(&pool).await?;
        }
        sqlx::query("INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2").bind(client_internal).bind(application).execute(&pool).await?;
        let token = super::super::auth::generate_session_token()?;
        sqlx::query("INSERT INTO user_sessions (user_id,session_hash,expires_at) VALUES ($1,$2,clock_timestamp()+INTERVAL '1 hour')").bind(user).bind(hash_session_token(&token)).execute(&pool).await?;
        let mut state = AppState::for_tests(pool.clone())?;
        let mut oauth = (*state.oauth).clone();
        oauth.config.issuer = Some("https://issuer.test".into());
        oauth.config.audience = Some("jobs-api".into());
        state.oauth = Arc::new(oauth);
        let router = crate::api::router()
            .split_for_parts()
            .0
            .with_state(state.clone());
        Ok(Self {
            postgres,
            pool,
            state,
            router,
            user,
            token,
            browser: SecretValue::generate()?,
            client,
            client_internal,
            application,
            organization,
            project,
            environment,
        })
    }

    /// Builds decoded parameter overrides while preserving exact state/redirect values.
    fn url(&self, overrides: &[(&str, Option<String>)]) -> String {
        let mut params = vec![
            ("client_id", self.client.to_string()),
            ("redirect_uri", REDIRECT.into()),
            ("response_type", "code".into()),
            ("scope", "jobs:read runs:read".into()),
            ("state", "opaque + / & = % ü".into()),
            ("code_challenge", CHALLENGE.into()),
            ("code_challenge_method", "S256".into()),
        ];
        for (key, value) in overrides {
            params.retain(|(name, _)| name != key);
            if let Some(value) = value {
                params.push((key, value.clone()));
            }
        }
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.extend_pairs(params);
        format!("/authorize?{}", query.finish())
    }

    /// Exercises a routed request with optional full-session/browser credentials.
    async fn call(
        &self,
        router: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        browser: Option<&SecretValue>,
        form: Option<&str>,
    ) -> Result<Reply> {
        let mut cookies = Vec::new();
        if let Some(token) = token {
            cookies.push(format!("permesi_session={token}"));
        }
        if let Some(browser) = browser {
            cookies.push(format!("{BROWSER_COOKIE}={}", browser.expose()));
        }
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(COOKIE, cookies.join("; "));
        if form.is_some() {
            builder = builder
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("origin", "https://issuer.test");
        }
        let response = router
            .clone()
            .oneshot(builder.body(Body::from(form.unwrap_or_default().to_owned()))?)
            .await?;
        let headers = response.headers().clone();
        let status = response.status();
        let location = headers
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let cookie = headers
            .get(SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
        Ok(Reply {
            status,
            location,
            body,
            cookie,
            headers,
        })
    }

    /// Starts an authenticated request whose authority has never been preconsented.
    async fn start(&self, overrides: &[(&str, Option<String>)]) -> Result<Reply> {
        self.call(
            &self.router,
            "GET",
            &self.url(overrides),
            Some(&self.token),
            Some(&self.browser),
            None,
        )
        .await
    }

    /// Submits only the backend's opaque request/CSRF fields and an explicit decision.
    async fn decide(&self, page: &Reply, decision: &str, extra: &str) -> Result<Reply> {
        let form = format!(
            "request_id={}&csrf={}&decision={decision}{extra}",
            hidden(&page.body, "request_id")?,
            hidden(&page.body, "csrf")?
        );
        self.call(
            &self.router,
            "POST",
            "/authorize/consent",
            Some(&self.token),
            Some(&self.browser),
            Some(&form),
        )
        .await
    }

    /// Obtains one code through real validation and explicit consent.
    async fn issue(&self) -> Result<String> {
        let reply = self.start(&[]).await?;
        let reply = if reply.status == StatusCode::OK {
            self.decide(&reply, "allow", "").await?
        } else {
            reply
        };
        ensure!(
            reply.status == StatusCode::SEE_OTHER,
            "issuance status: {}",
            reply.status
        );
        parameter(
            reply.location.as_deref().context("missing redirect")?,
            "code",
        )
    }

    /// Models a separate token-service transaction; commits only successful redemptions.
    async fn redeem(
        &self,
        pool: &PgPool,
        code: &str,
        client: Uuid,
        redirect: &str,
        verifier: &str,
        org: Uuid,
    ) -> Result<Option<RedeemedCode>> {
        let mut tx = pool.begin().await?;
        if let Ok(code) = redeem_authorization_code(
            &mut tx,
            &self.state.oauth.config,
            RedemptionInput {
                code,
                client_id: client,
                redirect_uri: redirect,
                code_verifier: verifier,
                organization_id: org,
            },
        )
        .await
        {
            tx.commit().await?;
            Ok(Some(code))
        } else {
            tx.rollback().await?;
            Ok(None)
        }
    }

    /// Changes a bounded test policy and rebuilds the router without any process-local state.
    fn ttl(&mut self, code_ttl: i64, request_ttl: i64) {
        let mut oauth = (*self.state.oauth).clone();
        oauth.config.code_ttl = code_ttl;
        oauth.config.request_ttl = request_ttl;
        self.state.oauth = Arc::new(oauth);
        self.router = crate::api::router()
            .split_for_parts()
            .0
            .with_state(self.state.clone());
    }
}

/// Reads an escaped opaque hidden capability from the server's minimal consent form.
fn hidden<'a>(html: &'a str, name: &str) -> Result<&'a str> {
    html.split_once(&format!("name=\"{name}\" value=\""))
        .and_then(|(_, s)| s.split_once('"'))
        .map(|(v, _)| v)
        .context("missing consent capability")
}
/// Decodes an exact returned protocol value for round-trip assertions.
fn parameter(location: &str, name: &str) -> Result<String> {
    url::Url::parse(location)?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .context("missing protocol parameter")
}
/// Checks failures never establish an untrusted redirect.
fn direct_rejection(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.location.is_none());
}
/// Checks a trusted protocol error without depending on implementation detail messages.
fn protocol_error(reply: &Reply, error: &str) -> Result<()> {
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        parameter(reply.location.as_deref().context("redirect")?, "error")?,
        error
    );
    Ok(())
}

#[tokio::test]
async fn authorize_rejects_unknown_disabled_deleted_clients_and_inactive_ancestors() -> Result<()> {
    let f = Fixture::new().await?;
    direct_rejection(
        &f.start(&[("client_id", Some(Uuid::new_v4().to_string()))])
            .await?,
    );
    for value in [None, Some("invalid".into())] {
        direct_rejection(&f.start(&[("client_id", value)]).await?);
    }
    let mut tx = f.pool.begin().await?;
    sqlx::query("UPDATE oauth_clients SET disabled_at=clock_timestamp() WHERE id=$1")
        .bind(f.client_internal)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    direct_rejection(&f.start(&[]).await?);
    sqlx::query("UPDATE oauth_clients SET deleted_at=clock_timestamp() WHERE id=$1")
        .bind(f.client_internal)
        .execute(&f.pool)
        .await?;
    direct_rejection(&f.start(&[]).await?);
    sqlx::query("UPDATE oauth_clients SET deleted_at=NULL,disabled_at=NULL WHERE id=$1")
        .bind(f.client_internal)
        .execute(&f.pool)
        .await?;
    for (update, restore, id) in [
        (
            "UPDATE applications SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE applications SET deleted_at=NULL WHERE id=$1",
            f.application,
        ),
        (
            "UPDATE environments SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE environments SET deleted_at=NULL WHERE id=$1",
            f.environment,
        ),
        (
            "UPDATE projects SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE projects SET deleted_at=NULL WHERE id=$1",
            f.project,
        ),
        (
            "UPDATE organizations SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE organizations SET deleted_at=NULL WHERE id=$1",
            f.organization,
        ),
    ] {
        sqlx::query(update).bind(id).execute(&f.pool).await?;
        direct_rejection(&f.start(&[]).await?);
        sqlx::query(restore).bind(id).execute(&f.pool).await?;
    }
    assert_eq!(f.start(&[]).await?.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn authorize_redirects_match_exactly_and_untrusted_errors_never_redirect() -> Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(f.start(&[]).await?.status, StatusCode::OK);
    for redirect in [
        "https://client.test/callback",
        "https://client.test/callback?existing=%2F",
        "https://client.test/callback?existing=%2f&extra=1",
        "https://client.test/callback.evil",
        "https://client.test.evil/callback",
        "https://client.test/*",
        "https://client.test/callback#x",
        "https://user@client.test/callback",
        "http://client.test/callback",
    ] {
        direct_rejection(
            &f.start(&[
                ("redirect_uri", Some(redirect.into())),
                ("response_type", Some("token".into())),
            ])
            .await?,
        );
    }
    direct_rejection(&f.start(&[("redirect_uri", None)]).await?);
    let bad = f.start(&[("response_type", Some("token".into()))]).await?;
    protocol_error(&bad, "unsupported_response_type")?;
    assert_eq!(
        parameter(bad.location.as_deref().context("redirect")?, "state")?,
        "opaque + / & = % ü"
    );
    protocol_error(
        &f.start(&[("response_type", None)]).await?,
        "invalid_request",
    )?;
    Ok(())
}

#[tokio::test]
async fn authorize_scope_pkce_and_oidc_policy_fail_closed() -> Result<()> {
    let f = Fixture::new().await?;
    for scope in [
        "",
        "jobs:unknown",
        "jobs:read jobs:read",
        "jobs:read  runs:read",
        "platform:admin",
        "users:write",
        "profile",
        "openid offline_access",
        "jobs:read\truns:read",
    ] {
        protocol_error(
            &f.start(&[("scope", Some(scope.into()))]).await?,
            "invalid_scope",
        )?;
    }
    sqlx::query("DELETE FROM oauth_client_scopes WHERE client_id=$1 AND scope_id=(SELECT id FROM oauth_scopes WHERE application_id=$2 AND name='jobs:write')").bind(f.client_internal).bind(f.application).execute(&f.pool).await?;
    protocol_error(
        &f.start(&[("scope", Some("jobs:write".into()))]).await?,
        "invalid_scope",
    )?;
    for (key, value) in [
        ("code_challenge", None),
        ("code_challenge_method", None),
        ("code_challenge_method", Some("plain".into())),
        ("code_challenge", Some("a".repeat(42))),
        ("code_challenge", Some("A".repeat(42) + "B")),
    ] {
        protocol_error(&f.start(&[(key, value)]).await?, "invalid_request")?;
    }
    // Confidential clients cannot turn off PKCE either.
    sqlx::query("UPDATE oauth_clients SET client_type='confidential' WHERE id=$1")
        .bind(f.client_internal)
        .execute(&f.pool)
        .await?;
    protocol_error(
        &f.start(&[("code_challenge", None)]).await?,
        "invalid_request",
    )?;
    for extra in [
        "request",
        "request_uri",
        "response_mode",
        "resource",
        "audience",
        "max_age",
        "claims",
        "acr_values",
        "id_token_hint",
    ] {
        protocol_error(
            &f.start(&[(extra, Some("unsupported".into()))]).await?,
            "invalid_request",
        )?;
    }
    protocol_error(
        &f.start(&[("scope", Some("openid profile".into()))]).await?,
        "invalid_request",
    )?;
    protocol_error(
        &f.start(&[("nonce", Some("orphan".into()))]).await?,
        "invalid_request",
    )?;
    let page = f
        .start(&[
            ("scope", Some("openid profile jobs:read".into())),
            ("nonce", Some("exact-nonce".into())),
        ])
        .await?;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Sign in and identify your account"));
    let done = f.decide(&page, "allow", "").await?;
    let code = parameter(done.location.as_deref().context("redirect")?, "code")?;
    let redeemed = f
        .redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
        .await?
        .context("redemption")?;
    assert_eq!(redeemed.nonce.as_deref(), Some("exact-nonce"));
    assert_eq!(
        parameter(done.location.as_deref().context("redirect")?, "iss")?,
        "https://issuer.test"
    );
    let query = url::Url::parse(done.location.as_deref().context("redirect")?)?;
    assert_eq!(
        query
            .query_pairs()
            .map(|(k, _)| k.into_owned())
            .collect::<Vec<_>>(),
        vec!["existing", "code", "iss", "state"]
    );
    Ok(())
}

#[tokio::test]
async fn authorize_tenant_membership_and_internal_permissions_never_expand_delegation() -> Result<()>
{
    let f = Fixture::new().await?;
    sqlx::query("INSERT INTO platform_operators (user_id) VALUES ($1)")
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    sqlx::query("INSERT INTO user_roles (user_id,role) VALUES ($1,'owner')")
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    let foreign: Uuid=sqlx::query_scalar("INSERT INTO organizations (slug,name,created_by) VALUES ('another-org','Another',$1) RETURNING id").bind(f.user).fetch_one(&f.pool).await?;
    sqlx::query("INSERT INTO org_memberships (org_id,user_id,status) VALUES ($1,$2,'active')")
        .bind(foreign)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    protocol_error(
        &f.start(&[("organization_id", Some(foreign.to_string()))])
            .await?,
        "access_denied",
    )?;
    for membership in ["suspended", "invited"] {
        sqlx::query("UPDATE org_memberships SET status=$1::org_membership_status WHERE org_id=$2 AND user_id=$3").bind(membership).bind(f.organization).bind(f.user).execute(&f.pool).await?;
        protocol_error(&f.start(&[]).await?, "access_denied")?;
    }
    sqlx::query("UPDATE org_memberships SET status='active' WHERE org_id=$1 AND user_id=$2")
        .bind(f.organization)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    let code = f.issue().await?;
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, foreign)
            .await?
            .is_none()
    );
    let row = f
        .redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
        .await?
        .context("redemption")?;
    assert_eq!(row.organization_id, f.organization);
    assert_eq!(row.application_id, f.application);
    assert_eq!(row.user_id, f.user);
    assert_eq!(
        row.scopes
            .iter()
            .map(crate::oauth::scope::OAuthScope::as_str)
            .collect::<Vec<_>>(),
        ["jobs:read", "runs:read"]
    );
    assert_eq!(row.issuer, "https://issuer.test");
    assert_eq!(row.audience, "jobs-api");
    Ok(())
}

#[tokio::test]
async fn authorize_consent_is_csrf_session_bound_single_use_and_cannot_widen_scopes() -> Result<()>
{
    let f = Fixture::new().await?;
    let page = f.start(&[]).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Read jobs"));
    assert!(page.body.contains("Read execution history"));
    assert!(!page.body.contains("jobs:write"));
    assert!(
        page.headers
            .get(CACHE_CONTROL)
            .is_some_and(|v| v == "no-store")
    );
    assert!(
        page.headers
            .get(REFERRER_POLICY)
            .is_some_and(|v| v == "same-origin")
    );
    direct_rejection(&f.decide(&page, "allow", "&scope=jobs:write").await?);
    let wrong = format!(
        "request_id={}&csrf={}&decision=allow",
        hidden(&page.body, "request_id")?,
        SecretValue::generate()?.expose()
    );
    protocol_error(
        &f.call(
            &f.router,
            "POST",
            "/authorize/consent",
            Some(&f.token),
            Some(&f.browser),
            Some(&wrong),
        )
        .await?,
        "access_denied",
    )?;
    let proper = format!(
        "request_id={}&csrf={}&decision=allow",
        hidden(&page.body, "request_id")?,
        hidden(&page.body, "csrf")?
    );
    direct_rejection(
        &f.call(
            &f.router,
            "POST",
            "/authorize/consent",
            Some(&f.token),
            Some(&SecretValue::generate()?),
            Some(&proper),
        )
        .await?,
    );
    protocol_error(
        &f.call(
            &f.router,
            "POST",
            "/authorize/consent",
            None,
            Some(&f.browser),
            Some(&proper),
        )
        .await?,
        "access_denied",
    )?;
    let second = super::super::auth::generate_session_token()?;
    sqlx::query("INSERT INTO user_sessions (user_id,session_hash,expires_at) VALUES ($1,$2,clock_timestamp()+INTERVAL '1 hour')").bind(f.user).bind(hash_session_token(&second)).execute(&f.pool).await?;
    protocol_error(
        &f.call(
            &f.router,
            "POST",
            "/authorize/consent",
            Some(&second),
            Some(&f.browser),
            Some(&proper),
        )
        .await?,
        "access_denied",
    )?;
    let done = f.decide(&page, "allow", "").await?;
    assert_eq!(
        done.headers
            .get(REFERRER_POLICY)
            .context("redirect referrer policy")?,
        "no-referrer"
    );
    let location = done.location.as_deref().context("redirect")?;
    assert!(location.starts_with(REDIRECT));
    assert_eq!(parameter(location, "state")?, "opaque + / & = % ü");
    let code = parameter(location, "code")?;
    let snapshot: String =
        sqlx::query_scalar("SELECT to_jsonb(c)::text FROM oauth_authorization_codes c")
            .fetch_one(&f.pool)
            .await?;
    assert!(!snapshot.contains(&code));
    let snapshot: Value = serde_json::from_str(&snapshot)?;
    assert_eq!(snapshot["scope_names"], json!(["jobs:read", "runs:read"]));
    assert!(snapshot.get("code").is_none());
    assert!(snapshot.get("code_verifier").is_none());
    let replay = f.decide(&page, "allow", "").await?;
    direct_rejection(&replay);
    assert!(replay.body.contains("start sign-in again"));
    assert!(!replay.body.contains(&code));
    // A subset skips consent but never inherits the prior grant's extra scope.
    let subset = f.start(&[("scope", Some("jobs:read".into()))]).await?;
    assert_eq!(subset.status, StatusCode::SEE_OTHER);
    let subset = parameter(subset.location.as_deref().context("redirect")?, "code")?;
    let redeemed = f
        .redeem(
            &f.pool,
            &subset,
            f.client,
            REDIRECT,
            VERIFIER,
            f.organization,
        )
        .await?
        .context("subset redemption")?;
    assert_eq!(
        redeemed
            .scopes
            .iter()
            .map(crate::oauth::scope::OAuthScope::as_str)
            .collect::<Vec<_>>(),
        ["jobs:read"]
    );
    let forced = f.start(&[("prompt", Some("consent".into()))]).await?;
    assert_eq!(forced.status, StatusCode::OK);
    protocol_error(&f.decide(&forced, "cancel", "").await?, "access_denied")?;
    direct_rejection(&f.decide(&forced, "allow", "").await?);
    Ok(())
}

#[tokio::test]
async fn authorize_login_resume_preserves_integrity_across_independent_service_instances()
-> Result<()> {
    let f = Fixture::new().await?;
    let request = f
        .call(
            &f.router,
            "GET",
            &f.url(&[
                ("scope", Some("openid jobs:read".into())),
                ("nonce", Some("login-bound-nonce".into())),
            ]),
            None,
            Some(&f.browser),
            None,
        )
        .await?;
    assert_eq!(request.status, StatusCode::SEE_OTHER);
    assert!(
        request
            .cookie
            .as_deref()
            .is_some_and(|s| s.contains("Secure; HttpOnly; SameSite=Lax"))
    );
    let id = parameter(
        request.location.as_deref().context("login")?,
        "oauth_request",
    )?;
    assert!(
        request
            .location
            .as_deref()
            .is_some_and(|s| s.starts_with("https://permesi.dev/login?oauth_request="))
    );
    let second_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&f.postgres.admin_dsn())
        .await?;
    let second_state = AppState {
        pool: second_pool.clone(),
        ..f.state.clone()
    };
    let second_router = crate::api::router()
        .split_for_parts()
        .0
        .with_state(second_state);
    let uri = format!("/authorize/resume?request_id={id}");
    direct_rejection(
        &f.call(
            &second_router,
            "GET",
            &uri,
            Some(&f.token),
            Some(&SecretValue::generate()?),
            None,
        )
        .await?,
    );
    let page = f
        .call(
            &second_router,
            "GET",
            &uri,
            Some(&f.token),
            Some(&f.browser),
            None,
        )
        .await?;
    assert_eq!(page.status, StatusCode::OK);
    let form = format!(
        "request_id={id}&csrf={}&decision=allow",
        hidden(&page.body, "csrf")?
    );
    let reply = f
        .call(
            &second_router,
            "POST",
            "/authorize/consent",
            Some(&f.token),
            Some(&f.browser),
            Some(&form),
        )
        .await?;
    let code = parameter(reply.location.as_deref().context("redirect")?, "code")?;
    let redeemed = f
        .redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
        .await?
        .context("redemption A")?;
    assert_eq!(redeemed.nonce.as_deref(), Some("login-bound-nonce"));
    assert_eq!(
        redeemed
            .scopes
            .iter()
            .map(crate::oauth::scope::OAuthScope::as_str)
            .collect::<Vec<_>>(),
        ["openid", "jobs:read"]
    );
    assert!(
        f.redeem(
            &second_pool,
            &code,
            f.client,
            REDIRECT,
            VERIFIER,
            f.organization
        )
        .await?
        .is_none()
    );
    direct_rejection(
        &f.call(
            &second_router,
            "GET",
            &uri,
            Some(&f.token),
            Some(&f.browser),
            None,
        )
        .await?,
    );
    protocol_error(
        &f.start(&[("prompt", Some("none".into()))]).await?,
        "consent_required",
    )?;
    let no_login = f
        .call(
            &f.router,
            "GET",
            &f.url(&[("prompt", Some("none".into()))]),
            None,
            Some(&f.browser),
            None,
        )
        .await?;
    protocol_error(&no_login, "login_required")?;
    Ok(())
}

#[tokio::test]
async fn authorization_codes_require_exact_client_redirect_pkce_and_current_authority() -> Result<()>
{
    let f = Fixture::new().await?;
    let code = f.issue().await?;
    let other:Uuid=sqlx::query_scalar("INSERT INTO oauth_clients (application_id,name,client_type) VALUES ($1,'Other','public') RETURNING client_id").bind(f.application).fetch_one(&f.pool).await?;
    assert!(
        f.redeem(&f.pool, &code, other, REDIRECT, VERIFIER, f.organization)
            .await?
            .is_none()
    );
    assert!(
        f.redeem(
            &f.pool,
            &code,
            f.client,
            "https://client.test/callback",
            VERIFIER,
            f.organization
        )
        .await?
        .is_none()
    );
    for verifier in ["bad".into(), "x".repeat(43)] {
        assert!(
            f.redeem(
                &f.pool,
                &code,
                f.client,
                REDIRECT,
                &verifier,
                f.organization
            )
            .await?
            .is_none()
        );
    }
    for (update, restore, id) in [
        (
            "UPDATE oauth_clients SET disabled_at=clock_timestamp() WHERE id=$1",
            "UPDATE oauth_clients SET disabled_at=NULL WHERE id=$1",
            f.client_internal,
        ),
        (
            "UPDATE applications SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE applications SET deleted_at=NULL WHERE id=$1",
            f.application,
        ),
        (
            "UPDATE users SET status='disabled' WHERE id=$1",
            "UPDATE users SET status='active' WHERE id=$1",
            f.user,
        ),
    ] {
        sqlx::query(update).bind(id).execute(&f.pool).await?;
        assert!(
            f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
                .await?
                .is_none()
        );
        sqlx::query(restore).bind(id).execute(&f.pool).await?;
    }
    sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
        .bind(f.organization)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
            .await?
            .is_none()
    );
    sqlx::query("UPDATE org_memberships SET status='active' WHERE org_id=$1 AND user_id=$2")
        .bind(f.organization)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    // A failed future issuance rolls consumption back with its caller-owned transaction.
    let mut tx = f.pool.begin().await?;
    redeem_authorization_code(
        &mut tx,
        &f.state.oauth.config,
        RedemptionInput {
            code: &code,
            client_id: f.client,
            redirect_uri: REDIRECT,
            code_verifier: VERIFIER,
            organization_id: f.organization,
        },
    )
    .await?;
    tx.rollback().await?;
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
            .await?
            .is_some()
    );
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
            .await?
            .is_none()
    );
    let revoked = f.issue().await?;
    sqlx::query("UPDATE oauth_grants SET revoked_at=clock_timestamp() WHERE client_id=$1 AND revoked_at IS NULL").bind(f.client_internal).execute(&f.pool).await?;
    assert!(
        f.redeem(
            &f.pool,
            &revoked,
            f.client,
            REDIRECT,
            VERIFIER,
            f.organization
        )
        .await?
        .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn authorization_codes_concurrent_redemption_has_one_committed_winner() -> Result<()> {
    let f = Fixture::new().await?;
    let code = f.issue().await?;
    let second = PgPoolOptions::new()
        .max_connections(3)
        .connect(&f.postgres.admin_dsn())
        .await?;
    let (a, b) = timeout(Duration::from_secs(10), async {
        tokio::join!(
            f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization),
            f.redeem(&second, &code, f.client, REDIRECT, VERIFIER, f.organization)
        )
    })
    .await?;
    assert_eq!(usize::from(a?.is_some()) + usize::from(b?.is_some()), 1);
    let consumed: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM oauth_authorization_codes WHERE code_hash=$1",
    )
    .bind(SecretValue::parse(&code)?.hash())
    .fetch_one(&f.pool)
    .await?;
    assert!(consumed);
    Ok(())
}

#[tokio::test]
async fn authorization_codes_and_pending_requests_expire_using_database_time() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.ttl(1, 600);
    let code = f.issue().await?;
    sleep(Duration::from_millis(1150)).await;
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
            .await?
            .is_none()
    );
    f.ttl(120, 1);
    let page = f.start(&[("prompt", Some("consent".into()))]).await?;
    assert_eq!(page.status, StatusCode::OK);
    sleep(Duration::from_millis(1150)).await;
    direct_rejection(&f.decide(&page, "allow", "").await?);
    Ok(())
}

#[tokio::test]
async fn authorize_pending_and_codes_fail_after_scope_removal_or_configuration_revocation()
-> Result<()> {
    let f = Fixture::new().await?;
    let pending = f.start(&[]).await?;
    let code = f.issue().await?;
    sqlx::query("DELETE FROM oauth_scopes WHERE application_id=$1 AND name='jobs:read'")
        .bind(f.application)
        .execute(&f.pool)
        .await?;
    sqlx::query(
        "INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'jobs:read','application')",
    )
    .bind(f.application)
    .execute(&f.pool)
    .await?;
    sqlx::query("INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2 AND name='jobs:read'").bind(f.client_internal).bind(f.application).execute(&f.pool).await?;
    protocol_error(&f.decide(&pending, "allow", "").await?, "invalid_scope")?;
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn authorization_database_constraints_prevent_binding_mutation_and_replay() -> Result<()> {
    let f = Fixture::new().await?;
    let code = f.issue().await?;
    let hash = SecretValue::parse(&code)?.hash();
    for query in [
        "UPDATE oauth_authorization_codes SET scope_names=ARRAY['jobs:write'] WHERE code_hash=$1",
        "UPDATE oauth_authorization_codes SET organization_id=uuidv4() WHERE code_hash=$1",
        "UPDATE oauth_authorization_codes SET code_challenge=repeat('A',43) WHERE code_hash=$1",
    ] {
        assert!(
            sqlx::query(query)
                .bind(&hash)
                .execute(&f.pool)
                .await
                .is_err()
        );
    }
    let id: Uuid =
        sqlx::query_scalar("SELECT request_id FROM oauth_authorization_codes WHERE code_hash=$1")
            .bind(&hash)
            .fetch_one(&f.pool)
            .await?;
    for query in [
        "UPDATE oauth_authorization_requests SET completed_at=NULL WHERE id=$1",
        "UPDATE oauth_authorization_requests SET scope_names=ARRAY['jobs:write'] WHERE id=$1",
        "UPDATE oauth_authorization_requests SET user_id=uuidv4() WHERE id=$1",
    ] {
        assert!(sqlx::query(query).bind(id).execute(&f.pool).await.is_err());
    }
    f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
        .await?
        .context("redeem")?;
    assert!(
        sqlx::query("UPDATE oauth_authorization_codes SET consumed_at=NULL WHERE code_hash=$1")
            .bind(hash)
            .execute(&f.pool)
            .await
            .is_err()
    );
    // Canonical schema and verifier stay idempotent after live registrations/codes exist.
    let mut conn = PgConnection::connect(&f.postgres.admin_dsn()).await?;
    test_support::sql::execute_script(&mut conn, "schema reapply", SCHEMA).await?;
    test_support::sql::execute_script(
        &mut conn,
        "schema verify",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/sql/verify_permesi.sql"
        )),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn authorization_discovery_advertises_only_implemented_token_methods() -> Result<()> {
    let f = Fixture::new().await?;
    let reply = f
        .call(
            &f.router,
            "GET",
            "/.well-known/openid-configuration",
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(reply.status, StatusCode::OK);
    let metadata: Value = serde_json::from_str(&reply.body)?;
    assert_eq!(metadata["issuer"], "https://issuer.test");
    assert_eq!(
        metadata["authorization_endpoint"],
        "https://issuer.test/authorize"
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(metadata["token_endpoint"], "https://issuer.test/token");
    assert_eq!(
        metadata["authorization_response_iss_parameter_supported"],
        true
    );
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code"])
    );
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["client_secret_basic", "none"])
    );
    assert_eq!(
        reply
            .headers
            .get(CACHE_CONTROL)
            .context("metadata cache policy")?,
        "public, max-age=30"
    );
    assert!(metadata.get("userinfo_endpoint").is_none());
    let disabled = crate::api::router()
        .split_for_parts()
        .0
        .with_state(AppState::for_tests(f.pool.clone())?);
    assert_eq!(
        f.call(
            &disabled,
            "GET",
            "/.well-known/openid-configuration",
            None,
            None,
            None
        )
        .await?
        .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.call(&disabled, "GET", "/authorize", None, None, None)
            .await?
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.call(&disabled, "GET", "/jwks.json", None, None, None)
            .await?
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
async fn authorize_rate_limits_are_shared_and_separate_from_login() -> Result<()> {
    use crate::api::handlers::auth::{
        OpaqueState, RateLimitConfig, RateLimiter, SubjectKey, mfa::MfaConfig,
    };
    let mut f = Fixture::new().await?;
    let auth = AuthState::new(
        f.state.auth.config().clone(),
        OpaqueState::from_seed([1; 32], "test".into(), Duration::from_secs(30), 10),
        Arc::new(RateLimiter::postgres(
            f.pool.clone(),
            RateLimitConfig::new(60, 1, 10),
            SubjectKey::derive(&[1; 32])?,
        )),
        MfaConfig::new(),
    );
    f.state.auth = Arc::new(auth);
    f.router = crate::api::router()
        .split_for_parts()
        .0
        .with_state(f.state.clone());
    let first = f.start(&[]).await?;
    assert_eq!(first.status, StatusCode::OK);
    let independent = PgPoolOptions::new()
        .max_connections(2)
        .connect(&f.postgres.admin_dsn())
        .await?;
    let replica = crate::api::router()
        .split_for_parts()
        .0
        .with_state(AppState {
            pool: independent,
            ..f.state.clone()
        });
    let second = f
        .call(
            &replica,
            "GET",
            &f.url(&[]),
            Some(&f.token),
            Some(&f.browser),
            None,
        )
        .await?;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(second.location.is_none());
    assert_eq!(
        f.state
            .auth
            .rate_limiter()
            .check_ip(None, RateLimitAction::Login)
            .await,
        RateLimitDecision::Allowed
    );
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_requests")
        .fetch_one(&f.pool)
        .await?;
    assert_eq!(pending, 1);
    Ok(())
}

/// Captures production trace output without printing credentials from test requests.
#[derive(Clone)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log lock poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn authorize_production_tracing_excludes_raw_codes_verifiers_and_cookies() -> Result<()> {
    use tracing::instrument::WithSubscriber;
    let mut f = Fixture::new().await?;
    f.router = service_utils::request_id::with_request_correlation(f.router);
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = LogSink(output.clone());
    let subscriber = Arc::new(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .finish(),
    );
    let code = f.issue().with_subscriber(subscriber.clone()).await?;
    assert!(
        f.redeem(&f.pool, &code, f.client, REDIRECT, VERIFIER, f.organization)
            .with_subscriber(subscriber.clone())
            .await?
            .is_some()
    );
    async {
        let error = sqlx::query("SELECT ($1::text)::integer")
            .bind("sensitive_database_value")
            .execute(&f.pool)
            .await
            .err()
            .context("expected database error")?;
        let _ = Error::from(error);
        Ok::<_, anyhow::Error>(())
    }
    .with_subscriber(subscriber.clone())
    .await?;
    let logs = String::from_utf8(
        output
            .lock()
            .map_err(|_| anyhow::anyhow!("log lock poisoned"))?
            .clone(),
    )?;
    for secret in [
        &code,
        &f.token,
        &f.browser.expose().to_owned(),
        &VERIFIER.to_owned(),
    ] {
        assert!(!logs.contains(secret));
    }
    assert!(logs.contains("http.request"));
    assert!(logs.contains("sqlstate_class=\"22\""));
    assert!(!logs.contains("sensitive_database_value"));
    Ok(())
}

/// Real Chromium form submission uses the normal isolated PostgreSQL fixture. The
/// loopback test transport changes no production TLS/issuer validation and never visits
/// an external client. `just web-test-browser` runs this explicitly after the WASM tests.
#[tokio::test]
#[ignore = "requires Chromium and Node; run just web-test-browser"]
async fn authorize_browser_real_postgres_consent_and_redirect() -> Result<()> {
    for callback_bind in ["127.0.0.1:0", "[::1]:0"] {
        browser_consent_flow(callback_bind).await?;
    }
    Ok(())
}

/// Exercises distinct issuer/client origins, including the CSP-unsupported IPv6 literal.
async fn browser_consent_flow(callback_bind: &str) -> Result<()> {
    let mut f = Fixture::new().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let callback_listener = tokio::net::TcpListener::bind(callback_bind).await?;
    let callback_origin = format!("http://{}", callback_listener.local_addr()?);
    let callback = format!("{callback_origin}/callback?existing=%2f");
    sqlx::query("UPDATE oauth_client_redirect_uris SET redirect_uri=$2 WHERE client_id=$1")
        .bind(f.client_internal)
        .bind(&callback)
        .execute(&f.pool)
        .await?;
    let mut oauth = (*f.state.oauth).clone();
    oauth.config.issuer = Some(origin.clone());
    f.state.oauth = Arc::new(oauth);
    let callback_app = axum::Router::new().route(
        "/callback",
        axum::routing::get(|| async {
            Html(
                "<!doctype html><title>Local callback fixture</title><p>Authorization complete</p>",
            )
        }),
    );
    let app = crate::api::router()
        .split_for_parts()
        .0
        .with_state(f.state.clone())
        .merge(callback_app.clone());
    let stop = tokio_util::sync::CancellationToken::new();
    let signal = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(signal.cancelled_owned())
            .await
    });
    let callback_signal = stop.clone();
    let callback_server = tokio::spawn(async move {
        axum::serve(callback_listener, callback_app)
            .with_graceful_shutdown(callback_signal.cancelled_owned())
            .await
    });
    let task_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tokio::process::Command::new("node")
        .arg(task_root.join("apps/web/tests/authorize.mjs"))
        .env("PERMESI_AUTHORIZE_TEST_ORIGIN", &origin)
        .env("PERMESI_AUTHORIZE_TEST_ISSUER", &origin)
        .env("PERMESI_AUTHORIZE_TEST_CALLBACK_ORIGIN", &callback_origin)
        .env(
            "PERMESI_AUTHORIZE_TEST_URL",
            format!("{origin}{}", f.url(&[("redirect_uri", Some(callback))])),
        )
        .env("PERMESI_AUTHORIZE_TEST_SESSION", &f.token)
        .kill_on_drop(true)
        .output();
    let result = timeout(Duration::from_secs(60), output).await;
    stop.cancel();
    server.await??;
    callback_server.await??;
    let output = result??;
    ensure!(
        output.status.success(),
        "browser test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_codes")
        .fetch_one(&f.pool)
        .await?;
    assert_eq!(count, 2);
    assert!(String::from_utf8_lossy(&output.stdout).contains("browser passed"));
    Ok(())
}

#[tokio::test]
async fn authorize_consent_accepts_same_origin_opaque_origin_without_accepting_cross_site_posts()
-> Result<()> {
    let f = Fixture::new().await?;
    let page = f.start(&[]).await?;
    let form = format!(
        "request_id={}&csrf={}&decision=allow",
        hidden(&page.body, "request_id")?,
        hidden(&page.body, "csrf")?
    );
    for (origin, site, status) in [
        ("https://evil.test", "same-origin", StatusCode::BAD_REQUEST),
        ("null", "cross-site", StatusCode::BAD_REQUEST),
        ("null", "none", StatusCode::BAD_REQUEST),
        ("null", "same-origin", StatusCode::SEE_OTHER),
    ] {
        let request = Request::post("/authorize/consent")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("origin", origin)
            .header("sec-fetch-site", site)
            .header(
                COOKIE,
                format!(
                    "permesi_session={}; {BROWSER_COOKIE}={}",
                    f.token,
                    f.browser.expose()
                ),
            )
            .body(Body::from(form.clone()))?;
        let reply = f.router.clone().oneshot(request).await?;
        assert_eq!(reply.status(), status, "origin={origin}, site={site}");
    }
    Ok(())
}

/// Display fields cannot inject forms, navigation or scripts into the script-free consent page.
#[tokio::test]
async fn authorize_consent_display_cannot_inject_markup_or_navigation() -> Result<()> {
    let hostile = "<form action='https://evil.example/'><script>alert(1)</script>";
    let csrf = SecretValue::generate()?;
    let response = consent_page(
        Uuid::new_v4(),
        &csrf,
        hostile,
        hostile,
        hostile,
        &[RequestedScope {
            id: Uuid::new_v4(),
            name: "jobs:read".into(),
            description: hostile.into(),
        }],
    );
    let policy = response
        .headers()
        .get(CONTENT_SECURITY_POLICY)
        .context("missing CSP")?
        .to_str()?;
    assert!(policy.contains("default-src 'none'"));
    assert!(!policy.contains("form-action"));
    assert_eq!(
        response
            .headers()
            .get(REFERRER_POLICY)
            .context("referrer policy")?,
        "same-origin"
    );
    let body = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
    assert_eq!(body.matches("<form ").count(), 1);
    assert!(!body.contains("<script>"));
    assert!(body.contains("&lt;script&gt;"));
    assert!(!body.contains("action='https://evil.example/'"));
    Ok(())
}

#[tokio::test]
async fn authorize_review_regression_client_readers_do_not_serialize_other_users() -> Result<()> {
    let f = Fixture::new().await?;
    let mut reader = f.pool.begin().await?;
    sqlx::query("SELECT id FROM oauth_clients WHERE id=$1 FOR SHARE")
        .bind(f.client_internal)
        .fetch_one(&mut *reader)
        .await?;
    let reply = timeout(Duration::from_millis(500), f.start(&[])).await;
    reader.rollback().await?;
    assert_eq!(
        reply
            .context("authorization blocked behind another client reader")??
            .status,
        StatusCode::OK
    );
    let (first, second) = tokio::join!(f.start(&[]), f.start(&[]));
    let (first, second) = (first?, second?);
    let (first, second) = tokio::join!(
        f.decide(&first, "allow", ""),
        f.decide(&second, "allow", "")
    );
    assert_eq!(first?.status, StatusCode::SEE_OTHER);
    assert_eq!(second?.status, StatusCode::SEE_OTHER);
    let grants: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_grants WHERE revoked_at IS NULL")
            .fetch_one(&f.pool)
            .await?;
    assert_eq!(grants, 1);
    Ok(())
}

#[tokio::test]
async fn authorize_review_regression_resume_and_consent_are_throttled() -> Result<()> {
    use crate::api::handlers::auth::{
        OpaqueState, RateLimitConfig, RateLimiter, SubjectKey, mfa::MfaConfig,
    };
    let mut f = Fixture::new().await?;
    let page = f.start(&[]).await?;
    f.state.auth = Arc::new(AuthState::new(
        f.state.auth.config().clone(),
        OpaqueState::from_seed([1; 32], "test".into(), Duration::from_secs(30), 10),
        Arc::new(RateLimiter::postgres(
            f.pool.clone(),
            RateLimitConfig::new(60, 1, 10),
            SubjectKey::derive(&[1; 32])?,
        )),
        MfaConfig::new(),
    ));
    f.router = crate::api::router()
        .split_for_parts()
        .0
        .with_state(f.state.clone());
    let resume = format!(
        "/authorize/resume?request_id={}",
        hidden(&page.body, "request_id")?
    );
    assert_eq!(
        f.call(
            &f.router,
            "GET",
            &resume,
            Some(&f.token),
            Some(&f.browser),
            None
        )
        .await?
        .status,
        StatusCode::OK
    );
    assert_eq!(
        f.decide(&page, "allow", "").await?.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        f.call(
            &f.router,
            "GET",
            &resume,
            Some(&f.token),
            Some(&f.browser),
            None
        )
        .await?
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}

#[tokio::test]
async fn authorize_lock_waits_are_bounded_and_rollback_without_issuing_codes() -> Result<()> {
    let mut f = Fixture::new().await?;
    let mut oauth = (*f.state.oauth).clone();
    oauth.config.lock_timeout_ms = 50;
    f.state.oauth = Arc::new(oauth);
    f.router = crate::api::router()
        .split_for_parts()
        .0
        .with_state(f.state.clone());
    let mut writer = f.pool.begin().await?;
    sqlx::query("SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE")
        .bind(f.client_internal)
        .fetch_one(&mut *writer)
        .await?;
    let reply = timeout(Duration::from_secs(1), f.start(&[])).await;
    writer.rollback().await?;
    let reply = reply.context("OAuth client lock wait was not bounded")??;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(reply.location.is_none());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_requests")
        .fetch_one(&f.pool)
        .await?;
    assert_eq!(count, 0);
    assert_eq!(f.start(&[]).await?.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn authorize_budget_is_browser_bound_and_shared_across_replicas() -> Result<()> {
    use crate::api::handlers::auth::{
        OpaqueState, RateLimitConfig, RateLimiter, SubjectKey, mfa::MfaConfig,
    };
    let f = Fixture::new().await?;
    let page = f.start(&[]).await?;
    let auth = |pool| -> Result<Arc<AuthState>> {
        Ok(Arc::new(AuthState::new(
            f.state.auth.config().clone(),
            OpaqueState::from_seed([1; 32], "test".into(), Duration::from_secs(30), 10),
            Arc::new(RateLimiter::postgres(
                pool,
                RateLimitConfig::new(60, 3, 1),
                SubjectKey::derive(&[1; 32])?,
            )),
            MfaConfig::new(),
        )))
    };
    let mut first_state = f.state.clone();
    first_state.auth = auth(f.pool.clone())?;
    let other_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&f.postgres.admin_dsn())
        .await?;
    let mut second_state = f.state.clone();
    second_state.auth = auth(other_pool.clone())?;
    second_state.pool = other_pool;
    let first = crate::api::router()
        .split_for_parts()
        .0
        .with_state(first_state);
    let second = crate::api::router()
        .split_for_parts()
        .0
        .with_state(second_state);
    let resume = format!(
        "/authorize/resume?request_id={}",
        hidden(&page.body, "request_id")?
    );
    let foreign_browser = SecretValue::generate()?;
    assert_eq!(
        f.call(
            &first,
            "GET",
            &resume,
            Some(&f.token),
            Some(&foreign_browser),
            None
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.call(
            &first,
            "GET",
            &resume,
            Some(&f.token),
            Some(&f.browser),
            None
        )
        .await?
        .status,
        StatusCode::OK
    );
    assert_eq!(
        f.call(
            &second,
            "GET",
            &resume,
            Some(&f.token),
            Some(&f.browser),
            None
        )
        .await?
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    for router in [&first, &second, &first] {
        let reply = f
            .call(
                router,
                "GET",
                "/.well-known/openid-configuration",
                None,
                None,
                None,
            )
            .await?;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.headers.get(CACHE_CONTROL).context("cache policy")?,
            "public, max-age=30"
        );
    }
    let limited = f
        .call(&second, "GET", "/jwks.json", None, None, None)
        .await?;
    assert_eq!(limited.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        limited
            .headers
            .get(CACHE_CONTROL)
            .context("error cache policy")?,
        "no-store"
    );
    Ok(())
}

#[tokio::test]
async fn oidc_metadata_does_not_charge_or_query_authentication_budgets() -> Result<()> {
    use crate::api::handlers::auth::{
        OpaqueState, RateLimitConfig, RateLimiter, SubjectKey, mfa::MfaConfig,
    };
    let f = Fixture::new().await?;
    let mut state = f.state.clone();
    state.auth = Arc::new(AuthState::new(
        f.state.auth.config().clone(),
        OpaqueState::from_seed([1; 32], "test".into(), Duration::from_secs(30), 10),
        Arc::new(RateLimiter::postgres(
            f.pool.clone(),
            RateLimitConfig::new(60, 1, 1),
            SubjectKey::derive(&[1; 32])?,
        )),
        MfaConfig::new(),
    ));
    let router = crate::api::router().split_for_parts().0.with_state(state);
    for _ in 0..5 {
        assert_eq!(
            f.call(
                &router,
                "GET",
                "/.well-known/openid-configuration",
                None,
                None,
                None
            )
            .await?
            .status,
            StatusCode::OK
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_rate_limits")
        .fetch_one(&f.pool)
        .await?;
    assert_eq!(count, 0);
    // Public, already cached metadata stays available even if the authentication pool is closed.
    f.pool.close().await;
    assert_eq!(
        f.call(
            &router,
            "GET",
            "/.well-known/openid-configuration",
            None,
            None,
            None
        )
        .await?
        .status,
        StatusCode::OK
    );
    Ok(())
}
