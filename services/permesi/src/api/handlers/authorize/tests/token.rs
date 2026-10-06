//! Real router/PostgreSQL/Vault exchange tests, including rollback and replica concurrency.

#![allow(clippy::indexing_slicing, clippy::too_many_lines)]

use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use test_support::vault::VaultContainer;
use vault_client::{VaultTarget, VaultTransport};

/// Combines a production-router fixture with real nonexportable transit signing.
mod refresh;

struct TokenFixture {
    f: Fixture,
    vault: VaultContainer,
}

/// Case-insensitive, repeated and quoted cache directives refresh actual rotated Vault keys.
#[tokio::test]
async fn jwks_review_regression_refresh_accepts_http_cache_directives() -> Result<()> {
    let fixture = TokenFixture::new().await?;
    let f = &fixture.f;
    let transport =
        VaultTransport::from_target("jwks-test", VaultTarget::parse(fixture.vault.base_url())?)?;
    let initial = f.state.oauth.jwks().await?;
    assert_eq!(initial.keys.len(), 1);
    for (index, directives) in [
        vec!["No-Cache"],
        vec!["MAX-AGE=0"],
        vec!["max-age=\"0\""],
        vec!["public", "No-Cache"],
    ]
    .into_iter()
    .enumerate()
    {
        let rotated = transport
            .request_json(
                http::Method::POST,
                "/v1/transit/permesi/keys/oidc-signing/rotate",
                Some("root-token"),
                Some(&json!({})),
            )
            .await?;
        ensure!(rotated.status.is_success(), "rotation failed");
        let mut request = Request::builder().uri("/jwks.json");
        for directive in directives {
            request = request.header(CACHE_CONTROL, directive);
        }
        let response = f
            .router
            .clone()
            .oneshot(request.body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["keys"].as_array().context("keys")?.len(), index + 2);
    }
    Ok(())
}

impl TokenFixture {
    /// Starts isolated storage and a real nonexportable RSA key for the production router.
    async fn new() -> Result<Self> {
        let mut f = Fixture::new().await?;
        let vault = VaultContainer::start("bridge").await?;
        vault
            .enable_secrets_engine("transit/permesi", "transit")
            .await?;
        vault
            .create_transit_key("transit/permesi", "oidc-signing", "rsa-2048")
            .await?;
        let transport =
            VaultTransport::from_target("token-test", VaultTarget::parse(vault.base_url())?)?;
        let mut globals = crate::cli::globals::GlobalArgs::new(vault.base_url().into(), transport);
        globals.set_token(SecretString::from("root-token"));
        globals.vault_transit_mount = "transit/permesi".into();
        f.state.oauth = Arc::new(OAuthState::new(f.state.oauth.config.clone(), &globals));
        f.router = router(&f.state);
        Ok(Self { f, vault })
    }
}

/// Builds a distinct HTTP service sharing only durable authority and deployment policy.
fn router(state: &AppState) -> Router {
    crate::api::router()
        .split_for_parts()
        .0
        .with_state(state.clone())
}

/// Strict native exchange with no session cookie. Error bodies and bearer strings are never printed.
async fn exchange(
    router: &Router,
    fields: &[(&str, &str)],
    basic: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let form = {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.extend_pairs(fields.iter().copied());
        serializer.finish()
    };
    let mut request = Request::builder()
        .method("POST")
        .uri("/token")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(value) = basic {
        request = request.header("authorization", value);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::from(form))?)
        .await?;
    let status = response.status();
    ensure!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .is_some_and(|v| v == "no-store"),
        "missing cache protection"
    );
    ensure!(
        response
            .headers()
            .get("pragma")
            .is_some_and(|v| v == "no-cache"),
        "missing pragma"
    );
    ensure!(
        response.headers().get(LOCATION).is_none(),
        "unsafe token redirect"
    );
    if status == StatusCode::UNAUTHORIZED {
        ensure!(
            response.headers().get("www-authenticate").is_some(),
            "missing Basic challenge"
        );
    }
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// Builds only supported code-exchange fields; no session or tenant authority is supplied.
fn fields<'a>(
    code: &'a str,
    client: &'a str,
    redirect: &'a str,
    verifier: &'a str,
) -> [(&'a str, &'a str); 5] {
    [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client),
        ("redirect_uri", redirect),
        ("code_verifier", verifier),
    ]
}

/// Independently verifies RSA signature, fixed algorithm, token type and published kid.
fn verify(token: &str, keys: &Value, typ: &str) -> Result<Value> {
    let parts = token.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 3, "invalid JWT shape");
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    ensure!(
        header["alg"] == "RS256" && header["typ"] == typ,
        "invalid JWT header"
    );
    let key = keys["keys"]
        .as_array()
        .context("no keys")?
        .iter()
        .find(|v| v["kid"] == header["kid"])
        .context("unknown kid")?;
    let rsa = RsaPublicKey::new(
        BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(key["n"].as_str().context("n")?)?),
        BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(key["e"].as_str().context("e")?)?),
    )?;
    let input = format!("{}.{}", parts[0], parts[1]);
    rsa.verify(
        Pkcs1v15Sign::new::<opaque_sha2::Sha256>(),
        &Sha256::digest(input.as_bytes()),
        &URL_SAFE_NO_PAD.decode(parts[2])?,
    )?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?)
}

#[tokio::test]
async fn token_exchange_public_claims_receipt_replay_and_internal_boundary() -> Result<()> {
    let t = TokenFixture::new().await?;
    let f = &t.f;
    let page = f
        .start(&[
            ("scope", Some("openid jobs:read".into())),
            ("nonce", Some("bound-nonce".into())),
        ])
        .await?;
    let redirect = f.decide(&page, "allow", "").await?;
    ensure!(
        parameter(redirect.location.as_deref().context("redirect")?, "iss")?
            == "https://issuer.test",
        "issuer missing"
    );
    let code = parameter(redirect.location.as_deref().context("redirect")?, "code")?;
    let client = f.client.to_string();
    let (status, body) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(
        body["scope"] == "openid jobs:read"
            && body["token_type"] == "Bearer"
            && body["expires_in"] == 300,
        "incorrect response authority"
    );
    ensure!(
        body.get("refresh_token").is_none(),
        "unsupported refresh token"
    );
    let keys = serde_json::to_value(f.state.oauth.jwks().await?)?;
    let access = body["access_token"].as_str().context("access")?;
    let claims = verify(access, &keys, "at+jwt")?;
    ensure!(
        claims["iss"] == "https://issuer.test"
            && claims["aud"] == "jobs-api"
            && claims["sub"] == f.user.to_string()
            && claims["client_id"] == client
            && claims["organization_id"] == f.organization.to_string()
            && claims["application_id"] == f.application.to_string()
            && claims["scope"] == "openid jobs:read"
            && claims["exp"].as_i64().context("exp")? - claims["iat"].as_i64().context("iat")?
                == 300,
        "incorrect access claims"
    );
    let id = body["id_token"].as_str().context("ID")?;
    let identity = verify(id, &keys, "JWT")?;
    ensure!(
        identity["aud"] == client
            && identity["nonce"] == "bound-nonce"
            && identity["sub"] == claims["sub"]
            && identity["iss"] == claims["iss"]
            && identity["at_hash"]
                == URL_SAFE_NO_PAD.encode(&Sha256::digest(access.as_bytes())[..16]),
        "incorrect ID binding"
    );
    let bound: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT auth_time FROM oauth_authorization_codes WHERE code_hash=$1")
            .bind(Sha256::digest(code.as_bytes()).to_vec())
            .fetch_one(&f.pool)
            .await?;
    ensure!(
        identity["auth_time"] == bound.timestamp(),
        "auth time widened"
    );
    let recorded: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_token_issuances WHERE code_hash=$1 AND access_token_hash=$2 AND id_token_hash=$3 AND access_jti=$4 AND user_id=$5 AND organization_id=$6)")
        .bind(Sha256::digest(code.as_bytes()).to_vec()).bind(Sha256::digest(access.as_bytes()).to_vec()).bind(Sha256::digest(id.as_bytes()).to_vec())
        .bind(Uuid::parse_str(claims["jti"].as_str().context("jti")?)?).bind(f.user).bind(f.organization).fetch_one(&f.pool).await?;
    ensure!(recorded, "hash-only receipt missing");
    let (status, error) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    ensure!(
        error == json!({"error":"invalid_grant"}),
        "replay error leak"
    );
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/orgs")
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn token_exchange_production_tracing_excludes_bearer_material() -> Result<()> {
    use tracing::instrument::WithSubscriber as _;
    let mut t = TokenFixture::new().await?;
    let f = &mut t.f;
    f.router = service_utils::request_id::with_request_correlation(f.router.clone());
    let page = f
        .start(&[
            ("scope", Some("openid jobs:read".into())),
            ("nonce", Some("private-nonce".into())),
        ])
        .await?;
    let redirect = f.decide(&page, "allow", "").await?;
    let code = parameter(redirect.location.as_deref().context("callback")?, "code")?;
    let client = f.client.to_string();
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = LogSink(output.clone());
    let subscriber = Arc::new(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .finish(),
    );
    let (status, body) = exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None)
        .with_subscriber(subscriber)
        .await?;
    assert_eq!(status, StatusCode::OK);
    let logs = String::from_utf8(
        output
            .lock()
            .map_err(|_| anyhow::anyhow!("log capture failed"))?
            .clone(),
    )?;
    for secret in [
        &code,
        VERIFIER,
        body["access_token"].as_str().context("access")?,
        body["id_token"].as_str().context("ID")?,
        "private-nonce",
    ] {
        ensure!(
            !logs.contains(secret),
            "secret appeared in production tracing"
        );
    }
    Ok(())
}

#[tokio::test]
async fn token_exchange_rejects_wrong_bindings_without_consumption_and_omits_id() -> Result<()> {
    let t = TokenFixture::new().await?;
    let f = &t.f;
    let code = f.issue().await?;
    let client = f.client.to_string();
    let other = Uuid::new_v4();
    let other_internal:Uuid=sqlx::query_scalar("INSERT INTO oauth_clients(application_id,client_id,name,client_type) VALUES($1,$2,'Other','public') RETURNING id").bind(f.application).bind(other).fetch_one(&f.pool).await?;
    sqlx::query("INSERT INTO oauth_client_redirect_uris(client_id,redirect_uri) VALUES($1,$2)")
        .bind(other_internal)
        .bind(REDIRECT)
        .execute(&f.pool)
        .await?;
    let (status, error) = exchange(
        &f.router,
        &fields(&code, &other.to_string(), REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    ensure!(
        error == json!({"error":"invalid_grant"}),
        "code crossed clients"
    );
    for (redirect, verifier) in [
        ("https://client.test/callback", VERIFIER),
        (REDIRECT, "wrong"),
        (REDIRECT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ] {
        let (status, error) =
            exchange(&f.router, &fields(&code, &client, redirect, verifier), None).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        ensure!(
            error == json!({"error":"invalid_grant"}),
            "binding error leak"
        );
    }
    let (status, body) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(body.get("id_token").is_none(), "ID token without openid");
    Ok(())
}

#[tokio::test]
async fn token_exchange_expired_codes_and_inactive_membership_fail_closed() -> Result<()> {
    let mut t = TokenFixture::new().await?;
    t.f.ttl(1, 600);
    let f = &t.f;
    let code = f.issue().await?;
    let client = f.client.to_string();
    sleep(Duration::from_millis(1100)).await;
    let (status, error) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    ensure!(
        error == json!({"error":"invalid_grant"}),
        "expired code accepted"
    );
    t.f.ttl(120, 600);
    let f = &t.f;
    let code = f.issue().await?;
    sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
        .bind(f.organization)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    let (status, error) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    ensure!(
        error == json!({"error":"invalid_grant"}),
        "inactive membership accepted"
    );
    let unexpired:bool=sqlx::query_scalar("SELECT consumed_at IS NULL AND expires_at>clock_timestamp() FROM oauth_authorization_codes WHERE code_hash=$1").bind(Sha256::digest(code.as_bytes()).to_vec()).fetch_one(&f.pool).await?;
    ensure!(unexpired, "membership rejection masked by expiry");
    Ok(())
}

#[tokio::test]
async fn token_exchange_signing_failure_and_deadline_roll_back_code() -> Result<()> {
    let t = TokenFixture::new().await?;
    let f = &t.f;
    let code = f.issue().await?;
    let client = f.client.to_string();
    let mut state = f.state.clone();
    let mut unavailable = (*state.oauth).clone();
    unavailable.config.signing_key = "missing-key".into();
    state.oauth = Arc::new(unavailable);
    let (status, error) = exchange(
        &router(&state),
        &fields(&code, &client, REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    ensure!(
        error == json!({"error":"temporarily_unavailable"}),
        "dependency leak"
    );
    let unconsumed: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NULL FROM oauth_authorization_codes WHERE code_hash=$1",
    )
    .bind(Sha256::digest(code.as_bytes()).to_vec())
    .fetch_one(&f.pool)
    .await?;
    ensure!(unconsumed, "signing failure consumed code");
    let mut block = f.pool.begin().await?;
    crate::oauth::locking::client(&mut block, f.client, true).await?;
    let mut bounded = (*f.state.oauth).clone();
    bounded.config.tokens.timeout_ms = 25;
    let mut bounded_state = f.state.clone();
    bounded_state.oauth = Arc::new(bounded);
    let (status, _) = exchange(
        &router(&bounded_state),
        &fields(&code, &client, REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    block.rollback().await?;
    let (status, _) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn token_exchange_confidential_current_retiring_revoked_and_no_downgrade() -> Result<()> {
    let mut t = TokenFixture::new().await?;
    let f = &mut t.f;
    let client = Uuid::new_v4();
    let internal:Uuid=sqlx::query_scalar("INSERT INTO oauth_clients (application_id,client_id,name,client_type) VALUES ($1,$2,'Confidential','confidential') RETURNING id").bind(f.application).bind(client).fetch_one(&f.pool).await?;
    sqlx::query("INSERT INTO oauth_client_redirect_uris (client_id,redirect_uri) VALUES ($1,$2)")
        .bind(internal)
        .bind(REDIRECT)
        .execute(&f.pool)
        .await?;
    sqlx::query("INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2").bind(internal).bind(f.application).execute(&f.pool).await?;
    // Credential management authorizes managers, not the resource owner's delegated scopes.
    sqlx::query("INSERT INTO org_roles (org_id,name) VALUES ($1,'owner')")
        .bind(f.organization)
        .execute(&f.pool)
        .await?;
    sqlx::query("INSERT INTO org_member_roles (org_id,user_id,role_name) VALUES ($1,$2,'owner')")
        .bind(f.organization)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    f.client = client;
    f.client_internal = internal;
    let context = crate::oauth::service::ApplicationContext::resolved(f.application, f.user);
    let first = f
        .state
        .oauth
        .credentials
        .issue(&f.pool, &context, client, None)
        .await?;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{client}:{}", first.client_secret.expose_secret()))
    );
    let code = f.issue().await?;
    let client = client.to_string();
    for auth in [None, Some("Basic bad")] {
        let (status, error) =
            exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), auth).await?;
        assert_eq!(
            status,
            if auth.is_some() {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            }
        );
        ensure!(
            error == json!({"error":"invalid_client"}),
            "credential leak"
        );
    }
    let current = f
        .state
        .oauth
        .credentials
        .issue(&f.pool, &context, f.client, Some(first.credential.id))
        .await?;
    let (status, _) = exchange(
        &f.router,
        &fields(&code, &client, REDIRECT, VERIFIER),
        Some(&basic),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let code = f.issue().await?;
    f.state
        .oauth
        .credentials
        .revoke(&f.pool, &context, f.client, first.credential.id)
        .await?;
    let (status, error) = exchange(
        &f.router,
        &fields(&code, &client, REDIRECT, VERIFIER),
        Some(&basic),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    ensure!(
        error == json!({"error":"invalid_client"}),
        "revocation leak"
    );
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{client}:{}",
            current.client_secret.expose_secret()
        ))
    );
    let (status, _) = exchange(
        &f.router,
        &fields(&code, &client, REDIRECT, VERIFIER),
        Some(&basic),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn token_exchange_independent_replicas_have_one_committed_winner() -> Result<()> {
    let t = TokenFixture::new().await?;
    let f = &t.f;
    let code = f.issue().await?;
    let client = f.client.to_string();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&f.postgres.admin_dsn())
        .await?;
    let mut state = f.state.clone();
    state.pool = pool.clone();
    let second = router(&state);
    let input = fields(&code, &client, REDIRECT, VERIFIER);
    let (a, b) = tokio::join!(
        exchange(&f.router, &input, None),
        exchange(&second, &input, None)
    );
    let a = a?;
    let b = b?;
    assert_eq!(
        [a.0, b.0].iter().filter(|s| **s == StatusCode::OK).count(),
        1
    );
    assert_eq!(
        [a.0, b.0]
            .iter()
            .filter(|s| **s == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_token_issuances WHERE code_hash=$1")
            .bind(Sha256::digest(code.as_bytes()).to_vec())
            .fetch_one(&pool)
            .await?;
    assert_eq!(count, 1);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn token_exchange_shared_budget_and_body_limits_preserve_code() -> Result<()> {
    use crate::api::handlers::auth::{RateLimitConfig, RateLimiter, SubjectKey};
    let t = TokenFixture::new().await?;
    let f = &t.f;
    let code = f.issue().await?;
    let client = f.client.to_string();
    let mut budgeted = f.state.clone();
    let mut oauth = (*f.state.oauth).clone();
    oauth.config.tokens.client_ip_attempts = 1;
    budgeted.oauth = Arc::new(oauth);
    let limiter = RateLimiter::postgres(
        f.pool.clone(),
        RateLimitConfig::new(600, 100, 1),
        SubjectKey::derive(&[9; 32])?,
    );
    budgeted.auth = Arc::new(AuthState::new(
        f.state.auth.config().clone(),
        crate::api::handlers::auth::OpaqueState::from_seed(
            [1; 32],
            "api.permesi.dev".into(),
            Duration::from_secs(30),
            100,
        ),
        Arc::new(limiter),
        f.state.auth.mfa().clone(),
    ));
    let first = router(&budgeted);
    let (status, _) = exchange(&first, &fields(&code, &client, REDIRECT, "wrong"), None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&f.postgres.admin_dsn())
        .await?;
    let limiter = RateLimiter::postgres(
        pool.clone(),
        RateLimitConfig::new(600, 100, 1),
        SubjectKey::derive(&[9; 32])?,
    );
    budgeted.auth = Arc::new(AuthState::new(
        f.state.auth.config().clone(),
        crate::api::handlers::auth::OpaqueState::from_seed(
            [1; 32],
            "api.permesi.dev".into(),
            Duration::from_secs(30),
            100,
        ),
        Arc::new(limiter),
        f.state.auth.mfa().clone(),
    ));
    let (status, error) = exchange(
        &router(&budgeted),
        &fields(&code, &client, REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    ensure!(
        error == json!({"error":"temporarily_unavailable"}),
        "rate error leak"
    );
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.extend_pairs(fields(&code, &client, REDIRECT, VERIFIER));
    let body = form.finish();
    let peer_router = router(&budgeted).layer(axum::middleware::from_fn_with_state(
        crate::api::handlers::auth::operations::OperationsConfig::defaults(),
        crate::api::handlers::auth::operations::verified_peer,
    ));
    // A raw forwarded header cannot bypass the exhausted unknown-peer bucket.
    let spoofed = peer_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-for", "192.0.2.77")
                .header("x-permesi-client-ip", "192.0.2.77")
                .body(Body::from(body.clone()))?,
        )
        .await?;
    assert_eq!(spoofed.status(), StatusCode::TOO_MANY_REQUESTS);
    let reply = peer_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .extension(axum::extract::ConnectInfo(
                    "192.0.2.77:443".parse::<std::net::SocketAddr>()?,
                ))
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(reply.status(), StatusCode::OK);
    let mut bounded = (*f.state.oauth).clone();
    bounded.config.tokens.max_body_bytes = 1024;
    let mut state = f.state.clone();
    state.oauth = Arc::new(bounded);
    let (status, error) = exchange(
        &router(&state),
        &fields(&"a".repeat(2000), &client, REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    ensure!(
        error == json!({"error":"invalid_request"}),
        "unbounded body"
    );
    let response = f
        .router
        .clone()
        .oneshot(Request::builder().uri("/token").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    ensure!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .is_some_and(|v| v == "no-store"),
        "method error cacheable"
    );
    pool.close().await;
    Ok(())
}

/// A fake transport signs access correctly but fails identity signing, exercising late rollback.
struct FailIdentity(rsa::RsaPrivateKey);

impl wiremock::Respond for FailIdentity {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let Some(input) = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|v| v["input"].as_str().map(str::to_owned))
            .and_then(|s| STANDARD.decode(s).ok())
            .and_then(|s| String::from_utf8(s).ok())
        else {
            return wiremock::ResponseTemplate::new(503);
        };
        let Some(header) = input
            .split('.')
            .next()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
            .and_then(|s| serde_json::from_slice::<Value>(&s).ok())
        else {
            return wiremock::ResponseTemplate::new(503);
        };
        if header["typ"] == "JWT" {
            return wiremock::ResponseTemplate::new(503);
        }
        let Ok(signature) = self.0.sign(
            Pkcs1v15Sign::new::<opaque_sha2::Sha256>(),
            &Sha256::digest(input.as_bytes()),
        ) else {
            return wiremock::ResponseTemplate::new(503);
        };
        wiremock::ResponseTemplate::new(200).set_body_json(
            json!({"data":{"signature":format!("vault:v1:{}",STANDARD.encode(signature))}}),
        )
    }
}

#[tokio::test]
async fn token_exchange_identity_signing_failure_rolls_back_already_signed_access() -> Result<()> {
    use rsa::pkcs8::{EncodePublicKey as _, LineEnding};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    let t = TokenFixture::new().await?;
    let f = &t.f;
    let page = f
        .start(&[
            ("scope", Some("openid jobs:read".into())),
            ("nonce", Some("nonce".into())),
        ])
        .await?;
    let redirect = f.decide(&page, "allow", "").await?;
    let code = parameter(redirect.location.as_deref().context("callback")?, "code")?;
    let client = f.client.to_string();
    let server = MockServer::start().await;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
    let pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;
    Mock::given(method("GET"))
        .and(path("/v1/transit/permesi/keys/oidc-signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data":{"type":"rsa-2048","latest_version":1,"keys":{"1":{"public_key":pem}}}}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/permesi/sign/oidc-signing"))
        .respond_with(FailIdentity(key))
        .mount(&server)
        .await;
    let transport = VaultTransport::from_target("test", VaultTarget::parse(&server.uri())?)?;
    let mut globals = crate::cli::globals::GlobalArgs::new(server.uri(), transport);
    globals.vault_transit_mount = "transit/permesi".into();
    let mut state = f.state.clone();
    state.oauth = Arc::new(OAuthState::new(f.state.oauth.config.clone(), &globals));
    let (status, _) = exchange(
        &router(&state),
        &fields(&code, &client, REDIRECT, VERIFIER),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_token_issuances")
        .fetch_one(&f.pool)
        .await?;
    assert_eq!(count, 0);
    let requests = server.received_requests().await.context("requests")?;
    assert_eq!(requests.len(), 3);
    let (status, _) =
        exchange(&f.router, &fields(&code, &client, REDIRECT, VERIFIER), None).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}
