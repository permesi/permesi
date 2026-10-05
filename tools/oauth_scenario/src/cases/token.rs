//! Real runtime-role HTTP exchanges and independent JWT verification on disposable replicas.
//!
//! Flow Overview: real browser consent issues codes on A; cookie-free native exchanges
//! on B authenticate current clients, commit one receipt and sign through real Vault.
//! Negative controls prove failed attempts do not consume codes; signature/claim checks
//! never reuse production validators. Bearer material is retained only in private memory.

use super::*;
use base64::engine::general_purpose::STANDARD;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};

/// Missing JSON members compare as null and never panic or print supplied material.
fn value(object: &Value, key: &str) -> Value {
    object.get(key).cloned().unwrap_or(Value::Null)
}

/// Builds the entire supported form; tenant and scope authority are never submitted.
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

/// Validates protocol/caching/redirect behavior without echoing secret-bearing responses.
async fn response(reply: reqwest::Response, status: StatusCode) -> Result<Value> {
    check(
        reply.status() == status,
        "Token endpoint returned an unexpected status.",
    )?;
    check(
        reply
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .is_some_and(|v| v == "no-store")
            && reply
                .headers()
                .get(reqwest::header::PRAGMA)
                .is_some_and(|v| v == "no-cache")
            && reply.headers().get(reqwest::header::LOCATION).is_none(),
        "Token response cache/redirect protection failed.",
    )?;
    if status == StatusCode::UNAUTHORIZED {
        check(
            reply
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .is_some(),
            "Basic failure omitted its challenge.",
        )?;
    }
    reply
        .json()
        .await
        .safe("Token endpoint returned invalid JSON.")
}

/// Requires a single value-free OAuth error, without envelope/diagnostic leaks.
async fn failure(reply: reqwest::Response, status: StatusCode, error: &str) -> Result<()> {
    check(
        response(reply, status).await? == json!({"error":error}),
        "Token error leaked details or used incorrect protocol semantics.",
    )
}

/// Verifies fixed RS256/type/key and a signature using published unsigned RSA integers.
fn verify(token: &str, keys: &Value, typ: &str) -> Result<(Value, Value)> {
    let mut parts = token.split('.');
    let header = parts
        .next()
        .ok_or_else(|| Failure::assertion("JWT header missing."))?;
    let payload = parts
        .next()
        .ok_or_else(|| Failure::assertion("JWT payload missing."))?;
    let signature = parts
        .next()
        .ok_or_else(|| Failure::assertion("JWT signature missing."))?;
    check(parts.next().is_none(), "Invalid JWT segment count.")?;
    let decoded: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .safe("Invalid JWT header encoding.")?,
    )
    .safe("Invalid JWT header.")?;
    check(
        value(&decoded, "alg") == "RS256" && value(&decoded, "typ") == typ,
        "JWT algorithm/type substitution.",
    )?;
    let key = keys
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| Failure::assertion("JWKS missing."))?
        .iter()
        .find(|v| value(v, "kid") == value(&decoded, "kid"))
        .ok_or_else(|| Failure::assertion("JWT kid not published."))?;
    let rsa = RsaPublicKey::new(
        BigUint::from_bytes_be(
            &URL_SAFE_NO_PAD
                .decode(text_field(key, "n")?)
                .safe("Invalid JWK modulus.")?,
        ),
        BigUint::from_bytes_be(
            &URL_SAFE_NO_PAD
                .decode(text_field(key, "e")?)
                .safe("Invalid JWK exponent.")?,
        ),
    )
    .safe("Invalid RSA key.")?;
    rsa.verify(
        Pkcs1v15Sign::new::<opaque_sha2::Sha256>(),
        &Sha256::digest(format!("{header}.{payload}").as_bytes()),
        &URL_SAFE_NO_PAD
            .decode(signature)
            .safe("Invalid JWT signature encoding.")?,
    )
    .safe("JWT signature verification failed.")?;
    let claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .safe("Invalid JWT payload encoding.")?,
    )
    .safe("Invalid JWT claims.")?;
    Ok((decoded, claims))
}

/// Reads keys through a verified HTTPS client; force refresh supports an unknown rotated kid.
async fn keys(api: &Api, refresh: bool) -> Result<Value> {
    let mut request = api.client.get(format!("{}/jwks.json", api.origin));
    if refresh {
        request = request.header(reqwest::header::CACHE_CONTROL, "no-cache");
    }
    let response = request.send().await.safe("JWKS HTTP request failed.")?;
    check(response.status() == StatusCode::OK, "JWKS unavailable.")?;
    response.json().await.safe("Invalid JWKS JSON.")
}

/// Refreshes once on an unknown kid; token exchange is never retried or relaxed.
/// Unverified header data selects only a lookup in this issuer's fixed public JWKS URL.
async fn verification_keys(api: &Api, token: &str) -> Result<Value> {
    let header = token
        .split('.')
        .next()
        .ok_or_else(|| Failure::assertion("JWT header missing."))?;
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .safe("Invalid JWT header encoding.")?,
    )
    .safe("Invalid JWT header.")?;
    let kid = text_field(&header, "kid")?;
    let cached = keys(api, false).await?;
    let known = cached
        .get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| keys.iter().any(|key| value(key, "kid") == kid));
    if known {
        Ok(cached)
    } else {
        keys(api, true).await
    }
}

/// Checks exact delegated and identity claims plus durable hashes from a real runtime-role exchange.
pub(super) async fn public_claims(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    snapshot(context, fixture, &request, &code).await?;
    context.gateway.replica_b();
    let client = fixture.app()?.public.client_id.to_string();
    let mut input = fields(&code, &client, &context.gateway.callback, &request.verifier).to_vec();
    input.push(("vendor_extension", "ignored"));
    input.push(("nonce", "cannot-replace-saved-nonce"));
    input.push(("resource", "cannot-replace-resource"));
    input.push(("audience", "cannot-replace-audience"));
    let body = response(context.api.token(&input, None).await?, StatusCode::OK).await?;
    claims(context, fixture, &request, &code, &body).await?;
    failure(
        context
            .api
            .token(
                &fields(&code, &client, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await
}

/// Independently validates time/audiences/nonce/tenant/exact scopes and hash-only committed receipt.
async fn claims(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
    body: &Value,
) -> Result<()> {
    let access = text_field(body, "access_token")?;
    let id = text_field(body, "id_token")?;
    let keys = verification_keys(context.api, &access).await?;
    let (_, claims) = verify(&access, &keys, "at+jwt")?;
    let (_, identity) = verify(&id, &keys, "JWT")?;
    let client = fixture.app()?.public.client_id.to_string();
    let user = context
        .api
        .user_id
        .ok_or_else(|| Failure::harness("Missing user."))?
        .to_string();
    check(
        value(body, "token_type") == "Bearer"
            && value(body, "scope") == request.scopes.join(" ")
            && body.get("refresh_token").is_none(),
        "Token response widened consent.",
    )?;
    check(
        value(&claims, "iss") == context.api.origin
            && value(&claims, "aud") == "scenario-api"
            && value(&claims, "sub") == user
            && value(&claims, "client_id") == client
            && value(&claims, "organization_id") == fixture.org.id.to_string()
            && value(&claims, "application_id") == fixture.app()?.resource.id.to_string()
            && value(&claims, "scope") == request.scopes.join(" "),
        "Access authority differs from consent.",
    )?;
    let iat = value(&claims, "iat")
        .as_i64()
        .ok_or_else(|| Failure::assertion("Missing issued time."))?;
    let exp = value(&claims, "exp")
        .as_i64()
        .ok_or_else(|| Failure::assertion("Missing expiration."))?;
    check(
        exp - iat
            == value(body, "expires_in")
                .as_i64()
                .ok_or_else(|| Failure::assertion("Missing TTL."))?
            && exp - iat == context.access_token_ttl_seconds
            && iat <= chrono::Utc::now().timestamp()
            && exp > chrono::Utc::now().timestamp(),
        "Token expiration policy incorrect.",
    )?;
    let digest = Sha256::digest(access.as_bytes());
    check(
        value(&identity, "iss") == context.api.origin
            && value(&identity, "sub") == user
            && value(&identity, "aud") == client
            && value(&identity, "nonce") == request.nonce
            && value(&identity, "at_hash")
                == URL_SAFE_NO_PAD.encode(
                    digest
                        .get(..16)
                        .ok_or_else(|| Failure::harness("Invalid digest."))?,
                )
            && value(&identity, "exp")
                .as_i64()
                .zip(value(&identity, "iat").as_i64())
                .is_some_and(|(e, i)| e - i == 300),
        "OIDC claims or token binding incorrect.",
    )?;
    let hash = Sha256::digest(code.as_bytes()).to_vec();
    let auth_time: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT auth_time FROM oauth_authorization_codes WHERE code_hash=$1")
            .bind(&hash)
            .fetch_one(context.pool)
            .await
            .safe("Cannot inspect auth time.")?;
    check(
        value(&identity, "auth_time") == auth_time.timestamp(),
        "OIDC auth time changed.",
    )?;
    let receipt:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_token_issuances WHERE code_hash=$1 AND access_token_hash=$2 AND id_token_hash=$3 AND access_jti=$4 AND organization_id=$5 AND user_id=$6)")
        .bind(hash).bind(Sha256::digest(access.as_bytes()).to_vec()).bind(Sha256::digest(id.as_bytes()).to_vec())
        .bind(Uuid::parse_str(&text_field(&claims,"jti")?).safe("Invalid token identifier.")?).bind(fixture.org.id).bind(context.api.user_id).fetch_one(context.pool).await.safe("Cannot inspect token receipt.")?;
    check(receipt, "Token hashes/context not durably committed.")?;
    let response = context
        .api
        .client
        .get(format!("{}/v1/orgs", context.api.origin))
        .bearer_auth(&access)
        .send()
        .await
        .safe("Internal boundary request failed.")?;
    check(
        response.status() == StatusCode::UNAUTHORIZED,
        "OAuth JWT became internal session authority.",
    )
}

/// Exercises form/authority and wrong client/redirect/verifier negatives with a valid retry control.
pub(super) async fn validation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    let client = fixture.app()?.public.client_id.to_string();
    for (redirect, verifier) in [
        (
            format!("{}/suffix", context.gateway.callback),
            request.verifier.clone(),
        ),
        (context.gateway.callback.clone(), "short".into()),
        (context.gateway.callback.clone(), "a".repeat(43)),
    ] {
        failure(
            context
                .api
                .token(&fields(&code, &client, &redirect, &verifier), None)
                .await?,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        )
        .await?;
    }
    failure(
        context
            .api
            .token(
                &fields(
                    &code,
                    &fixture.app()?.confidential.client_id.to_string(),
                    &context.gateway.callback,
                    &request.verifier,
                ),
                None,
            )
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_client",
    )
    .await?;
    for extra in [
        ("scope", "platform:admin"),
        ("organization_id", "foreign"),
        ("code", "duplicate"),
        ("client_secret", "unsafe"),
    ] {
        let mut input =
            fields(&code, &client, &context.gateway.callback, &request.verifier).to_vec();
        input.push(extra);
        failure(
            context.api.token(&input, None).await?,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await?;
    }
    let wrong = Uuid::new_v4().to_string();
    failure(
        context
            .api
            .token(
                &fields(&code, &wrong, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_client",
    )
    .await?;
    foreign_code_rejected(context, &request, &code).await?;
    let _ = response(
        context
            .api
            .token(
                &fields(&code, &client, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    without_identity(context, fixture, &client).await
}

/// Another active public client in a fresh organization cannot redeem the original tenant's code.
async fn foreign_code_rejected(context: &Context<'_>, request: &Request, code: &str) -> Result<()> {
    let foreign =
        Fixture::create(context.api, context.manifest, 2, &context.gateway.callback).await?;
    let client = foreign.app()?.public.client_id.to_string();
    failure(
        context
            .api
            .token(
                &fields(code, &client, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await
}

/// Current client disablement or irrevocably lost consent is rejected through real HTTP too.
pub(super) async fn reject_lifecycle(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
) -> Result<()> {
    let client = fixture.app()?.public.client_id;
    let inactive:bool=sqlx::query_scalar("SELECT disabled_at IS NOT NULL OR deleted_at IS NOT NULL FROM oauth_clients WHERE client_id=$1").bind(client).fetch_one(context.pool).await.safe("Cannot inspect client lifecycle.")?;
    failure(
        context
            .api
            .token(
                &fields(
                    code,
                    &client.to_string(),
                    &context.gateway.callback,
                    &request.verifier,
                ),
                None,
            )
            .await?,
        StatusCode::BAD_REQUEST,
        if inactive {
            "invalid_client"
        } else {
            "invalid_grant"
        },
    )
    .await
}

/// Fresh consent after restoration must actually issue signed tokens, not merely pass domain checks.
pub(super) async fn commit_lifecycle(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
) -> Result<()> {
    let body = response(
        context
            .api
            .token(
                &fields(
                    code,
                    &fixture.app()?.public.client_id.to_string(),
                    &context.gateway.callback,
                    &request.verifier,
                ),
                None,
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    claims(context, fixture, request, code, &body).await
}

/// Non-OIDC delegated requests never gain an ID token at exchange.
async fn without_identity(
    context: &mut Context<'_>,
    fixture: &Fixture,
    client: &str,
) -> Result<()> {
    let mut request = Request::new(context, fixture)?;
    request.scopes.retain(|s| s != "openid");
    request
        .labels
        .retain(|s| s != "Sign in and identify your account");
    request.url = request.changed("scope", Some(&request.scopes.join(" ")));
    request.url = request.changed("nonce", None);
    request.url = request.changed("prompt", Some("consent"));
    let code = issue(context, &request).await?;
    let body = response(
        context
            .api
            .token(
                &fields(&code, client, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    check(
        body.get("id_token").is_none() && value(&body, "scope") == request.scopes.join(" "),
        "Exchange added identity or scope authority.",
    )
}

/// Confidential credentials authenticate only their exact client; rotation does not bypass S256.
pub(super) async fn confidential(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let app = fixture.app()?;
    let client = app.confidential.client_id.to_string();
    let redirect = format!("{}/client-callback", context.api.origin);
    let path = format!("{}/oauth/clients/{client}/secrets", app.path);
    let first: Value = context
        .api
        .json(Method::POST, &path, Some(json!({})), StatusCode::CREATED)
        .await?;
    let secret = text_field(&first, "client_secret")?;
    let id = first
        .pointer("/credential/id")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::harness("Missing credential ID."))?;
    let request = confidential_request(context, fixture, &client, &redirect)?;
    let code = issue_for(context, &request, &redirect).await?;
    context.gateway.replica_b();
    authentication_negatives(context, &code, &client, &redirect, &request.verifier).await?;
    let current: Value = context
        .api
        .json(
            Method::POST,
            &format!("{path}/rotate"),
            Some(json!({"current_secret_id":id})),
            StatusCode::CREATED,
        )
        .await?;
    let basic = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));
    failure(
        context
            .api
            .token(&fields(&code, &client, &redirect, "short"), Some(&basic))
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    let _ = response(
        context
            .api
            .token(
                &fields(&code, &client, &redirect, &request.verifier),
                Some(&basic),
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    let code = issue_for(context, &request, &redirect).await?;
    context
        .api
        .status(
            Method::DELETE,
            &format!("{path}/{id}"),
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
    failure(
        context
            .api
            .token(
                &fields(&code, &client, &redirect, &request.verifier),
                Some(&basic),
            )
            .await?,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
    )
    .await?;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{client}:{}",
            text_field(&current, "client_secret")?
        ))
    );
    let _ = response(
        context
            .api
            .token(
                &fields(&code, &client, &redirect, &request.verifier),
                Some(&basic),
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

/// A confidential client cannot authenticate with none or a malformed/wrong Basic secret.
async fn authentication_negatives(
    context: &Context<'_>,
    code: &str,
    client: &str,
    redirect: &str,
    verifier: &str,
) -> Result<()> {
    failure(
        context
            .api
            .token(&fields(code, client, redirect, verifier), None)
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_client",
    )
    .await?;
    let bad = format!("Basic {}", STANDARD.encode(format!("{client}:wrong")));
    failure(
        context
            .api
            .token(&fields(code, client, redirect, verifier), Some(&bad))
            .await?,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
    )
    .await?;
    Ok(())
}

/// Builds only registry-approved confidential authority with explicit browser consent.
fn confidential_request(
    context: &Context<'_>,
    fixture: &Fixture,
    client: &str,
    redirect: &str,
) -> Result<Request> {
    let app = fixture.app()?;
    let mut request = Request::new(context, fixture)?;
    request.scopes = vec![
        app.scopes
            .first()
            .ok_or_else(|| Failure::harness("Missing scope."))?
            .clone(),
    ];
    request.labels = vec![
        app.descriptions
            .first()
            .ok_or_else(|| Failure::harness("Missing label."))?
            .clone(),
    ];
    request.url = request.changed("client_id", Some(client));
    request.url = request.changed("redirect_uri", Some(redirect));
    request.url = request.changed("scope", Some(&request.scopes.join(" ")));
    request.url = request.changed("nonce", None);
    request.url = request.changed("prompt", Some("consent"));
    Ok(request)
}

/// Races two actual processes using pinned private sockets, requiring one committed receipt.
pub(super) async fn race(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    let client = fixture.app()?.public.client_id.to_string();
    let input = fields(&code, &client, &context.gateway.callback, &request.verifier);
    let (a, b) = tokio::join!(
        context.gateway.token_replica(false, &input),
        context.gateway.token_replica(true, &input)
    );
    let a = a?;
    let b = b?;
    check(
        (a.status() == StatusCode::OK && b.status() == StatusCode::BAD_REQUEST)
            || (b.status() == StatusCode::OK && a.status() == StatusCode::BAD_REQUEST),
        "Concurrent exchange lacked exactly one winner.",
    )?;
    let (winner, loser) = if a.status() == StatusCode::OK {
        (a, b)
    } else {
        (b, a)
    };
    let body = response(winner, StatusCode::OK).await?;
    failure(loser, StatusCode::BAD_REQUEST, "invalid_grant").await?;
    claims(context, fixture, &request, &code, &body).await?;
    failure(
        context.gateway.token_replica(true, &input).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_token_issuances WHERE code_hash=$1")
            .bind(Sha256::digest(code.as_bytes()).to_vec())
            .fetch_one(context.pool)
            .await
            .safe("Cannot count committed receipts.")?;
    check(
        count == 1,
        "Concurrent exchange committed duplicate receipts.",
    )
}

/// Denies real transit signing, verifies rollback, restores permission, then rotates the shared key.
pub(super) async fn signing(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    let client = fixture.app()?.public.client_id.to_string();
    let original_keys = keys(context.api, false).await?;
    context.gateway.replica_b();
    let _ = keys(context.api, false).await?;
    context.infrastructure.signing_allowed(false).await?;
    let failed = context
        .api
        .token(
            &fields(&code, &client, &context.gateway.callback, &request.verifier),
            None,
        )
        .await;
    context.infrastructure.signing_allowed(true).await?;
    failure(
        failed?,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await?;
    let untouched:bool=sqlx::query_scalar("SELECT consumed_at IS NULL AND expires_at>clock_timestamp() FROM oauth_authorization_codes WHERE code_hash=$1").bind(Sha256::digest(code.as_bytes()).to_vec()).fetch_one(context.pool).await.safe("Cannot inspect failed exchange.")?;
    check(untouched, "Vault failure consumed/expired the code.")?;
    let original = response(
        context
            .api
            .token(
                &fields(&code, &client, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    let old_access = text_field(&original, "access_token")?;
    let (old_header, _) = verify(&old_access, &original_keys, "at+jwt")?;
    context.infrastructure.rotate_oidc_key().await?;
    context.gateway.replica_a();
    let mut request = Request::new(context, fixture)?;
    request.url = request.changed("prompt", Some("consent"));
    let code = issue(context, &request).await?;
    let body = response(
        context
            .api
            .token(
                &fields(&code, &client, &context.gateway.callback, &request.verifier),
                None,
            )
            .await?,
        StatusCode::OK,
    )
    .await?;
    context.gateway.replica_b();
    let refreshed = keys(context.api, true).await?;
    let (new_header, _) = verify(&text_field(&body, "access_token")?, &refreshed, "at+jwt")?;
    check(
        value(&new_header, "kid") != value(&old_header, "kid"),
        "Rotation reused the old signing key.",
    )?;
    let _ = verify(&old_access, &refreshed, "at+jwt")?;
    let _ = verify(&text_field(&body, "id_token")?, &refreshed, "JWT")?;
    Ok(())
}
