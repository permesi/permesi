//! Real browser offline consent and runtime-role refresh exchanges on independent Permesi replicas.
//!
//! Each case provisions explicit client authority, approves the immutable consent form,
//! then uses cookie-free token requests. Independent signature/context and hash-history
//! assertions cover rotation, replay, concurrent family revocation and lifecycle changes.
use super::{Context, Request, check, issue, text_field, token};
use crate::{
    client::Fixture,
    error::{Failure, Result, Safe},
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Adds offline access to this case's allow-list and requests a fresh, visibly explicit consent.
async fn root(context: &mut Context<'_>, fixture: &Fixture) -> Result<Value> {
    let app = fixture.app()?;
    let mut request = Request::new(context, fixture)?;
    request.scopes.push("offline_access".into());
    request
        .labels
        .push("Maintain access while you are offline".into());
    let _: Value = context
        .api
        .json(
            Method::PUT,
            &format!("{}/oauth/clients/{}/scopes", app.path, app.public.client_id),
            Some(json!({"scopes":request.scopes})),
            StatusCode::OK,
        )
        .await?;
    request.url = request.changed("scope", Some(&request.scopes.join(" ")));
    request.url = request.changed("prompt", Some("consent"));
    context.gateway.replica_a();
    let code = issue(context, &request).await?;
    context.gateway.replica_b();
    let client = app.public.client_id.to_string();
    let input = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("client_id", &client),
        ("redirect_uri", &context.gateway.callback),
        ("code_verifier", &request.verifier),
    ];
    let body = token::response(context.api.token(&input, None).await?, StatusCode::OK).await?;
    check(
        body.get("id_token").is_some() && body.get("refresh_token").is_some(),
        "Offline consent did not issue initial tokens.",
    )?;
    Ok(body)
}

/// Refresh input cannot carry organization, grant, resource or internal permissions.
fn fields<'a>(client: &'a str, token: &'a str) -> [(&'a str, &'a str); 3] {
    [
        ("grant_type", "refresh_token"),
        ("client_id", client),
        ("refresh_token", token),
    ]
}

/// Rotates across A/B, independently verifies narrow claims, then rejects every successor after replay.
pub(super) async fn rotation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let body = root(context, fixture).await?;
    let original = text_field(&body, "refresh_token")?;
    let client = fixture.app()?.public.client_id.to_string();
    let scope = fixture
        .app()?
        .scopes
        .first()
        .ok_or_else(|| Failure::harness("Missing scope."))?;
    let mut input = fields(&client, &original).to_vec();
    input.push(("scope", scope));
    let rotated = token::response(
        context.gateway.token_replica(false, &input).await?,
        StatusCode::OK,
    )
    .await?;
    let access = text_field(&rotated, "access_token")?;
    let keys = token::verification_keys(context.api, &access).await?;
    let (_, claims) = token::verify(&access, &keys, "at+jwt")?;
    check(
        claims.get("scope") == Some(&json!(scope))
            && claims.get("organization_id") == Some(&json!(fixture.org.id))
            && claims.get("application_id") == Some(&json!(fixture.app()?.resource.id))
            && claims.get("sub") == Some(&json!(context.api.user_id))
            && rotated.get("id_token").is_none(),
        "Refresh changed tenant, user, scope or fabricated an ID token.",
    )?;
    let next = text_field(&rotated, "refresh_token")?;
    check(next != original, "Refresh did not rotate bearer material.")?;
    let stored:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id WHERE t.token_hash=$1 AND t.previous_hash=$2 AND f.organization_id=$3 AND f.application_id=$4 AND f.user_id=$5 AND f.revoked_at IS NULL)")
        .bind(Sha256::digest(next.as_bytes()).to_vec()).bind(Sha256::digest(original.as_bytes()).to_vec()).bind(fixture.org.id).bind(fixture.app()?.resource.id).bind(context.api.user_id).fetch_one(context.pool).await.safe("Cannot inspect refresh lineage.")?;
    check(stored, "Refresh lineage was not durably bound.")?;
    token::failure(
        context
            .gateway
            .token_replica(true, &fields(&client, &original))
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    token::failure(
        context
            .gateway
            .token_replica(false, &fields(&client, &next))
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await
}

/// Two real socket backends share one winner; the losing reuse revokes the committed successor too.
pub(super) async fn race(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let body = root(context, fixture).await?;
    let original = text_field(&body, "refresh_token")?;
    let client = fixture.app()?.public.client_id.to_string();
    let input = fields(&client, &original);
    let (a, b) = tokio::join!(
        context.gateway.token_replica(false, &input),
        context.gateway.token_replica(true, &input)
    );
    let a = a?;
    let b = b?;
    check(
        (a.status() == StatusCode::OK && b.status() == StatusCode::BAD_REQUEST)
            || (b.status() == StatusCode::OK && a.status() == StatusCode::BAD_REQUEST),
        "Refresh race did not have exactly one winner.",
    )?;
    let (winner, loser) = if a.status() == StatusCode::OK {
        (a, b)
    } else {
        (b, a)
    };
    let winner = token::response(winner, StatusCode::OK).await?;
    token::failure(loser, StatusCode::BAD_REQUEST, "invalid_grant").await?;
    let next = text_field(&winner, "refresh_token")?;
    token::failure(
        context
            .gateway
            .token_replica(true, &fields(&client, &next))
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_token_issuances WHERE refresh_hash=$1")
            .bind(Sha256::digest(original.as_bytes()).to_vec())
            .fetch_one(context.pool)
            .await
            .safe("Cannot count refresh receipts.")?;
    check(
        count == 1,
        "Refresh race committed duplicate access issuance.",
    )
}

/// Removing/reinstating client authority through real management APIs cannot resurrect a family.
pub(super) async fn lifecycle(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let body = root(context, fixture).await?;
    let original = text_field(&body, "refresh_token")?;
    let app = fixture.app()?;
    let client = app.public.client_id.to_string();
    let path = format!("{}/oauth/clients/{client}/scopes", app.path);
    let _: Value = context
        .api
        .json(
            Method::PUT,
            &path,
            Some(json!({"scopes":["openid","offline_access"]})),
            StatusCode::OK,
        )
        .await?;
    token::failure(
        context
            .gateway
            .token_replica(true, &fields(&client, &original))
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    let _:Value=context.api.json(Method::PUT,&path,Some(json!({"scopes":["openid","offline_access",app.scopes.first().ok_or_else(||Failure::harness("Missing scope."))?]})),StatusCode::OK).await?;
    token::failure(
        context
            .gateway
            .token_replica(false, &fields(&client, &original))
            .await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await
}
