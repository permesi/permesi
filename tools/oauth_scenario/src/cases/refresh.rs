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
use uuid::Uuid;

/// Exact fixture-owned refresh authority; internal permissions never supply any expected scope.
struct RefreshAuthority {
    issuer: String,
    audience: String,
    user: Uuid,
    client: Uuid,
    organization: Uuid,
    application: Uuid,
    scope: String,
    ttl: i64,
}

impl RefreshAuthority {
    /// Rejects signed-but-substituted context, widened scopes, fabricated identity tokens and invalid lifetimes.
    fn validate(&self, claims: &Value, body: &Value, now: i64) -> Result<()> {
        check(
            claims.get("iss") == Some(&json!(self.issuer))
                && claims.get("aud") == Some(&json!(self.audience))
                && claims.get("sub") == Some(&json!(self.user))
                && claims.get("client_id") == Some(&json!(self.client))
                && claims.get("organization_id") == Some(&json!(self.organization))
                && claims.get("application_id") == Some(&json!(self.application))
                && claims.get("scope") == Some(&json!(self.scope))
                && body.get("scope") == Some(&json!(self.scope))
                && body.get("token_type") == Some(&json!("Bearer"))
                && body.get("id_token").is_none()
                && body.get("expires_in") == Some(&json!(self.ttl)),
            "Refresh race changed protocol or delegated authority.",
        )?;
        let issued = claims.get("iat").and_then(Value::as_i64);
        let expires = claims.get("exp").and_then(Value::as_i64);
        check(
            issued.zip(expires).is_some_and(|(issued, expires)| {
                issued <= now && expires > now && expires.checked_sub(issued) == Some(self.ttl)
            }),
            "Refresh race changed token lifetime.",
        )
    }
}

/// Independently checks a race winner's signature, exact authority, lineage and loser-driven family revocation.
/// This runs before the test itself replays either token, so replay assertions cannot cause the expected revocation.
pub(super) async fn race_authority(
    context: &Context<'_>,
    fixture: &Fixture,
    original: &str,
    body: &Value,
) -> Result<()> {
    let app = fixture.app()?;
    let expected = RefreshAuthority {
        issuer: context.api.origin.clone(),
        audience: context
            .policy
            .audience
            .clone()
            .ok_or_else(|| Failure::harness("Missing resource audience."))?,
        user: context
            .api
            .user_id
            .ok_or_else(|| Failure::harness("Missing fixture user."))?,
        client: app.public.client_id,
        organization: fixture.org.id,
        application: app.resource.id,
        scope: format!(
            "openid {} offline_access",
            app.scopes
                .first()
                .ok_or_else(|| Failure::harness("Missing fixture scope."))?
        ),
        ttl: context.access_token_ttl_seconds,
    };
    let access = text_field(body, "access_token")?;
    let keys = token::verification_keys(context.api, &access).await?;
    let (_, claims) = token::verify(&access, &keys, "at+jwt")?;
    expected.validate(&claims, body, chrono::Utc::now().timestamp())?;
    let successor = text_field(body, "refresh_token")?;
    let revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id WHERE t.token_hash=$1 AND t.previous_hash=$2 AND f.organization_id=$3 AND f.application_id=$4 AND f.user_id=$5 AND f.client_id=$6 AND f.revoked_at IS NOT NULL AND f.revocation_reason='reuse')")
        .bind(Sha256::digest(successor.as_bytes()).to_vec())
        .bind(Sha256::digest(original.as_bytes()).to_vec())
        .bind(expected.organization).bind(expected.application).bind(expected.user).bind(expected.client)
        .fetch_one(context.pool).await.safe("Cannot inspect refresh race lineage and revocation.")?;
    check(
        revoked,
        "Refresh race lost lineage or did not revoke its family before replay.",
    )
}

/// Adds offline access to this case's allow-list and requests a fresh, visibly explicit consent.
pub(super) async fn root(context: &mut Context<'_>, fixture: &Fixture) -> Result<Value> {
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
pub(super) fn fields<'a>(client: &'a str, token: &'a str) -> [(&'a str, &'a str); 3] {
    [
        ("grant_type", "refresh_token"),
        ("client_id", client),
        ("refresh_token", token),
    ]
}

/// Issues on A/B and rotates on C, independently verifies claims, then rejects successors after replay.
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
        context.gateway.token_on_replica(2, &input).await?,
        StatusCode::OK,
    )
    .await?;
    context.gateway.replica_c();
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

/// Every configured socket participates; losing reuses revoke the committed successor too.
pub(super) async fn race(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let body = root(context, fixture).await?;
    let original = text_field(&body, "refresh_token")?;
    let client = fixture.app()?.public.client_id.to_string();
    let input = fields(&client, &original);
    let replicas = (0..context.gateway.replica_count()).collect::<Vec<_>>();
    let winner = token::one_winner(context.gateway.race_tokens(&replicas, &input).await?).await?;
    let next = text_field(&winner, "refresh_token")?;
    race_authority(context, fixture, &original, &winner).await?;
    for replica in replicas {
        token::failure(
            context
                .gateway
                .token_on_replica(replica, &fields(&client, &next))
                .await?,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        )
        .await?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Signature validity alone cannot accept a changed issuer/client/tenant/scope or expired refresh result.
    #[test]
    fn race_authority_rejects_substitution_widening_and_invalid_lifetimes() -> Result<()> {
        let expected = RefreshAuthority {
            issuer: "https://issuer.example".into(),
            audience: "jobs-api".into(),
            user: Uuid::from_u128(1),
            client: Uuid::from_u128(2),
            organization: Uuid::from_u128(3),
            application: Uuid::from_u128(4),
            scope: "openid jobs:read offline_access".into(),
            ttl: 10,
        };
        let claims = json!({"iss":"https://issuer.example","aud":"jobs-api",
            "sub":Uuid::from_u128(1),"client_id":Uuid::from_u128(2),
            "organization_id":Uuid::from_u128(3),"application_id":Uuid::from_u128(4),
            "scope":"openid jobs:read offline_access","iat":100,"exp":110});
        let body = json!({"token_type":"Bearer","scope":"openid jobs:read offline_access","expires_in":10});
        expected.validate(&claims, &body, 100)?;
        for (field, substitution) in [
            ("iss", json!("https://foreign.example")),
            ("aud", json!(["jobs-api"])),
            ("sub", json!(Uuid::from_u128(5))),
            ("client_id", json!(Uuid::from_u128(5))),
            ("organization_id", json!(Uuid::from_u128(5))),
            ("application_id", json!(Uuid::from_u128(5))),
            ("scope", json!("platform:admin")),
            ("iat", json!(101)),
            ("exp", json!(100)),
        ] {
            let mut changed = claims.clone();
            *changed
                .get_mut(field)
                .ok_or_else(|| Failure::harness("Missing claim fixture."))? = substitution;
            assert!(
                expected.validate(&changed, &body, 100).is_err(),
                "Substitution accepted for {field}"
            );
            changed
                .as_object_mut()
                .ok_or_else(|| Failure::harness("Invalid claim fixture."))?
                .remove(field);
            assert!(
                expected.validate(&changed, &body, 100).is_err(),
                "Missing claim accepted for {field}"
            );
        }
        for (field, substitution) in [
            ("token_type", json!("MAC")),
            ("scope", json!("openid jobs:read jobs:write offline_access")),
            ("expires_in", json!(11)),
            ("id_token", Value::Null),
        ] {
            let mut changed = body.clone();
            changed
                .as_object_mut()
                .ok_or_else(|| Failure::harness("Invalid response fixture."))?
                .insert(field.into(), substitution);
            assert!(expected.validate(&claims, &changed, 100).is_err());
        }
        assert!(expected.validate(&claims, &body, 110).is_err());
        Ok(())
    }
}
