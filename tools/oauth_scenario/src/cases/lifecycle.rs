//! Lifecycle changes must invalidate pending approval and previously issued authority.
//!
//! Flow Overview: start consent or issue a real code on A, commit a management
//! mutation through B, then validate the old state on A or an independent pool.
//! Restoration requires fresh consent/code; a new grant cannot resurrect an old
//! code. Only the existing management APIs mutate authority. SQL assertions are
//! read-only; redemption remains the internal administrator-pool domain API.

use super::{Context, Request, begin, callback, issue, redeem, snapshot};
use crate::{
    client::Fixture,
    error::{Result, Safe, check},
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use url::Url;
use uuid::Uuid;

/// Existing API lifecycle operations; these never change authentication or token policy.
#[derive(Clone, Copy)]
pub(super) enum Mutation {
    Client,
    Scopes,
    Redirects,
}

impl Mutation {
    /// Commits a mutation on B and independently reads it back before testing stale state.
    /// Restoration restores configuration only, never saved consent or issued codes.
    async fn apply(self, context: &Context<'_>, fixture: &Fixture, restore: bool) -> Result<()> {
        context.gateway.replica_b();
        let app = fixture.app()?;
        let client_path = format!("{}/oauth/clients/{}", app.path, app.public.client_id);
        match self {
            Self::Client => {
                let _: Value = context
                    .api
                    .json(
                        Method::PATCH,
                        &client_path,
                        Some(json!({"disabled":!restore})),
                        StatusCode::OK,
                    )
                    .await?;
                let current: Value = context
                    .api
                    .json(Method::GET, &client_path, None, StatusCode::OK)
                    .await?;
                check(
                    current
                        .get("disabled_at")
                        .is_some_and(|v| if restore { v.is_null() } else { v.is_string() }),
                    "Client lifecycle mutation did not round-trip.",
                )
            }
            Self::Scopes => {
                let mut scopes = vec!["openid".to_owned(), "profile".to_owned()];
                if restore {
                    scopes.push(
                        app.scopes
                            .first()
                            .ok_or_else(|| crate::error::Failure::harness("Missing custom scope."))?
                            .clone(),
                    );
                }
                replace_list(context, &format!("{client_path}/scopes"), "scopes", scopes).await
            }
            Self::Redirects => {
                let mut redirects = vec![format!("{}/alternate", context.gateway.callback)];
                if restore {
                    redirects.push(context.gateway.callback.clone());
                }
                replace_list(
                    context,
                    &format!("{client_path}/redirect-uris"),
                    "redirect_uris",
                    redirects,
                )
                .await
            }
        }
    }
}

/// Replaces an exact allow-list through the API, then verifies a separate GET.
async fn replace_list(
    context: &Context<'_>,
    path: &str,
    field: &str,
    mut expected: Vec<String>,
) -> Result<()> {
    let _: Vec<String> = context
        .api
        .json(
            Method::PUT,
            path,
            Some(json!({field:expected})),
            StatusCode::OK,
        )
        .await?;
    let mut current: Vec<String> = context
        .api
        .json(Method::GET, path, None, StatusCode::OK)
        .await?;
    current.sort();
    expected.sort();
    check(
        current == expected,
        "Lifecycle allow-list mutation did not round-trip.",
    )
}

/// Shows consent on A, mutates through B, and submits the original real form on A.
/// Invalid approval cannot issue a code; removed redirects receive no error navigation.
pub(super) async fn pending_consent(
    context: &mut Context<'_>,
    fixture: &Fixture,
    mutation: Mutation,
) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let page = begin(context, &request, "owner").await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("consent"),
        "Lifecycle test did not start with real consent.",
    )?;
    no_codes(context, fixture).await?;
    mutation.apply(context, fixture, false).await?;
    context.gateway.replica_a();
    let denied = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"allow"}))
        .await?;
    match mutation {
        Mutation::Scopes => check(
            callback(&denied, &context.gateway.callback, &request.state, "error")?
                == "invalid_scope",
            "Removed scope was not rejected through the validated callback.",
        )?,
        Mutation::Client | Mutation::Redirects => direct_error(context, &denied)?,
    }
    no_codes(context, fixture).await?;
    mutation.apply(context, fixture, true).await?;
    let fresh = Request::new(context, fixture)?;
    let code = issue(context, &fresh).await?;
    snapshot(context, fixture, &fresh, &code).await?;
    check(
        redeem(
            context.pool,
            context.policy,
            fixture,
            &fresh,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Restored configuration did not permit a fresh consented code.",
    )
}

/// Requires a terminal issuer error with no Location header, excluding timeout or UI failure.
fn direct_error(context: &Context<'_>, result: &Value) -> Result<()> {
    let location = result
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::error::Failure::assertion("Direct error omitted issuer location."))?;
    let location = Url::parse(location).safe("Invalid direct-error location.")?;
    let issuer = Url::parse(&context.api.origin).safe("Invalid generated issuer.")?;
    check(
        result.get("stage").and_then(Value::as_str) == Some("protocol_error")
            && result.get("status").and_then(Value::as_u64) == Some(400)
            && result.get("has_location_header").and_then(Value::as_bool) == Some(false)
            && result.get("had_redirect").and_then(Value::as_bool) == Some(false)
            && location.origin() == issuer.origin()
            && location.path() == "/authorize/consent",
        "Invalid lifecycle approval escaped the issuer or lacked a direct protocol error.",
    )
}

/// Counts the case's exact client only; denied approval must not leave any issued code.
async fn no_codes(context: &Context<'_>, fixture: &Fixture) -> Result<()> {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_codes WHERE client_id=$1")
            .bind(fixture.app()?.public.id)
            .fetch_one(context.pool)
            .await
            .safe("Cannot count lifecycle authorization codes.")?;
    check(count == 0, "Denied lifecycle approval issued a code.")
}

/// A private immutable row snapshot, used only for equality assertions, never diagnostics.
struct OriginalCode {
    record: String,
    grant: Uuid,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl OriginalCode {
    /// Confirms an unconsumed live code before mutation; expiry cannot supply a false negative.
    async fn read(pool: &PgPool, code: &str) -> Result<Self> {
        let row = sqlx::query("SELECT to_jsonb(c)::text AS record,c.grant_id,c.expires_at,c.consumed_at IS NULL AND c.expires_at>clock_timestamp() AS live FROM oauth_authorization_codes c WHERE c.code_hash=$1")
            .bind(Sha256::digest(code.as_bytes()).to_vec()).fetch_one(pool).await.safe("Cannot inspect original lifecycle code.")?;
        check(
            row.try_get("live").safe("Missing code liveness.")?,
            "Lifecycle code expired or was consumed before validation.",
        )?;
        Ok(Self {
            record: row
                .try_get("record")
                .safe("Missing original code snapshot.")?,
            grant: row
                .try_get("grant_id")
                .safe("Missing original grant binding.")?,
            expires_at: row
                .try_get("expires_at")
                .safe("Missing original code expiry.")?,
        })
    }

    /// Failed redemption leaves an unchanged live code or preserves the redirect FK's
    /// permanent removal. The original deadline and revoked grant exclude expiry/revival.
    async fn invalidated(&self, pool: &PgPool, code: &str, mutation: Mutation) -> Result<()> {
        let before_expiry: bool = sqlx::query_scalar("SELECT clock_timestamp() < $1")
            .bind(self.expires_at)
            .fetch_one(pool)
            .await
            .safe("Cannot verify original code deadline.")?;
        check(
            before_expiry,
            "Lifecycle rejection occurred after original code expiry.",
        )?;
        if matches!(mutation, Mutation::Redirects) {
            let absent: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS (SELECT 1 FROM oauth_authorization_codes WHERE code_hash=$1)",
            )
            .bind(Sha256::digest(code.as_bytes()).to_vec())
            .fetch_one(pool)
            .await
            .safe("Cannot inspect removed redirect code.")?;
            check(
                absent,
                "Redirect restoration resurrected an old authorization code.",
            )?;
        } else {
            let current = Self::read(pool, code).await?;
            check(
                current.record == self.record && current.grant == self.grant,
                "Lifecycle change consumed or rewrote the original code.",
            )?;
        }
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM oauth_grants WHERE id=$1")
                .bind(self.grant)
                .fetch_one(pool)
                .await
                .safe("Cannot inspect original consent revocation.")?;
        check(revoked, "Lifecycle change restored revoked consent.")
    }
}

/// Proves a real code is usable before mutation, rejected during/after restoration,
/// and still rejected after fresh consent creates a new grant. Only a new code commits.
pub(super) async fn restore_code(
    context: &mut Context<'_>,
    fixture: &Fixture,
    mutation: Mutation,
) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    snapshot(context, fixture, &request, &code).await?;
    let original = OriginalCode::read(context.pool, &code).await?;
    let independent = PgPool::connect(context.admin_dsn)
        .await
        .safe("Cannot connect independent lifecycle redeemer.")?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            false,
        )
        .await?,
        "Original lifecycle code was not redeemable before mutation.",
    )?;
    mutation.apply(context, fixture, false).await?;
    rejected(
        context,
        fixture,
        &independent,
        &request,
        &code,
        &original,
        mutation,
    )
    .await?;
    mutation.apply(context, fixture, true).await?;
    rejected(
        context,
        fixture,
        &independent,
        &request,
        &code,
        &original,
        mutation,
    )
    .await?;
    let fresh = Request::new(context, fixture)?;
    let fresh_code = issue(context, &fresh).await?;
    snapshot(context, fixture, &fresh, &fresh_code).await?;
    check(
        fresh_code != code,
        "Restoration reused a revoked authorization code.",
    )?;
    let replacement = OriginalCode::read(context.pool, &fresh_code).await?;
    check(
        replacement.grant != original.grant,
        "Fresh consent resurrected the revoked grant.",
    )?;
    rejected(
        context,
        fixture,
        &independent,
        &request,
        &code,
        &original,
        mutation,
    )
    .await?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &fresh,
            &fresh_code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Fresh consented lifecycle code could not commit.",
    )?;
    check(
        !redeem(
            &independent,
            context.policy,
            fixture,
            &fresh,
            &fresh_code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Fresh lifecycle code could be redeemed twice.",
    )?;
    independent.close().await;
    Ok(())
}

/// Checks the original deadline and irreversible invalidation before/after rejection.
async fn rejected(
    context: &Context<'_>,
    fixture: &Fixture,
    pool: &PgPool,
    request: &Request,
    code: &str,
    original: &OriginalCode,
    mutation: Mutation,
) -> Result<()> {
    original.invalidated(context.pool, code, mutation).await?;
    check(
        !redeem(
            pool,
            context.policy,
            fixture,
            request,
            code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Revoked lifecycle code was accepted by the independent redeemer.",
    )?;
    original.invalidated(context.pool, code, mutation).await
}
