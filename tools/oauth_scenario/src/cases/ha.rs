//! Real process replacement and backend outage against shared authorization state.
//!
//! Flow Overview: create genuine browser consent and OPAQUE proofs, stop only an
//! owned child, verify survivors and fail-closed routing, then restart with identical
//! configuration. Independent JWT/hash-history assertions prove authority survives
//! replacement while replay stays rejected. Runtime supervision journals new children
//! before readiness and restores stopped slots after case failures. Whole-run
//! cancellation retains every child handle for unconditional cleanup.

use super::{Context, Request, issue, refresh, snapshot, token};
use crate::{
    client::{Api, Fixture, PasswordFlow, text_field},
    error::{Result, Safe, check},
    services::StopMode,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Replaces every configured process, keeping sessions and pending authority bound to the original user/client/tenant.
pub async fn rolling_restart(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let anonymous = Api::anonymous(context.api.origin.clone(), context.api.client.clone());
    let client = fixture.app()?.public.client_id.to_string();
    let count = context.gateway.replica_count();
    for replica in 0..count {
        context.gateway.select_replica(replica)?;
        let mut request = Request::new(context, fixture)?;
        request.url = request.changed("prompt", Some("consent"));
        let code = issue(context, &request).await?;
        snapshot(context, fixture, &request, &code).await?;
        let proof = context
            .owner
            .password_proof(&anonymous, PasswordFlow::Login)
            .await?;
        let elevation = context
            .owner
            .password_proof(context.api, PasswordFlow::Reauthenticate)
            .await?;
        let previous = context.services.identity(replica)?;
        context
            .services
            .stop_replica(replica, StopMode::Graceful)
            .await?;
        unavailable(context).await?;
        context.gateway.select_replica((replica + 1) % count)?;
        original_session(context).await?;
        let response = proof.finish(&anonymous).await?;
        let session = anonymous.authenticated_response(&response).await?;
        check(
            session.user_id == context.api.user_id,
            "Rolling login changed user identity.",
        )?;
        context.services.restart_replica(replica).await?;
        let current = context.services.identity(replica)?;
        check(
            previous.pid != current.pid || previous.start_ticks != current.start_ticks,
            "Rolling replacement reused the old process.",
        )?;
        println!("Restarted Permesi replica {}/{}.", replica + 1, count);
        context.gateway.select_replica(replica)?;
        check(
            proof.finish(&anonymous).await?.status() == StatusCode::UNAUTHORIZED,
            "Restart restored a spent OPAQUE exchange.",
        )?;
        check(
            elevation.finish(context.api).await?.status() == StatusCode::NO_CONTENT,
            "Restart lost pending reauthentication state.",
        )?;
        context.gateway.select_replica((replica + 1) % count)?;
        check(
            elevation.finish(context.api).await?.status() == StatusCode::UNAUTHORIZED,
            "Restart allowed reauthentication replay.",
        )?;
        context.gateway.select_replica(replica)?;
        original_session(context).await?;
        let input = token::fields(&code, &client, &context.gateway.callback, &request.verifier);
        let body = token::response(
            context.gateway.token_on_replica(replica, &input).await?,
            StatusCode::OK,
        )
        .await?;
        token::claims(context, fixture, &request, &code, &body).await?;
        for other in 0..count {
            token::failure(
                context.gateway.token_on_replica(other, &input).await?,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
            )
            .await?;
        }
    }
    Ok(())
}

/// Loses the last backend before redemption, then verifies surviving code/refresh races and recovered replay rejection.
pub async fn replica_outage(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    // Independent tenant/client consent keeps the pending code control from narrowing offline authority.
    let offline_fixture = Fixture::create(
        context.api,
        context.manifest,
        context.fixture_seed,
        &context.gateway.callback,
    )
    .await?;
    let refresh_root = refresh::root(context, &offline_fixture).await?;
    let original = text_field(&refresh_root, "refresh_token")?;
    let client = fixture.app()?.public.client_id.to_string();
    let refresh_client = offline_fixture.app()?.public.client_id.to_string();
    let count = context.gateway.replica_count();
    let victim = count - 1;
    context.gateway.select_replica(victim)?;
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    let input = token::fields(&code, &client, &context.gateway.callback, &request.verifier);
    context
        .services
        .stop_replica(victim, StopMode::Abrupt)
        .await?;
    unavailable(context).await?;
    check(
        context
            .gateway
            .token_on_replica(victim, &input)
            .await
            .is_err(),
        "Stopped backend accepted a token exchange.",
    )?;
    let untouched: bool = sqlx::query_scalar("SELECT consumed_at IS NULL AND expires_at > clock_timestamp() FROM oauth_authorization_codes WHERE code_hash=$1")
        .bind(Sha256::digest(code.as_bytes()).to_vec()).fetch_one(context.pool).await.safe("Cannot inspect unconsumed outage code.")?;
    check(
        untouched,
        "Unavailable backend consumed or expired pending authority.",
    )?;
    context.gateway.replica_a();
    original_session(context).await?;
    let survivors = (0..victim).collect::<Vec<_>>();
    let body = token::one_winner(context.gateway.race_tokens(&survivors, &input).await?).await?;
    token::claims(context, fixture, &request, &code, &body).await?;
    let winner = token::one_winner(
        context
            .gateway
            .race_tokens(&survivors, &refresh::fields(&refresh_client, &original))
            .await?,
    )
    .await?;
    refresh::race_authority(context, &offline_fixture, &original, &winner).await?;
    let next = text_field(&winner, "refresh_token")?;
    context.services.restart_replica(victim).await?;
    for replica in 0..count {
        token::failure(
            context.gateway.token_on_replica(replica, &input).await?,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        )
        .await?;
        for refresh in [&next, &original] {
            token::failure(
                context
                    .gateway
                    .token_on_replica(replica, &refresh::fields(&refresh_client, refresh))
                    .await?,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
            )
            .await?;
        }
    }
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_token_issuances WHERE refresh_hash=$1")
            .bind(Sha256::digest(original.as_bytes()).to_vec())
            .fetch_one(context.pool)
            .await
            .safe("Cannot inspect outage refresh receipts.")?;
    check(
        receipts == 1,
        "Outage committed duplicate refresh receipts.",
    )
}

/// A positively identified stopped child must produce an explicit unavailable response at the stable issuer.
async fn unavailable(context: &Context<'_>) -> Result<()> {
    let response = context
        .api
        .client
        .get(format!("{}/health", context.api.origin))
        .send()
        .await
        .safe("Cannot probe stopped backend.")?;
    check(
        response.status() == StatusCode::SERVICE_UNAVAILABLE,
        "Stopped backend did not fail closed.",
    )
}

/// Server-side session identity/kind must remain unchanged while a different backend handles the request.
async fn original_session(context: &Context<'_>) -> Result<()> {
    let current: Value = context
        .api
        .json(Method::GET, "/v1/auth/session", None, StatusCode::OK)
        .await?;
    check(
        current.get("user_id") == Some(&json!(context.api.user_id))
            && current.get("session_kind") == Some(&json!("full")),
        "Replica transition changed session authority.",
    )
}
