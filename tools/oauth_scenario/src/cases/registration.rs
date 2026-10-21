//! Actual runtime-role HTTP signup/verification handoffs; no account authority is browser asserted.
//! Administrative changes below are deliberate local incident-containment fault injection only.
use super::Context;
use crate::{
    client::{Actor, Api},
    error::{Result, Safe as _, check},
};
use reqwest::StatusCode;
use secrecy::ExposeSecret as _;
use serde_json::json;

/// Exercises reserved-domain rejection and verifier authority on independently routed processes.
pub async fn security(context: &mut Context<'_>) -> Result<()> {
    let anonymous = Api::anonymous(context.api.origin.clone(), context.api.client.clone());
    let prefix = format!("synthetic-{}", uuid::Uuid::new_v4().simple());
    for index in 0..92 {
        let email = format!("{prefix}-{index}@example.com");
        for (route, field) in [
            ("start", "registration_request"),
            ("finish", "registration_record"),
        ] {
            context.gateway.replica_a();
            let response = anonymous
                .auth_response(
                    &format!("/v1/auth/opaque/signup/{route}"),
                    json!({"email":email,field:"invalid-transcript"}),
                )
                .await?;
            check(
                response.status() == StatusCode::FORBIDDEN,
                "Reserved signup received protocol authority.",
            )?;
        }
    }
    let inserted: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email::text LIKE $1")
        .bind(format!("{prefix}%"))
        .fetch_one(context.pool)
        .await
        .safe("Cannot inspect reserved signup effects.")?;
    let queued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM email_outbox WHERE to_email::text LIKE $1")
            .bind(format!("{prefix}%"))
            .fetch_one(context.pool)
            .await
            .safe("Cannot inspect reserved outbox effects.")?;
    check(
        inserted == 0 && queued == 0,
        "Rejected registrations persisted account or mail state.",
    )?;
    context.gateway.replica_a();
    let (actor, token) = Actor::pending_signup(&anonymous, context.pool).await?;
    context.gateway.replica_b();
    let verified = anonymous
        .auth_response(
            "/v1/auth/verify-email",
            json!({"token":token.expose_secret()}),
        )
        .await?;
    check(
        verified.status() == StatusCode::NO_CONTENT,
        "Cross-replica verification did not activate the pending account.",
    )?;
    context.gateway.replica_c();
    let replay = anonymous
        .auth_response(
            "/v1/auth/verify-email",
            json!({"token":token.expose_secret()}),
        )
        .await?;
    check(
        replay.status() == StatusCode::BAD_REQUEST,
        "A different replica accepted a consumed verifier.",
    )?;
    let (disabled, token) = Actor::pending_signup(&anonymous, context.pool).await?;
    sqlx::query("UPDATE users SET status='disabled' WHERE email=$1")
        .bind(&disabled.email)
        .execute(context.pool)
        .await
        .safe("Cannot apply local account containment.")?;
    context.gateway.replica_a();
    let response = anonymous
        .auth_response(
            "/v1/auth/verify-email",
            json!({"token":token.expose_secret()}),
        )
        .await?;
    check(
        response.status() == StatusCode::BAD_REQUEST,
        "Verification bypassed disabled account containment.",
    )?;
    let state: (String, bool) =
        sqlx::query_as("SELECT status::text,email_verified_at IS NULL FROM users WHERE email=$1")
            .bind(&disabled.email)
            .fetch_one(context.pool)
            .await
            .safe("Cannot inspect containment state.")?;
    check(
        state == ("disabled".into(), true),
        "Verification changed a disabled account's protected state.",
    )?;
    let state: String = sqlx::query_scalar("SELECT status::text FROM users WHERE email=$1")
        .bind(&actor.email)
        .fetch_one(context.pool)
        .await
        .safe("Cannot inspect verified account.")?;
    check(
        state == "active",
        "Verification did not preserve the active account.",
    )?;
    context.gateway.replica_a();
    Ok(())
}
