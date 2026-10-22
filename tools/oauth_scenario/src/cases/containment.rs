//! HTTP account containment across all configured processes, including safe recovery.
//! Only the isolated fixture bootstrap enables the operator; target lifecycle changes
//! use the real recent-session API. Raw proofs and tokens never leave private memory.

use super::{Context, Request, begin, callback, issue, refresh, token};
use crate::{
    client::{Actor, Api, Fixture, PasswordFlow, text_field},
    error::{Result, Safe as _, check},
};
use reqwest::{Method, StatusCode};
use serde_json::json;

/// A dedicated target avoids revoking another case's owner or browser/session authority.
pub async fn account_containment(context: &mut Context<'_>) -> Result<()> {
    let anonymous = Api::anonymous(context.api.origin.clone(), context.api.client.clone());
    let operator = Actor::signup(&anonymous, context.pool).await?;
    let proof = operator
        .password_proof(&anonymous, PasswordFlow::Login)
        .await?;
    let operator_api = anonymous
        .authenticated_response(&proof.finish(&anonymous).await?)
        .await?;
    let operator_id = operator_api
        .user_id
        .ok_or_else(|| crate::error::Failure::harness("Missing operator identity."))?;
    sqlx::query(
        "INSERT INTO platform_operators(user_id,note) VALUES($1,'isolated containment fixture')",
    )
    .bind(operator_id)
    .execute(context.pool)
    .await
    .safe("Cannot bootstrap isolated operator.")?;
    let target = Actor::signup(&anonymous, context.pool).await?;
    let target_api = target
        .login(
            context.browser,
            &anonymous,
            &context.gateway.callback,
            "owner",
        )
        .await?;
    let fixture = Fixture::create(
        &target_api,
        context.manifest,
        context.fixture_seed,
        &context.gateway.callback,
    )
    .await?;
    let result = {
        let mut isolated = Context {
            browser: context.browser,
            services: context.services,
            gateway: context.gateway,
            owner: &target,
            api: &target_api,
            outsider: context.outsider,
            pool: context.pool,
            admin_dsn: context.admin_dsn,
            policy: context.policy,
            credential_grace_seconds: context.credential_grace_seconds,
            access_token_ttl_seconds: context.access_token_ttl_seconds,
            resource: context.resource,
            infrastructure: context.infrastructure,
            manifest: context.manifest,
            fixture_seed: context.fixture_seed,
        };
        exercise(&mut isolated, &fixture, &operator_api, &anonymous).await
    };
    // Restore the browser actor even when the isolated case fails; the original native
    // owner's session was never targeted and later cases retain independent authority.
    let restored = context
        .owner
        .login(
            context.browser,
            &anonymous,
            &context.gateway.callback,
            "owner",
        )
        .await;
    result?;
    restored?;
    context.gateway.replica_a();
    Ok(())
}

/// Rejection after recovery must be permanent; fresh login and consent prove services remain usable.
async fn exercise(
    context: &mut Context<'_>,
    fixture: &Fixture,
    operator: &Api,
    anonymous: &Api,
) -> Result<()> {
    let user = context
        .api
        .user_id
        .ok_or_else(|| crate::error::Failure::harness("Missing target identity."))?;
    let root = refresh::root(context, fixture).await?;
    let refresh_token = text_field(&root, "refresh_token")?;
    let client = fixture.app()?.public.client_id.to_string();
    let mut request = Request::new(context, fixture)?;
    request.url = request.changed("prompt", Some("consent"));
    let code = issue(context, &request).await?;
    let fields = token::fields(&code, &client, &context.gateway.callback, &request.verifier);
    validate_code(context, fixture, &request, &code).await?;
    let proof = context
        .owner
        .password_proof(anonymous, PasswordFlow::Login)
        .await?;
    let mut pending = Request::new(context, fixture)?;
    pending.url = pending.changed("prompt", Some("consent"));
    let page = begin(context, &pending, "owner").await?;
    crate::browser::expect_stage(
        &page,
        "consent",
        "Containment request did not require fresh scopes.",
    )?;
    let route = format!("/v1/users/{user}");
    context
        .api
        .status(
            Method::POST,
            &format!("{route}/suspend"),
            Some(json!({"reason":"administrative"})),
            StatusCode::FORBIDDEN,
        )
        .await?;
    context.gateway.replica_a();
    operator
        .status(
            Method::POST,
            &format!("{route}/suspend"),
            Some(json!({"reason":"suspected_compromise"})),
            StatusCode::NO_CONTENT,
        )
        .await?;
    reject_everywhere(context, &fields, &client, &refresh_token).await?;
    context.gateway.replica_b();
    operator
        .status(
            Method::POST,
            &format!("{route}/reactivate"),
            Some(json!({"reason":"incident_resolved"})),
            StatusCode::NO_CONTENT,
        )
        .await?;
    reject_everywhere(context, &fields, &client, &refresh_token).await?;
    check(
        proof.finish(anonymous).await?.status() == StatusCode::UNAUTHORIZED,
        "Recovery revived a prior login proof.",
    )?;
    let response = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"allow"}))
        .await?;
    check(
        callback(
            &response,
            &context.gateway.callback,
            &pending.state,
            "error",
            &context.api.origin,
        )? == "access_denied",
        "Recovery revived bound pending consent instead of denying the exact request.",
    )?;
    assert_retired(context, user, operator.user_id).await?;
    let _fresh = context
        .owner
        .login(
            context.browser,
            anonymous,
            &context.gateway.callback,
            "owner",
        )
        .await?;
    let mut recovery = Request::new(context, fixture)?;
    recovery.url = recovery.changed("prompt", Some("consent"));
    let recovered = issue(context, &recovery).await?;
    let recovery_fields = token::fields(
        &recovered,
        &client,
        &context.gateway.callback,
        &recovery.verifier,
    );
    token::response(
        context.api.token(&recovery_fields, None).await?,
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

/// Every real replica independently rejects old cookies, codes and refresh tokens without sticky state.
async fn reject_everywhere(
    context: &Context<'_>,
    code: &[(&str, &str)],
    client: &str,
    refresh_token: &str,
) -> Result<()> {
    for index in 0..context.gateway.replica_count() {
        context.gateway.select_replica(index)?;
        context
            .outsider
            .status(Method::GET, "/v1/auth/session", None, StatusCode::OK)
            .await?;
        context
            .api
            .status(
                Method::GET,
                "/v1/auth/session",
                None,
                StatusCode::NO_CONTENT,
            )
            .await?;
        token::failure(
            context.gateway.token_on_replica(index, code).await?,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        )
        .await?;
        token::failure(
            context
                .gateway
                .token_on_replica(index, &refresh::fields(client, refresh_token))
                .await?,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        )
        .await?;
    }
    Ok(())
}

/// A rolled-back independent redemption proves the code was usable before suspension.
async fn validate_code(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
) -> Result<()> {
    let mut control = context
        .pool
        .begin()
        .await
        .safe("Cannot begin code control.")?;
    permesi::oauth::authorization::redemption::redeem_authorization_code(
        &mut control,
        context.policy,
        permesi::oauth::authorization::redemption::RedemptionInput {
            code,
            client_id: fixture.app()?.public.client_id,
            redirect_uri: &context.gateway.callback,
            code_verifier: &request.verifier,
            organization_id: fixture.org.id,
        },
    )
    .await
    .safe("Containment code control was not initially valid.")?;
    control
        .rollback()
        .await
        .safe("Cannot roll back code control.")?;
    Ok(())
}

/// History and unrelated identities survive while only the target's live authority disappears.
async fn assert_retired(
    context: &Context<'_>,
    user: uuid::Uuid,
    operator: Option<uuid::Uuid>,
) -> Result<()> {
    let active: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM user_sessions WHERE user_id=$1),(SELECT count(*) FROM oauth_grants WHERE user_id=$1 AND revoked_at IS NULL),(SELECT count(*) FROM oauth_refresh_families WHERE user_id=$1 AND revoked_at IS NULL)")
        .bind(user).fetch_one(context.pool).await.safe("Cannot inspect containment effects.")?;
    check(
        active == (0, 0, 0),
        "Containment retained active session or delegated authority.",
    )?;
    let audits: i64=sqlx::query_scalar("SELECT count(*) FROM user_lifecycle_audit_log WHERE target_id=$1 AND actor_id=$2 AND outcome='changed'")
        .bind(user).bind(operator).fetch_one(context.pool).await.safe("Cannot inspect containment audit.")?;
    check(
        audits == 2,
        "Containment transitions lack matching audit events.",
    )?;
    Ok(())
}
