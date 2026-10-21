//! Single-use authorization-code binding, expiry and concurrent-redemption assertions.
//! Each case retains its own tenant fixture and verifies the real service boundary.

use crate::error::Safe;

use super::{
    Context, Fixture, OAuthConfig, PgPool, RedemptionInput, Request, Result, Uuid, check, issue,
    redeem, redeem_authorization_code, snapshot,
};

/// Wrong context/verifier/client/redirect never consumes; rollback restores usability, replay fails after commit.
pub(super) async fn bindings(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    snapshot(context, fixture, &request, &code).await?;
    negative_bindings(context, fixture, &request, &code).await?;
    let independent = PgPool::connect(context.admin_dsn)
        .await
        .safe("Cannot connect independent redemption instance.")?;
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
        "Separate-instance validation failed.",
    )?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Rollback consumed the code.",
    )?;
    check(
        !redeem(
            context.pool,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Committed authorization code replay succeeded.",
    )?;
    independent.close().await;
    Ok(())
}

/// Wrong authenticated-client/resource/PKCE inputs fail before consumption and leave the valid code untouched.
async fn negative_bindings(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
) -> Result<()> {
    let app = fixture.app()?;
    let other_client = crate::client::create_client(
        context.api,
        &app.path,
        "public",
        &context.gateway.callback,
        &request.scopes,
    )
    .await?;
    for (client_id, org, redirect, verifier) in [
        (
            other_client.client_id,
            fixture.org.id,
            context.gateway.callback.clone(),
            request.verifier.clone(),
        ),
        (
            app.public.client_id,
            Uuid::new_v4(),
            context.gateway.callback.clone(),
            request.verifier.clone(),
        ),
        (
            app.public.client_id,
            fixture.org.id,
            format!("{}/alternate", context.gateway.callback),
            request.verifier.clone(),
        ),
        (
            app.public.client_id,
            fixture.org.id,
            context.gateway.callback.clone(),
            "a".repeat(43),
        ),
        (
            app.public.client_id,
            fixture.org.id,
            context.gateway.callback.clone(),
            "short".to_owned(),
        ),
    ] {
        let mut tx = context
            .pool
            .begin()
            .await
            .safe("Cannot start negative redemption.")?;
        let result = redeem_authorization_code(
            &mut tx,
            context.policy,
            RedemptionInput {
                code,
                client_id,
                redirect_uri: &redirect,
                code_verifier: &verifier,
                organization_id: org,
            },
        )
        .await;
        check(result.is_err(), "Wrong code binding/verifier was accepted.")?;
        tx.rollback()
            .await
            .safe("Cannot rollback negative redemption.")?;
    }
    Ok(())
}

/// Expires a real-issued code by waiting its actual TTL; immutable database fields are never patched.
pub(super) async fn expiration_race(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    let independent = PgPool::connect(context.admin_dsn)
        .await
        .safe("Cannot connect concurrent redemption instance.")?;
    snapshot(context, fixture, &request, &code).await?;
    let a = context
        .pool
        .begin()
        .await
        .safe("Cannot start first concurrent transaction.")?;
    let b = independent
        .begin()
        .await
        .safe("Cannot start second concurrent transaction.")?;
    let barrier = tokio::sync::Barrier::new(2);
    let client_id = fixture.app()?.public.client_id;
    let input = || RedemptionInput {
        code: &code,
        client_id,
        redirect_uri: &context.gateway.callback,
        code_verifier: &request.verifier,
        organization_id: fixture.org.id,
    };
    let (a, b) = tokio::join!(
        raced_redemption(a, context.policy, input(), &barrier),
        raced_redemption(b, context.policy, input(), &barrier)
    );
    check(
        usize::from(a?) + usize::from(b?) == 1,
        "Concurrent redemption did not have exactly one committed winner.",
    )?;
    let mut expired = Request::new(context, fixture)?;
    expired.url = expired.changed("prompt", Some("consent"));
    let code = issue(context, &expired).await?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &expired,
            &code,
            &context.gateway.callback,
            false,
        )
        .await?,
        "Fresh code failed validation before the expiry wait.",
    )?;
    tokio::time::sleep(std::time::Duration::from_secs(
        u64::try_from(context.policy.code_ttl).safe("Invalid code TTL.")? + 1,
    ))
    .await;
    check(
        !redeem(
            &independent,
            context.policy,
            fixture,
            &expired,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Expired authorization code was redeemed.",
    )?;
    independent.close().await;
    Ok(())
}

/// Releases two established database transactions together; only a successful committed consumption wins.
async fn raced_redemption(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    policy: &OAuthConfig,
    input: RedemptionInput<'_>,
    barrier: &tokio::sync::Barrier,
) -> Result<bool> {
    barrier.wait().await;
    let valid = redeem_authorization_code(&mut tx, policy, input)
        .await
        .is_ok();
    if valid {
        tx.commit()
            .await
            .safe("Cannot commit concurrent code consumption.")?;
    } else {
        tx.rollback()
            .await
            .safe("Cannot roll back concurrent code consumption.")?;
    }
    Ok(valid)
}
