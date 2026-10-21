//! Replica failover and explicit bottom-up tenant lifecycle assertions.
//! Each case retains its own tenant fixture and verifies the real service boundary.

use crate::error::Safe;

use super::{
    Context, Fixture, Method, Request, Resource, Result, StatusCode, begin, callback, check, issue,
    json, redeem, snapshot,
};

/// Persists consent on A, stops A, and completes that unchanged authorization on B.
pub(super) async fn failover(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    // Ensure this case starts on A even if an earlier independent login-resume selected B.
    context.gateway.replica_a();
    let page = begin(context, &request, "owner").await?;
    crate::browser::expect_stage(
        &page,
        "consent",
        "Replica A did not persist consent request.",
    )?;
    context
        .services
        .stop_replica(0, crate::services::StopMode::Abrupt)
        .await?;
    context.gateway.replica_b();
    let result = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"allow"}))
        .await?;
    let code = callback(
        &result,
        &context.gateway.callback,
        &request.state,
        "code",
        &context.api.origin,
    )?;
    snapshot(context, fixture, &request, &code).await?;
    check(
        redeem(
            context.pool,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Replica-independent code redemption failed after A stopped.",
    )
}

/// Populated parents conflict, clients are explicitly removed, then resources soft-delete bottom-up.
pub(super) async fn deletion(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    context
        .api
        .delete_org(&fixture.org, StatusCode::CONFLICT)
        .await?;
    context
        .api
        .status(
            Method::DELETE,
            &fixture.project_path,
            None,
            StatusCode::CONFLICT,
        )
        .await?;
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    for (_, env_path, applications) in &fixture.environments {
        context
            .api
            .status(Method::DELETE, env_path, None, StatusCode::CONFLICT)
            .await?;
        remove_applications(context, applications).await?;
        context
            .api
            .status(Method::DELETE, env_path, None, StatusCode::NO_CONTENT)
            .await?;
    }
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
        "Deleted application retained redeemable OAuth authority.",
    )?;
    context
        .api
        .status(
            Method::DELETE,
            &fixture.project_path,
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
    context
        .api
        .delete_org(&fixture.org, StatusCode::NO_CONTENT)
        .await?;
    context
        .api
        .status(
            Method::GET,
            &format!("/v1/orgs/{}/projects", fixture.org.slug),
            None,
            StatusCode::NOT_FOUND,
        )
        .await?;
    let orgs: Vec<Resource> = context
        .api
        .json(Method::GET, "/v1/orgs", None, StatusCode::OK)
        .await?;
    check(
        !orgs.iter().any(|org| org.id == fixture.org.id),
        "Deleted tenant remains in active organization list.",
    )?;
    Ok(())
}

/// Explicitly removes every client before leaf deletion and verifies database rows remain soft-deleted.
async fn remove_applications(
    context: &Context<'_>,
    applications: &[crate::client::Application],
) -> Result<()> {
    for app in applications {
        context
            .api
            .status(Method::DELETE, &app.path, None, StatusCode::CONFLICT)
            .await?;
        for client in [&app.public, &app.confidential] {
            context
                .api
                .status(
                    Method::DELETE,
                    &format!("{}/oauth/clients/{}", app.path, client.client_id),
                    None,
                    StatusCode::NO_CONTENT,
                )
                .await?;
        }
        context
            .api
            .status(Method::DELETE, &app.path, None, StatusCode::NO_CONTENT)
            .await?;
        context
            .api
            .status(
                Method::GET,
                &format!("{}/oauth/scopes", app.path),
                None,
                StatusCode::NOT_FOUND,
            )
            .await?;
        context
            .api
            .status(Method::DELETE, &app.path, None, StatusCode::NOT_FOUND)
            .await?;
        let deleted: bool =
            sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM applications WHERE id=$1")
                .bind(app.resource.id)
                .fetch_one(context.pool)
                .await
                .safe("Cannot verify application soft deletion.")?;
        check(
            deleted,
            "Application deletion physically removed or retained active row.",
        )?;
    }
    Ok(())
}
