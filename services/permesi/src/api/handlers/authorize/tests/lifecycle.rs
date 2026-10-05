//! Authorization requests and issued codes cannot survive explicit tenant teardown.
//!
//! These tests use the actual deletion endpoints rather than only toggling lifecycle
//! columns, linking consent, client revocation and application deletion behavior.

use super::*;

/// Links client/application deletion to failed pending consent and cross-replica code redemption.
#[tokio::test]
async fn authorize_requests_and_codes_fail_after_bottom_up_application_deletion() -> Result<()> {
    let f = Fixture::new().await?;
    sqlx::query("INSERT INTO org_roles(org_id,name) VALUES($1,'owner')")
        .bind(f.organization)
        .execute(&f.pool)
        .await?;
    sqlx::query("INSERT INTO org_member_roles(org_id,user_id,role_name) VALUES($1,$2,'owner')")
        .bind(f.organization)
        .bind(f.user)
        .execute(&f.pool)
        .await?;
    let code = f.issue().await?;
    let pending = f.start(&[("prompt", Some("consent".to_owned()))]).await?;
    assert_eq!(pending.status, StatusCode::OK);
    let base = format!(
        "/v1/orgs/authorize-org/projects/project/envs/test/apps/{}",
        f.application
    );
    let deletion = f
        .call(&f.router, "DELETE", &base, Some(&f.token), None, None)
        .await?;
    assert_eq!(deletion.status, StatusCode::CONFLICT);
    let client = f
        .call(
            &f.router,
            "DELETE",
            &format!("{base}/oauth/clients/{}", f.client),
            Some(&f.token),
            None,
            None,
        )
        .await?;
    assert_eq!(client.status, StatusCode::NO_CONTENT);
    let deletion = f
        .call(&f.router, "DELETE", &base, Some(&f.token), None, None)
        .await?;
    assert_eq!(deletion.status, StatusCode::NO_CONTENT);
    let denied = f.start(&[]).await?;
    assert_eq!(denied.status, StatusCode::BAD_REQUEST);
    assert!(
        denied.location.is_none(),
        "Deleted clients cannot establish a safe callback"
    );
    let denied = f.decide(&pending, "allow", "").await?;
    assert_eq!(denied.status, StatusCode::BAD_REQUEST);
    assert!(denied.location.is_none());
    let replica = PgPoolOptions::new()
        .max_connections(2)
        .connect(&f.postgres.admin_dsn())
        .await?;
    assert!(
        f.redeem(
            &replica,
            &code,
            f.client,
            REDIRECT,
            VERIFIER,
            f.organization
        )
        .await?
        .is_none()
    );
    let consumed: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM oauth_authorization_codes WHERE code_hash=$1",
    )
    .bind(SecretValue::parse(&code)?.hash())
    .fetch_one(&f.pool)
    .await?;
    assert!(
        !consumed,
        "Revoked authority cannot consume outstanding codes"
    );
    replica.close().await;
    Ok(())
}
