//! Self-service saved-consent regressions against the production router and PostgreSQL.

use super::*;
use axum::http::header::CACHE_CONTROL;

/// A grant remains bound to the exact user and can be revoked without exposing another user's consent.
#[tokio::test]
async fn saved_grants_list_and_revoke_only_current_user() -> Result<()> {
    let fixture = Fixture::new().await?;
    let owned: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_grants(user_id,client_id,application_id,organization_id)
         VALUES($1,$2,$3,$4) RETURNING id",
    )
    .bind(fixture.user)
    .bind(fixture.client_internal)
    .bind(fixture.application)
    .bind(fixture.organization)
    .fetch_one(&fixture.pool)
    .await?;
    sqlx::query(
        "INSERT INTO oauth_grant_scopes(grant_id,client_id,application_id,scope_id)
         SELECT $1,$2,$3,id FROM oauth_scopes
         WHERE application_id=$3 AND name IN ('jobs:read','runs:read')",
    )
    .bind(owned)
    .bind(fixture.client_internal)
    .bind(fixture.application)
    .execute(&fixture.pool)
    .await?;

    let other: Uuid = sqlx::query_scalar(
        "INSERT INTO users(email,opaque_registration_record,status)
         VALUES('another-grant-user@test.local',$1,'active') RETURNING id",
    )
    .bind(vec![0u8; 16])
    .fetch_one(&fixture.pool)
    .await?;
    sqlx::query("INSERT INTO org_memberships(org_id,user_id,status) VALUES($1,$2,'active')")
        .bind(fixture.organization)
        .bind(other)
        .execute(&fixture.pool)
        .await?;
    let foreign: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_grants(user_id,client_id,application_id,organization_id)
         VALUES($1,$2,$3,$4) RETURNING id",
    )
    .bind(other)
    .bind(fixture.client_internal)
    .bind(fixture.application)
    .bind(fixture.organization)
    .fetch_one(&fixture.pool)
    .await?;

    let listed = fixture
        .call(
            &fixture.router,
            "GET",
            "/v1/me/oauth/grants",
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(
        listed.headers.get(CACHE_CONTROL).context("cache policy")?,
        "no-store"
    );
    let page: Value = serde_json::from_str(&listed.body)?;
    assert_eq!(page["grants"].as_array().context("grants array")?.len(), 1);
    assert_eq!(page["grants"][0]["id"], owned.to_string());
    assert_eq!(page["grants"][0]["client_id"], fixture.client.to_string());
    assert_eq!(page["grants"][0]["organization_slug"], "authorize-org");
    assert_eq!(
        page["grants"][0]["scopes"],
        json!(["jobs:read", "runs:read"])
    );
    assert!(page["grants"][0].get("user_id").is_none());
    assert!(page["grants"][0].get("application_id").is_none());
    assert!(page["grants"][0].get("organization_id").is_none());
    assert!(!listed.body.contains("platform:admin"));

    let forbidden = fixture
        .call(
            &fixture.router,
            "DELETE",
            &format!("/v1/me/oauth/grants/{foreign}"),
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(forbidden.status, StatusCode::NOT_FOUND);
    let foreign_unchanged: bool =
        sqlx::query_scalar("SELECT revoked_at IS NULL FROM oauth_grants WHERE id=$1")
            .bind(foreign)
            .fetch_one(&fixture.pool)
            .await?;
    assert!(foreign_unchanged);

    let revoked = fixture
        .call(
            &fixture.router,
            "DELETE",
            &format!("/v1/me/oauth/grants/{owned}"),
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let repeated = fixture
        .call(
            &fixture.router,
            "DELETE",
            &format!("/v1/me/oauth/grants/{owned}"),
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(repeated.status, StatusCode::NOT_FOUND);
    let listed_after = fixture
        .call(
            &fixture.router,
            "GET",
            "/v1/me/oauth/grants",
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    let page: Value = serde_json::from_str(&listed_after.body)?;
    assert_eq!(page["grants"], json!([]));
    Ok(())
}

/// A foreign or malformed cursor cannot reveal another user's grant records.
#[tokio::test]
async fn saved_grants_cursor_is_scoped_and_malformed_cursor_rejected() -> Result<()> {
    let fixture = Fixture::new().await?;
    let malformed = fixture
        .call(
            &fixture.router,
            "GET",
            "/v1/me/oauth/grants?after=not-a-uuid",
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    let foreign_cursor = Uuid::new_v4();
    let listed = fixture
        .call(
            &fixture.router,
            "GET",
            &format!("/v1/me/oauth/grants?after={foreign_cursor}"),
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(listed.status, StatusCode::OK);
    let page: Value = serde_json::from_str(&listed.body)?;
    assert_eq!(page["grants"], json!([]));
    Ok(())
}

/// Keyset pages must neither repeat grants nor admit another user's cursor or consent.
#[tokio::test]
async fn saved_grants_page_through_more_than_one_page() -> Result<()> {
    let fixture = Fixture::new().await?;
    let mut expected = Vec::new();
    for index in 0..=crate::oauth::grant::GRANT_PAGE_SIZE {
        let client: Uuid = sqlx::query_scalar(
            "INSERT INTO oauth_clients(application_id,client_id,name,client_type)
             VALUES($1,$2,$3,'public') RETURNING id",
        )
        .bind(fixture.application)
        .bind(Uuid::new_v4())
        .bind(format!("Paged client {index}"))
        .fetch_one(&fixture.pool)
        .await?;
        let grant: Uuid = sqlx::query_scalar(
            "INSERT INTO oauth_grants(user_id,client_id,application_id,organization_id)
             VALUES($1,$2,$3,$4) RETURNING id",
        )
        .bind(fixture.user)
        .bind(client)
        .bind(fixture.application)
        .bind(fixture.organization)
        .fetch_one(&fixture.pool)
        .await?;
        expected.push(grant.to_string());
    }
    let first = fixture
        .call(
            &fixture.router,
            "GET",
            "/v1/me/oauth/grants",
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(first.status, StatusCode::OK);
    let first: Value = serde_json::from_str(&first.body)?;
    let first_grants = first["grants"].as_array().context("first page")?;
    assert_eq!(first_grants.len(), crate::oauth::grant::GRANT_PAGE_SIZE);
    let cursor = first["next_cursor"].as_str().context("next cursor")?;
    let second = fixture
        .call(
            &fixture.router,
            "GET",
            &format!("/v1/me/oauth/grants?after={cursor}"),
            Some(&fixture.token),
            None,
            None,
        )
        .await?;
    assert_eq!(second.status, StatusCode::OK);
    let second: Value = serde_json::from_str(&second.body)?;
    assert_eq!(second["grants"].as_array().context("second page")?.len(), 1);
    assert!(second["next_cursor"].is_null());
    let mut actual = first_grants
        .iter()
        .chain(second["grants"].as_array().context("second page")?.iter())
        .map(|grant| grant["id"].as_str().context("grant ID").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    Ok(())
}
