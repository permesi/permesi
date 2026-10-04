//! Real-PostgreSQL regressions for independent sibling environment lifecycles.
//! Session authorization and scoped HTTP resolution are exercised before writes;
//! active-only filtering and uniqueness remain enforced by the existing schema.

use super::*;
use axum::response::Response;
use serde_json::Value;

struct Fixture {
    db: TestDb,
    app: Router,
    token: String,
    org_id: Uuid,
}

impl Fixture {
    /// Creates an authenticated owner and organization through the normal HTTP API.
    async fn new() -> Result<Option<Self>> {
        let Some(db) = TestDb::new().await? else {
            return Ok(None);
        };
        let owner = insert_active_user(&db.pool, "environment-owner@example.test").await?;
        let token = insert_session(&db.pool, owner).await?;
        let app = app_router(db.pool.clone());
        let response = request(
            &app,
            &token,
            "POST",
            "/v1/orgs",
            json!({"name":"Acme", "slug":"acme"}),
        )
        .await?;
        let org = created_json(response).await?;
        let org_id = Uuid::parse_str(text_field(&org, "id")?)?;
        Ok(Some(Self {
            db,
            app,
            token,
            org_id,
        }))
    }

    /// Creates a project via HTTP and returns its id plus the environment collection URI.
    async fn project(&self, org: &str, slug: &str) -> Result<(Uuid, String)> {
        let response = request(
            &self.app,
            &self.token,
            "POST",
            &format!("/v1/orgs/{org}/projects"),
            json!({"name":slug,"slug":slug}),
        )
        .await?;
        let project = created_json(response).await?;
        Ok((
            Uuid::parse_str(text_field(&project, "id")?)?,
            format!("/v1/orgs/{org}/projects/{slug}/envs"),
        ))
    }

    /// Uses the owner's session to create a sibling with a deliberately independent name/tier.
    async fn environment(&self, uri: &str, slug: &str, tier: &str) -> Result<Response> {
        request(
            &self.app,
            &self.token,
            "POST",
            uri,
            json!({"name":slug,"slug":slug,"tier":tier}),
        )
        .await
    }

    /// Reads only the environment DTOs visible through the normal authenticated collection API.
    async fn environments(&self, uri: &str) -> Result<Vec<Value>> {
        let response = request(&self.app, &self.token, "GET", uri, Value::Null).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&body)?)
    }
}

/// Sends an authenticated test request without bypassing handler authorization or scoping.
async fn request(
    app: &Router,
    token: &str,
    method: &str,
    uri: &str,
    payload: Value,
) -> Result<Response> {
    let body = if payload.is_null() {
        Body::empty()
    } else {
        Body::from(payload.to_string())
    };
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(body)?,
        )
        .await?)
}

/// Requires a successful creation before interpreting the public response fields.
async fn created_json(response: Response) -> Result<Value> {
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Reads a required public DTO string without panicking on malformed test responses.
fn text_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("Missing response field {name}"))
}

#[tokio::test]
/// Covers either tier first, multiple non-production siblings, and the omitted-tier default.
async fn environment_tiers_are_independent_in_either_creation_order() -> Result<()> {
    let Some(fixture) = Fixture::new().await? else {
        return Ok(());
    };
    for (project, order) in [
        (
            "development-first",
            [
                ("dev", "non_production"),
                ("staging", "non_production"),
                ("live", "production"),
            ],
        ),
        (
            "production-first",
            [
                ("live", "production"),
                ("dev", "non_production"),
                ("staging", "non_production"),
            ],
        ),
    ] {
        let (_, uri) = fixture.project("acme", project).await?;
        assert_eq!(fixture.environments(&uri).await?, Vec::<Value>::new());
        for (slug, tier) in order {
            let row = created_json(fixture.environment(&uri, slug, tier).await?).await?;
            assert_eq!(text_field(&row, "slug")?, slug);
            assert_eq!(text_field(&row, "tier")?, tier);
        }
        assert_eq!(fixture.environments(&uri).await?.len(), 3);
        assert_eq!(
            fixture
                .environment(&uri, "prod2", "production")
                .await?
                .status(),
            StatusCode::CONFLICT
        );
    }
    // The existing omitted-tier default can also create the first environment.
    let (_, uri) = fixture.project("acme", "default-tier").await?;
    let response = request(
        &fixture.app,
        &fixture.token,
        "POST",
        &uri,
        json!({"name":"QA","slug":"qa"}),
    )
    .await?;
    assert_eq!(
        text_field(&created_json(response).await?, "tier")?,
        "non_production"
    );
    Ok(())
}

#[tokio::test]
/// Keeps the production slot local to each project and rejects wrong-org project ancestry.
async fn environment_production_limit_is_scoped_to_each_project_and_organization() -> Result<()> {
    let Some(fixture) = Fixture::new().await? else {
        return Ok(());
    };
    created_json(
        request(
            &fixture.app,
            &fixture.token,
            "POST",
            "/v1/orgs",
            json!({"name":"Other", "slug":"other"}),
        )
        .await?,
    )
    .await?;
    for (org, project) in [
        ("acme", "core"),
        ("acme", "second"),
        ("other", "other-project"),
    ] {
        let (_, uri) = fixture.project(org, project).await?;
        created_json(
            fixture
                .environment(&uri, "production", "production")
                .await?,
        )
        .await?;
        assert_eq!(fixture.environments(&uri).await?.len(), 1);
    }
    // A valid project slug in another org must not resolve under this org.
    for method in ["GET", "POST"] {
        assert_eq!(
            request(
                &fixture.app,
                &fixture.token,
                method,
                "/v1/orgs/acme/projects/other-project/envs",
                json!({"name":"Dev","slug":"dev","tier":"non_production"})
            )
            .await?
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM environments WHERE tier = 'production' AND deleted_at IS NULL",
    )
    .fetch_one(&fixture.db.pool)
    .await?;
    assert_eq!(count, 3);
    Ok(())
}

#[tokio::test]
/// Existing owner/admin writes and active membership reads retain their anti-enumeration rules.
async fn environment_management_keeps_role_and_membership_boundaries() -> Result<()> {
    let Some(fixture) = Fixture::new().await? else {
        return Ok(());
    };
    let (_, uri) = fixture.project("acme", "core").await?;
    for (role, status, write, read) in [
        ("admin", "active", StatusCode::CREATED, StatusCode::OK),
        ("member", "active", StatusCode::NOT_FOUND, StatusCode::OK),
        ("readonly", "active", StatusCode::NOT_FOUND, StatusCode::OK),
        (
            "owner",
            "invited",
            StatusCode::NOT_FOUND,
            StatusCode::NOT_FOUND,
        ),
        (
            "admin",
            "suspended",
            StatusCode::NOT_FOUND,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let user =
            insert_active_user(&fixture.db.pool, &format!("{role}-{status}@example.test")).await?;
        let token = insert_session(&fixture.db.pool, user).await?;
        insert_member_role(&fixture.db.pool, fixture.org_id, user, role).await?;
        sqlx::query("UPDATE org_memberships SET status = $1::org_membership_status WHERE org_id = $2 AND user_id = $3").bind(status).bind(fixture.org_id).bind(user).execute(&fixture.db.pool).await?;
        let response = request(
            &fixture.app,
            &token,
            "POST",
            &uri,
            json!({"name":"Dev","slug":"dev","tier":"non_production"}),
        )
        .await?;
        assert_eq!(response.status(), write, "{role}/{status}");
        assert_eq!(
            request(&fixture.app, &token, "GET", &uri, Value::Null)
                .await?
                .status(),
            read,
            "{role}/{status}"
        );
    }
    let stranger = insert_active_user(&fixture.db.pool, "non-member@example.test").await?;
    let token = insert_session(&fixture.db.pool, stranger).await?;
    for method in ["GET", "POST"] {
        assert_eq!(
            request(
                &fixture.app,
                &token,
                method,
                &uri,
                json!({"name":"QA","slug":"qa","tier":"non_production"})
            )
            .await?
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        request(
            &fixture.app,
            "",
            "POST",
            &uri,
            json!({"name":"QA","slug":"qa","tier":"non_production"})
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fixture.environments(&uri).await?.len(), 1);
    Ok(())
}

#[tokio::test]
/// Soft deletion releases slug and production uniqueness while lists exclude the old row.
async fn environment_soft_delete_releases_production_and_slug_without_blocking_siblings()
-> Result<()> {
    let Some(fixture) = Fixture::new().await? else {
        return Ok(());
    };
    let (_, uri) = fixture.project("acme", "core").await?;
    let original = created_json(fixture.environment(&uri, "live", "production").await?).await?;
    let duplicate = fixture.environment(&uri, "live", "non_production").await?;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(duplicate.into_body(), usize::MAX).await?.as_ref(),
        b"Environment slug already exists."
    );
    let original_id = Uuid::parse_str(text_field(&original, "id")?)?;
    sqlx::query("UPDATE environments SET deleted_at = NOW() WHERE id = $1")
        .bind(original_id)
        .execute(&fixture.db.pool)
        .await?;
    assert_eq!(fixture.environments(&uri).await?, Vec::<Value>::new());
    created_json(fixture.environment(&uri, "dev", "non_production").await?).await?;
    let replacement = created_json(fixture.environment(&uri, "live", "production").await?).await?;
    assert_ne!(
        text_field(&replacement, "id")?,
        text_field(&original, "id")?
    );
    let rows = fixture.environments(&uri).await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.get("id") != original.get("id")));
    Ok(())
}

#[tokio::test]
/// Concurrent production writes yield one success and one stable conflict response.
async fn environment_concurrent_production_creation_returns_one_conflict() -> Result<()> {
    let Some(fixture) = Fixture::new().await? else {
        return Ok(());
    };
    let (_, uri) = fixture.project("acme", "core").await?;
    let (first, second) = tokio::join!(
        fixture.environment(&uri, "live", "production"),
        fixture.environment(&uri, "prod2", "production")
    );
    let (first, second) = (first?, second?);
    let conflict = if first.status() == StatusCode::CREATED {
        second
    } else {
        assert_eq!(second.status(), StatusCode::CREATED);
        first
    };
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(conflict.into_body(), usize::MAX).await?.as_ref(),
        b"A production environment already exists for this project."
    );
    assert_eq!(fixture.environments(&uri).await?.len(), 1);
    Ok(())
}

#[tokio::test]
/// An uncommitted production row forces the HTTP pre-check to miss it, so the
/// blocked insert must report the partial unique index's conflict after commit.
async fn environment_production_index_conflict_survives_a_stale_precheck() -> Result<()> {
    let Some(fixture) = Fixture::new().await? else {
        return Ok(());
    };
    let (project_id, uri) = fixture.project("acme", "core").await?;
    let mut transaction = fixture.db.pool.begin().await?;
    sqlx::query("INSERT INTO environments (project_id, slug, name, tier) VALUES ($1, 'live', 'Live', 'production')")
        .bind(project_id).execute(&mut *transaction).await?;

    let app = fixture.app.clone();
    let token = fixture.token.clone();
    let pending_uri = uri.clone();
    let pending = tokio::spawn(async move {
        request(
            &app,
            &token,
            "POST",
            &pending_uri,
            json!({"name":"Other", "slug":"prod2", "tier":"production"}),
        )
        .await
    });
    // Observe the competing INSERT blocked on the index, rather than assuming
    // scheduling or using a fixed delay to let the request pass its pre-check.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock' AND query LIKE '%INSERT INTO environments%')",
            ).fetch_one(&fixture.db.pool).await?;
            if blocked {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.context("competing environment insert did not reach the index lock")??;

    transaction.commit().await?;
    let response = pending.await.context("environment HTTP task")??;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await?.as_ref(),
        b"A production environment already exists for this project."
    );
    let rows = fixture.environments(&uri).await?;
    assert_eq!(rows.len(), 1);
    assert!(
        rows.iter()
            .all(|row| row.get("slug").and_then(Value::as_str) == Some("live"))
    );
    Ok(())
}
