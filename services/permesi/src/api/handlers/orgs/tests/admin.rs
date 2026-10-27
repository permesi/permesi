//! Production-router regressions for operator inspection and unchanged tenant authority.

use super::{TestDb, insert_active_user, insert_member_role, insert_session};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod boundaries;
mod browser;
mod pagination;

struct Tree {
    org: Uuid,
    project: Uuid,
    environment: Uuid,
    application: Uuid,
    slug: String,
}

impl Tree {
    /// Seeds retained tenant metadata under exact foreign-key ancestry.
    async fn new(pool: &PgPool, creator: Uuid, slug: &str) -> Result<Self> {
        let org = sqlx::query_scalar(
            "INSERT INTO organizations(slug,name,created_by) VALUES($1,$1,$2) RETURNING id",
        )
        .bind(slug)
        .bind(creator)
        .fetch_one(pool)
        .await?;
        sqlx::query("INSERT INTO org_roles(org_id,name) VALUES($1,'owner')")
            .bind(org)
            .execute(pool)
            .await?;
        insert_member_role(pool, org, creator, "owner").await?;
        let project = sqlx::query_scalar(
            "INSERT INTO projects(org_id,slug,name) VALUES($1,'main','Main project') RETURNING id",
        )
        .bind(org)
        .fetch_one(pool)
        .await?;
        let environment = sqlx::query_scalar("INSERT INTO environments(project_id,slug,name) VALUES($1,'test','Test environment') RETURNING id")
            .bind(project).fetch_one(pool).await?;
        let application = sqlx::query_scalar(
            "INSERT INTO applications(environment_id,name) VALUES($1,'Application') RETURNING id",
        )
        .bind(environment)
        .fetch_one(pool)
        .await?;
        Ok(Self {
            org,
            project,
            environment,
            application,
            slug: slug.to_owned(),
        })
    }

    /// Enumerates collection/detail URLs through the complete tenant ancestry.
    fn paths(&self, prefix: &str) -> Vec<String> {
        let org = format!("{prefix}/{}", self.slug);
        let project = format!("{org}/projects/main");
        let environment = format!("{project}/envs/test");
        vec![
            prefix.to_owned(),
            org.clone(),
            format!("{org}/projects"),
            project.clone(),
            format!("{project}/envs"),
            environment.clone(),
            format!("{environment}/apps"),
            format!("{environment}/apps/{}", self.application),
        ]
    }
}

struct Fixture {
    db: TestDb,
    router: Router,
    operator: Uuid,
    token: String,
    ordinary: Uuid,
    ordinary_token: String,
    own: Tree,
    foreign: Tree,
}

impl Fixture {
    /// Requires real PostgreSQL and uses the same router and authorization as production.
    async fn new() -> Result<Self> {
        let db = TestDb::new()
            .await?
            .context("Admin regressions require PostgreSQL; a skip is not coverage")?;
        let operator = insert_active_user(&db.pool, "operator@inspection.test").await?;
        let ordinary = insert_active_user(&db.pool, "owner@inspection.test").await?;
        sqlx::query("INSERT INTO platform_operators(user_id) VALUES($1)")
            .bind(operator)
            .execute(&db.pool)
            .await?;
        let token = insert_session(&db.pool, operator).await?;
        let ordinary_token = insert_session(&db.pool, ordinary).await?;
        let own = Tree::new(&db.pool, operator, "operator-owned").await?;
        let foreign = Tree::new(&db.pool, ordinary, "foreign-owned").await?;
        let state = crate::api::AppState::for_tests(db.pool.clone())?;
        let router = crate::api::with_response_policy(
            crate::api::router()
                .split_for_parts()
                .0
                .with_state(state.clone()),
        );
        Ok(Self {
            db,
            router,
            operator,
            token,
            ordinary,
            ordinary_token,
            own,
            foreign,
        })
    }

    /// Captures protected tenant state, excluding session last-seen bookkeeping.
    async fn snapshot(&self) -> Result<String> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM organizations t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM projects t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM environments t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM applications t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY org_id,user_id) FROM org_memberships t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY org_id,user_id,role_name) FROM org_member_roles t))::text").fetch_one(&self.db.pool).await?)
    }
}

/// Sends real HTTP requests without printing session material or response contents.
async fn request(
    router: &Router,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder().method(method).uri(path);
    if !token.is_empty() {
        builder = builder.header(COOKIE, format!("permesi_session={token}"));
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .header(CONTENT_TYPE, "application/json")
                .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

/// An operator's organization membership must not restrict the separate global directory.
#[tokio::test]
async fn operator_inspects_foreign_hierarchy_without_changing_tenant_authority() -> Result<()> {
    let f = Fixture::new().await?;
    let before = f.snapshot().await?;
    let enabled: bool =
        sqlx::query_scalar("SELECT enabled FROM platform_operators WHERE user_id=$1")
            .bind(f.operator)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(enabled);
    let (_, ordinary) = request(&f.router, &f.ordinary_token, "GET", "/v1/orgs", None).await?;
    assert_eq!(ordinary.as_array().context("ordinary owner list")?.len(), 1);
    let owner: Uuid = sqlx::query_scalar("SELECT created_by FROM organizations WHERE id=$1")
        .bind(f.foreign.org)
        .fetch_one(&f.db.pool)
        .await?;
    assert_eq!(owner, f.ordinary);
    for (path, expected) in [
        (
            format!("/v1/admin/orgs/{}/projects/main", f.foreign.slug),
            f.foreign.project,
        ),
        (
            format!("/v1/admin/orgs/{}/projects/main/envs/test", f.foreign.slug),
            f.foreign.environment,
        ),
    ] {
        let (status, body) = request(&f.router, &f.token, "GET", &path, None).await?;
        assert_eq!(status, StatusCode::OK, "operator inspection route {path}");
        assert_eq!(body.get("id"), Some(&json!(expected.to_string())));
    }
    for path in f.foreign.paths("/v1/admin/orgs") {
        let (status, body) = request(&f.router, &f.token, "GET", &path, None).await?;
        assert_eq!(status, StatusCode::OK, "operator inspection route {path}");
        assert_collection_metadata(&f.foreign, &path, &body);
    }
    let (status, own) = request(&f.router, &f.token, "GET", "/v1/orgs", None).await?;
    assert_eq!(status, StatusCode::OK);
    let own = own.as_array().context("ordinary organization list")?;
    assert_eq!(own.len(), 1);
    assert_eq!(
        own.first().context("owned organization")?["id"],
        f.own.org.to_string()
    );
    let foreign = format!("/v1/orgs/{}", f.foreign.slug);
    for (method, path, body) in [
        ("GET", foreign.clone(), None),
        ("GET", format!("{foreign}/projects"), None),
        (
            "POST",
            format!("{foreign}/projects"),
            Some(json!({"name":"Forbidden"})),
        ),
        ("PATCH", foreign.clone(), Some(json!({"name":"Forbidden"}))),
        ("DELETE", foreign, None),
    ] {
        assert_eq!(
            request(&f.router, &f.token, method, &path, body).await?.0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(f.snapshot().await?, before);
    Ok(())
}

/// Checks collection contents, not only successful statuses, under duplicate sibling slugs.
fn assert_collection_metadata(tree: &Tree, path: &str, body: &Value) {
    let expected = if path.ends_with("/projects") || path.ends_with("/projects/main") {
        tree.project
    } else if path.ends_with("/envs") || path.ends_with("/envs/test") {
        tree.environment
    } else if path.contains("/apps") {
        tree.application
    } else {
        tree.org
    };
    let metadata_only = |row: &Value| {
        row.as_object().is_some_and(|fields| {
            fields
                .keys()
                .all(|key| ["id", "name", "slug", "tier", "created_at"].contains(&key.as_str()))
        })
    };
    if let Some(items) = body.get("items").and_then(Value::as_array) {
        assert_eq!(items.len(), if path == "/v1/admin/orgs" { 2 } else { 1 });
        assert!(
            items
                .iter()
                .any(|row| row.get("id") == Some(&json!(expected.to_string())))
        );
        assert!(items.iter().all(metadata_only));
    } else {
        assert_eq!(body.get("id"), Some(&json!(expected.to_string())));
        assert!(metadata_only(body));
    }
}
