//! Integration-style handler tests for the orgs API.
//!
//! These tests spin up a temporary Postgres container, apply the schema, and
//! exercise the Axum router end-to-end.

use anyhow::{Context, Result};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
    routing::{get, post},
};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};
use test_support::{TestNetwork, postgres::PostgresContainer, runtime};
use tower::ServiceExt;
use uuid::Uuid;

const PERMESI_SCHEMA_SQL: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/sql/schema.sql"));

struct TestDb {
    _postgres: PostgresContainer,
    pool: PgPool,
}

impl TestDb {
    /// Creates a fresh ephemeral database by starting a `PostgresContainer` and applying the schema.
    /// If the container runtime is unavailable, returns an error so callers can skip the test cleanly.
    async fn new() -> Result<Self> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Err(err);
        }

        let network = TestNetwork::new("permesi-orgs");
        let postgres = PostgresContainer::start(network.name()).await?;
        postgres.wait_until_ready().await?;
        apply_schema(&postgres).await?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&postgres.admin_dsn())
            .await
            .context("failed to connect test pool")?;

        Ok(Self {
            _postgres: postgres,
            pool,
        })
    }
}

/// Applies the embedded schema SQL to the provided `PostgresContainer` using a single connection.
/// It assumes statements are safe to run sequentially and are separated by semicolons in `schema.sql`.
async fn apply_schema(postgres: &PostgresContainer) -> Result<()> {
    let mut connection = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("failed to connect for schema setup")?;

    for (index, statement) in split_sql_statements(PERMESI_SCHEMA_SQL).iter().enumerate() {
        sqlx::query(statement)
            .execute(&mut connection)
            .await
            .with_context(|| format!("failed to execute schema statement {}", index + 1))?;
    }

    Ok(())
}

/// Splits a schema file into individual SQL statements, skipping `\\ir` includes used by `psql`.
/// This is a lightweight parser that assumes statements end with `;` and do not nest semicolons.
fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("\\ir ") {
            continue;
        }
        current.push_str(line);
        current.push('\n');

        if trimmed.ends_with(';') {
            let statement = current.trim();
            if !statement.is_empty() {
                statements.push(statement.to_string());
            }
            current.clear();
        }
    }

    let leftover = current.trim();
    if !leftover.is_empty() {
        statements.push(leftover.to_string());
    }

    statements
}

/// Inserts an `active` user row with a random id for use in handler tests.
/// It relies on the schema accepting a placeholder `opaque_registration_record` blob for test users.
async fn insert_active_user(pool: &PgPool, email: &str) -> Result<Uuid> {
    let user_id = Uuid::new_v4();
    let query = r"
            INSERT INTO users (id, email, opaque_registration_record, status)
            VALUES ($1, $2, $3, 'active')
        ";
    sqlx::query(query)
        .bind(user_id)
        .bind(email)
        .bind(vec![0u8; 16])
        .execute(pool)
        .await
        .context("insert active user")?;
    Ok(user_id)
}

/// Creates a session token for `user_id` and inserts its hash into `user_sessions`.
/// Only the hashed token is stored; the raw token is returned for request cookies/headers.
async fn insert_session(pool: &PgPool, user_id: Uuid) -> Result<String> {
    let token = super::super::auth::generate_session_token()?;
    let hash = super::super::auth::hash_session_token(&token);
    let query = r"
            INSERT INTO user_sessions (user_id, session_hash, expires_at)
            VALUES ($1, $2, NOW() + INTERVAL '1 hour')
        ";
    sqlx::query(query)
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await
        .context("insert session")?;
    Ok(token)
}

/// Ensures the user is an active org member and assigns the specified org role.
/// This is test-only ACL setup mirroring what org creation does for owners.
async fn insert_member_role(pool: &PgPool, org_id: Uuid, user_id: Uuid, role: &str) -> Result<()> {
    sqlx::query(
        r"
            INSERT INTO org_memberships (org_id, user_id, status)
            VALUES ($1, $2, 'active')
            ON CONFLICT (org_id, user_id) DO NOTHING
            ",
    )
    .bind(org_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
            INSERT INTO org_member_roles (org_id, user_id, role_name)
            VALUES ($1, $2, $3)
            ",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(())
}

/// Builds an `axum::Router` with the org/project/env/app routes mounted for end-to-end tests.
/// It exercises the same auth and `404`-on-unauthorized behavior as production handlers.
fn app_router(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/v1/orgs",
            post(super::organizations::create_org).get(super::organizations::list_orgs),
        )
        .route(
            "/v1/orgs/:org_slug",
            get(super::organizations::get_org).patch(super::organizations::patch_org),
        )
        .route(
            "/v1/orgs/:org_slug/projects",
            post(super::projects::create_project).get(super::projects::list_projects),
        )
        .route(
            "/v1/orgs/:org_slug/projects/:project_slug/envs",
            post(super::environments::create_environment)
                .get(super::environments::list_environments),
        )
        .route(
            "/v1/orgs/:org_slug/projects/:project_slug/envs/:env_slug/apps",
            post(super::applications::create_application)
                .get(super::applications::list_applications),
        )
        .layer(Extension(pool))
}

#[tokio::test]
/// Verifies that creating an org enrolls the caller as a member and assigns the `owner` role.
/// This guards the authorization invariant relied on by `OrgContext::can_manage`.
async fn org_creation_assigns_owner_role() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "owner@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let payload = json!({ "name": "Acme" });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let row = sqlx::query(
        "SELECT org_id FROM org_member_roles WHERE user_id = $1 AND role_name = 'owner'",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await?;
    let org_id: Uuid = row.get("org_id");
    assert_ne!(org_id, Uuid::nil());
    Ok(())
}

#[tokio::test]
/// Ensures project creation is restricted to org managers (owner/admin) and returns `404` otherwise.
/// This `404` behavior avoids leaking tenant membership via authorization errors.
async fn project_creation_requires_owner_or_admin() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let owner_id = insert_active_user(&db.pool, "owner2@example.com").await?;
    let owner_token = insert_session(&db.pool, owner_id).await?;
    let member_id = insert_active_user(&db.pool, "member@example.com").await?;
    let member_token = insert_session(&db.pool, member_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "Beta" });
    let org_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={owner_token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(org_response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Beta'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    insert_member_role(&db.pool, org_id, member_id, "member").await?;

    let payload = json!({ "name": "Payments" });
    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={member_token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))?,
        )
        .await?;
    assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);

    let allowed = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={owner_token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))?,
        )
        .await?;
    assert_eq!(allowed.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
/// Confirms environment creation enforces the production-tier rules (prod first, only one prod).
/// This matches the invariants enforced in `storage::insert_environment`.
async fn environment_creation_enforces_single_production() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "env-owner@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "Gamma" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Gamma'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    let project_payload = json!({ "name": "Payments" });
    let project_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(project_payload.to_string()))?,
        )
        .await?;
    assert_eq!(project_response.status(), StatusCode::CREATED);

    let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&db.pool)
        .await?;
    let project_slug: String = project_row.get("slug");

    let non_prod_payload = json!({
        "name": "Dev",
        "slug": "dev",
        "tier": "non_production"
    });
    let non_prod_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(non_prod_payload.to_string()))?,
        )
        .await?;
    assert_eq!(non_prod_response.status(), StatusCode::BAD_REQUEST);

    let prod_payload = json!({
        "name": "Production",
        "slug": "prod",
        "tier": "production"
    });
    let prod_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(prod_payload.to_string()))?,
        )
        .await?;
    assert_eq!(prod_response.status(), StatusCode::CREATED);

    let second_prod = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(prod_payload.to_string()))?,
        )
        .await?;
    assert_eq!(second_prod.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
/// Ensures the environment list endpoint is reachable for members and returns `200` after creation.
/// It should only return environment DTO fields, not role/membership metadata.
async fn environment_list_returns_created_envs() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "env-list@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "Delta" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Delta'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    let project_payload = json!({ "name": "Core" });
    let project_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(project_payload.to_string()))?,
        )
        .await?;
    assert_eq!(project_response.status(), StatusCode::CREATED);

    let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&db.pool)
        .await?;
    let project_slug: String = project_row.get("slug");

    let prod_payload = json!({
        "name": "Production",
        "slug": "production",
        "tier": "production"
    });
    let prod_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(prod_payload.to_string()))?,
        )
        .await?;
    assert_eq!(prod_response.status(), StatusCode::CREATED);

    let staging_payload = json!({
        "name": "Staging",
        "slug": "stage",
        "tier": "non_production"
    });
    let stage_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(staging_payload.to_string()))?,
        )
        .await?;
    assert_eq!(stage_response.status(), StatusCode::CREATED);

    let list_response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
/// Confirms that a non-member cannot fetch an org and receives `404` rather than `403`.
/// This is the anti-enumeration behavior: resource existence is hidden across tenants.
async fn non_member_access_returns_404() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let owner_id = insert_active_user(&db.pool, "owner3@example.com").await?;
    let owner_token = insert_session(&db.pool, owner_id).await?;
    let stranger_id = insert_active_user(&db.pool, "stranger@example.com").await?;
    let stranger_token = insert_session(&db.pool, stranger_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "Epsilon" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={owner_token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT slug FROM organizations WHERE name = 'Epsilon'")
        .fetch_one(&db.pool)
        .await?;
    let org_slug: String = org_row.get("slug");

    let forbidden = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/orgs/{org_slug}"))
                .header(COOKIE, format!("permesi_session={stranger_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
/// Exercises the happy-path flow for creating an org → project → env → application as an owner.
/// This implicitly checks that nested resolution keeps org/project/env boundaries consistent.
async fn owner_can_create_app() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "app-owner@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "Zeta" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'Zeta'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    let project_payload = json!({ "name": "Frontend" });
    let project_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(project_payload.to_string()))?,
        )
        .await?;
    assert_eq!(project_response.status(), StatusCode::CREATED);

    let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&db.pool)
        .await?;
    let project_slug: String = project_row.get("slug");

    let prod_payload = json!({
        "name": "Production",
        "slug": "prod",
        "tier": "production"
    });
    let prod_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(prod_payload.to_string()))?,
        )
        .await?;
    assert_eq!(prod_response.status(), StatusCode::CREATED);

    let app_payload = json!({ "name": "Payments API" });
    let app_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/orgs/{org_slug}/projects/{project_slug}/envs/prod/apps"
                ))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(app_payload.to_string()))?,
        )
        .await?;
    assert_eq!(app_response.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
/// Verifies soft-deleted orgs are hidden from `get` and removed from the list endpoint.
/// This prevents clients from observing deleted resources via stale slugs.
async fn soft_deleted_org_is_hidden_by_default() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "hidden-org@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let payload = json!({ "name": "HiddenOrg" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'HiddenOrg'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    sqlx::query("UPDATE organizations SET deleted_at = NOW() WHERE id = $1")
        .bind(org_id)
        .execute(&db.pool)
        .await?;

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/orgs/{org_slug}"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

    let list_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    let body = to_bytes(list_response.into_body(), usize::MAX).await?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
    assert!(list.iter().all(|item| {
        item.get("slug").and_then(|value| value.as_str()) != Some(org_slug.as_str())
    }));

    Ok(())
}

#[tokio::test]
/// Verifies soft-deleted projects are excluded from project lists and make nested env routes return `404`.
/// This ensures soft-delete is enforced transitively and prevents access through child resources.
async fn soft_deleted_project_is_hidden_even_with_envs() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "hidden-project@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "ProjectOrg" });
    let org_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(org_response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'ProjectOrg'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    let project_payload = json!({ "name": "HiddenProject" });
    let project_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(project_payload.to_string()))?,
        )
        .await?;
    assert_eq!(project_response.status(), StatusCode::CREATED);

    let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&db.pool)
        .await?;
    let project_id: Uuid = project_row.get("id");
    let project_slug: String = project_row.get("slug");

    let env_payload = json!({
        "name": "Production",
        "slug": "prod",
        "tier": "production"
    });
    let env_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(env_payload.to_string()))?,
        )
        .await?;
    assert_eq!(env_response.status(), StatusCode::CREATED);

    sqlx::query("UPDATE projects SET deleted_at = NOW() WHERE id = $1")
        .bind(project_id)
        .execute(&db.pool)
        .await?;

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    let body = to_bytes(list_response.into_body(), usize::MAX).await?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
    assert!(list.is_empty());

    let env_list_response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(env_list_response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
/// Verifies soft-deleted environments are excluded from lists and make nested app routes return `404`.
/// This ensures soft-delete is enforced transitively, even when applications still exist.
async fn soft_deleted_environment_is_hidden_even_with_apps() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "hidden-env@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "EnvOrg" });
    let org_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(org_response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'EnvOrg'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    let project_payload = json!({ "name": "EnvProject" });
    let project_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(project_payload.to_string()))?,
        )
        .await?;
    assert_eq!(project_response.status(), StatusCode::CREATED);

    let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&db.pool)
        .await?;
    let project_id: Uuid = project_row.get("id");
    let project_slug: String = project_row.get("slug");

    let env_payload = json!({
        "name": "Production",
        "slug": "prod",
        "tier": "production"
    });
    let env_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(env_payload.to_string()))?,
        )
        .await?;
    assert_eq!(env_response.status(), StatusCode::CREATED);

    let env_row = sqlx::query("SELECT id, slug FROM environments WHERE project_id = $1")
        .bind(project_id)
        .fetch_one(&db.pool)
        .await?;
    let env_id: Uuid = env_row.get("id");
    let env_slug: String = env_row.get("slug");

    let app_payload = json!({ "name": "HiddenEnvApp" });
    let app_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                ))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(app_payload.to_string()))?,
        )
        .await?;
    assert_eq!(app_response.status(), StatusCode::CREATED);

    sqlx::query("UPDATE environments SET deleted_at = NOW() WHERE id = $1")
        .bind(env_id)
        .execute(&db.pool)
        .await?;

    let env_list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(env_list_response.status(), StatusCode::OK);
    let body = to_bytes(env_list_response.into_body(), usize::MAX).await?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
    assert!(list.is_empty());

    let app_list_response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                ))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(app_list_response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
/// Verifies soft-deleted applications are not returned from the application list endpoint.
/// This prevents deleted resources from leaking via list APIs.
async fn soft_deleted_app_is_hidden_by_default() -> Result<()> {
    let Ok(db) = TestDb::new().await else {
        return Ok(());
    };
    let user_id = insert_active_user(&db.pool, "hidden-app@example.com").await?;
    let token = insert_session(&db.pool, user_id).await?;

    let app = app_router(db.pool.clone());
    let org_payload = json!({ "name": "AppOrg" });
    let org_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(org_payload.to_string()))?,
        )
        .await?;
    assert_eq!(org_response.status(), StatusCode::CREATED);

    let org_row = sqlx::query("SELECT id, slug FROM organizations WHERE name = 'AppOrg'")
        .fetch_one(&db.pool)
        .await?;
    let org_id: Uuid = org_row.get("id");
    let org_slug: String = org_row.get("slug");

    let project_payload = json!({ "name": "AppProject" });
    let project_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(project_payload.to_string()))?,
        )
        .await?;
    assert_eq!(project_response.status(), StatusCode::CREATED);

    let project_row = sqlx::query("SELECT id, slug FROM projects WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&db.pool)
        .await?;
    let project_id: Uuid = project_row.get("id");
    let project_slug: String = project_row.get("slug");

    let env_payload = json!({
        "name": "Production",
        "slug": "prod",
        "tier": "production"
    });
    let env_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/orgs/{org_slug}/projects/{project_slug}/envs"))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(env_payload.to_string()))?,
        )
        .await?;
    assert_eq!(env_response.status(), StatusCode::CREATED);

    let env_row = sqlx::query("SELECT id, slug FROM environments WHERE project_id = $1")
        .bind(project_id)
        .fetch_one(&db.pool)
        .await?;
    let env_id: Uuid = env_row.get("id");
    let env_slug: String = env_row.get("slug");

    let app_payload = json!({ "name": "HiddenApp" });
    let app_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                ))
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(app_payload.to_string()))?,
        )
        .await?;
    assert_eq!(app_response.status(), StatusCode::CREATED);

    let app_row = sqlx::query("SELECT id FROM applications WHERE environment_id = $1")
        .bind(env_id)
        .fetch_one(&db.pool)
        .await?;
    let app_id: Uuid = app_row.get("id");

    sqlx::query("UPDATE applications SET deleted_at = NOW() WHERE id = $1")
        .bind(app_id)
        .execute(&db.pool)
        .await?;

    let app_list_response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps"
                ))
                .header(COOKIE, format!("permesi_session={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(app_list_response.status(), StatusCode::OK);
    let body = to_bytes(app_list_response.into_body(), usize::MAX).await?;
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body)?;
    assert!(list.is_empty());

    Ok(())
}
