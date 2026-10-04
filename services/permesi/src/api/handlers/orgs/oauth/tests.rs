//! Real-Postgres tests through the production `OpenAPI` router and session extraction.
//!
//! Fixtures reuse existing org test infrastructure. No runtime means an explicit skip;
//! schema/container failures otherwise fail. Assertions cover ACLs, tenant binding,
//! rollback, lifecycle, serialization, and database constraints independently of HTTP validation.

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use tokio::time::{Duration, sleep, timeout};
use tower::ServiceExt;
use uuid::Uuid;

use super::super::{
    storage::create_org_with_roles,
    tests::{TestDb, insert_active_user, insert_member_role, insert_session},
};
use crate::{api::AppState, oauth::client::load_active_client};

struct Fixture {
    db: TestDb,
    router: Router,
    base: String,
    owner: Uuid,
    token: String,
    org: Uuid,
    project: Uuid,
    environment: Uuid,
    application: Uuid,
}

/// Uses the real scope API and database to verify convention validation and compatibility.
#[tokio::test]
async fn oauth_application_scopes_require_resource_action_and_preserve_namespace_rules()
-> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    for name in [
        "jobs:read",
        "runs:execute",
        "runs:cancel",
        "deployments:approve",
        "members:invite",
    ] {
        let (status, scope) = f
            .call(
                "POST",
                "/scopes",
                &f.token,
                Some(json!({"name":name,"description":"Delegated operation"})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{name}: {scope}");
        assert_eq!(scope.get("name").and_then(Value::as_str), Some(name));
        assert_eq!(
            scope.get("kind").and_then(Value::as_str),
            Some("application")
        );
        assert!(scope.get("resource").is_none());
        assert!(scope.get("action").is_none());
        let saved: String = sqlx::query_scalar("SELECT name FROM oauth_scopes WHERE id=$1")
            .bind(id(&scope, "id")?)
            .fetch_one(&f.db.pool)
            .await?;
        assert_eq!(saved, name);
    }
    for name in [
        "jobs",
        "custom.scope+value",
        "urn:example:scope",
        ":read",
        "jobs:",
        "jobs::read",
        "openid",
        "PROFILE",
        "email",
        "address",
        "phone",
        "offline_access",
        "users:invite",
        "Users:write",
        "PLATFORM:manage",
        "jobs:read all",
        "jobs:\\read",
    ] {
        let (status, _) = f
            .call("POST", "/scopes", &f.token, Some(json!({"name":name})))
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_scopes WHERE application_id=$1 AND kind='application'",
    )
    .bind(f.application)
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(count, 5, "Rejected names must not be persisted");
    Ok(())
}

/// Previously configured names stay visible but must be explicitly removed on replacement.
#[tokio::test]
async fn oauth_scope_assignment_rejects_unsupported_names_until_explicitly_removed() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    // An older installation may still have opaque rows. New assignment must fail
    // before replacing the allow-list or revoking any authority.
    sqlx::query("INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'old.opaque','application')")
        .bind(f.application).execute(&f.db.pool).await?;
    let client = f.client("format-check").await?;
    let suffix = format!("/clients/{}/scopes", id(&client, "client_id")?);
    assert_eq!(
        f.call(
            "PUT",
            &suffix,
            &f.token,
            Some(json!({"scopes":["old.opaque"]}))
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.call("GET", &suffix, &f.token, None).await?.1,
        json!(["openid"])
    );
    sqlx::query("INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2 AND name='old.opaque'")
        .bind(id(&client,"id")?).bind(f.application).execute(&f.db.pool).await?;
    assert_eq!(
        f.call(
            "PUT",
            &suffix,
            &f.token,
            Some(json!({"scopes":["openid","old.opaque"]}))
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.call("GET", &suffix, &f.token, None).await?.1,
        json!(["old.opaque", "openid"])
    );
    assert_eq!(
        f.call("PUT", &suffix, &f.token, Some(json!({"scopes":["openid"]})))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.call("GET", &suffix, &f.token, None).await?.1,
        json!(["openid"])
    );
    Ok(())
}

impl Fixture {
    /// Creates active ancestry and a real full session; routes are the production routes.
    async fn new() -> Result<Option<Self>> {
        let Some(db) = TestDb::new().await? else {
            return Ok(None);
        };
        let owner = insert_active_user(&db.pool, "oauth-owner@example.com").await?;
        let token = insert_session(&db.pool, owner).await?;
        let org = create_org_with_roles(&db.pool, owner, "OAuth Org", "oauth-org")
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let org_id = Uuid::parse_str(&org.id)?;
        let (project, environment, application) = insert_application(&db.pool, org_id).await?;
        let (router, _) = crate::api::router().split_for_parts();
        let router = router.with_state(AppState::for_tests(db.pool.clone())?);
        Ok(Some(Self {
            db,
            router,
            owner,
            token,
            org: org_id,
            project,
            environment,
            application,
            base: format!("/v1/orgs/oauth-org/projects/project/envs/prod/apps/{application}/oauth"),
        }))
    }

    /// Sends a session-authenticated request and decodes a response without logging cookies.
    async fn call(
        &self,
        method: &str,
        suffix: &str,
        token: &str,
        payload: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        request(
            &self.router,
            method,
            &format!("{}{suffix}", self.base),
            token,
            payload,
        )
        .await
    }

    /// Registers one confidential client with an HTTPS redirect and protocol allow-list.
    async fn client(&self, name: &str) -> Result<Value> {
        let (status, client) = self
            .call(
                "POST",
                "/clients",
                &self.token,
                Some(json!({
                    "name": name, "client_type": "confidential",
                    "redirect_uris": ["https://example.com/callback"], "scopes": ["openid"],
                })),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{client}");
        Ok(client)
    }
}

/// Inserts complete ancestry below an organization using the canonical schema.
async fn insert_application(pool: &PgPool, org: Uuid) -> Result<(Uuid, Uuid, Uuid)> {
    let project = sqlx::query_scalar(
        "INSERT INTO projects (org_id, slug, name) VALUES ($1, 'project', 'Project') RETURNING id",
    )
    .bind(org)
    .fetch_one(pool)
    .await?;
    let environment = sqlx::query_scalar("INSERT INTO environments (project_id, slug, name, tier) VALUES ($1, 'prod', 'Production', 'production') RETURNING id")
        .bind(project).fetch_one(pool).await?;
    let application = sqlx::query_scalar(
        "INSERT INTO applications (environment_id, name) VALUES ($1, 'Application') RETURNING id",
    )
    .bind(environment)
    .fetch_one(pool)
    .await?;
    Ok((project, environment, application))
}

/// Executes one router request; non-JSON error bodies are retained as test evidence.
async fn request(
    router: &Router,
    method: &str,
    path: &str,
    token: &str,
    payload: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(COOKIE, format!("permesi_session={token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(payload.map_or_else(Body::empty, |value| Body::from(value.to_string())))?,
        )
        .await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    Ok((status, value))
}

/// Reads a UUID response field with a useful assertion failure.
fn id(value: &Value, field: &str) -> Result<Uuid> {
    Ok(Uuid::parse_str(
        value
            .get(field)
            .and_then(Value::as_str)
            .context("missing UUID")?,
    )?)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn oauth_management_requires_active_membership_and_org_manager() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("initial").await?;
    let client_id = id(&client, "client_id")?;
    let mutations = [
        (
            "POST",
            "/clients".to_owned(),
            Some(json!({"name":"forbidden","client_type":"public"})),
        ),
        (
            "PATCH",
            format!("/clients/{client_id}"),
            Some(json!({"name":"forbidden"})),
        ),
        ("DELETE", format!("/clients/{client_id}"), None),
        (
            "PUT",
            format!("/clients/{client_id}/redirect-uris"),
            Some(json!({"redirect_uris":[]})),
        ),
        (
            "PUT",
            format!("/clients/{client_id}/scopes"),
            Some(json!({"scopes":[]})),
        ),
        (
            "POST",
            "/scopes".to_owned(),
            Some(json!({"name":"jobs:read"})),
        ),
        (
            "PATCH",
            format!("/scopes/{}", Uuid::new_v4()),
            Some(json!({"description":"forbidden"})),
        ),
        ("DELETE", format!("/scopes/{}", Uuid::new_v4()), None),
    ];
    for role in ["readonly", "member", "outsider"] {
        let user = insert_active_user(&f.db.pool, &format!("{role}@example.com")).await?;
        let token = insert_session(&f.db.pool, user).await?;
        if role != "outsider" {
            insert_member_role(&f.db.pool, f.org, user, role).await?;
        }
        for (method, suffix, payload) in &mutations {
            assert_eq!(
                f.call(method, suffix, &token, payload.clone()).await?.0,
                StatusCode::NOT_FOUND,
                "{role} {method} {suffix}"
            );
        }
        for suffix in [
            "/clients".to_owned(),
            format!("/clients/{client_id}"),
            format!("/clients/{client_id}/redirect-uris"),
            format!("/clients/{client_id}/scopes"),
            "/scopes".into(),
        ] {
            let expected = if role == "outsider" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::OK
            };
            assert_eq!(f.call("GET", &suffix, &token, None).await?.0, expected);
        }
        if role == "member" {
            // Global operator capabilities do not confer tenant management rights.
            sqlx::query("INSERT INTO platform_operators (user_id) VALUES ($1)")
                .bind(user)
                .execute(&f.db.pool)
                .await?;
            assert_eq!(
                f.call(
                    "POST",
                    "/clients",
                    &token,
                    Some(json!({"name":"global","client_type":"public"}))
                )
                .await?
                .0,
                StatusCode::NOT_FOUND
            );
            sqlx::query("UPDATE org_memberships SET status = 'suspended' WHERE org_id = $1 AND user_id = $2")
                .bind(f.org).bind(user).execute(&f.db.pool).await?;
            assert_eq!(
                f.call("GET", "/clients", &token, None).await?.0,
                StatusCode::NOT_FOUND
            );
        }
    }
    for role in ["owner", "admin"] {
        let user = insert_active_user(&f.db.pool, &format!("manager-{role}@example.com")).await?;
        let token = insert_session(&f.db.pool, user).await?;
        insert_member_role(&f.db.pool, f.org, user, role).await?;
        let (status, created) = f
            .call(
                "POST",
                "/clients",
                &token,
                Some(json!({"name":role,"client_type":"public"})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED);
        let suffix = format!("/clients/{}", id(&created, "client_id")?);
        assert_eq!(
            f.call(
                "PATCH",
                &suffix,
                &token,
                Some(json!({"name":format!("{role}-renamed")}))
            )
            .await?
            .0,
            StatusCode::OK
        );
        assert_eq!(
            f.call("DELETE", &suffix, &token, None).await?.0,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        f.call("GET", "/clients", "", None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
        .bind(f.owner)
        .execute(&f.db.pool)
        .await?;
    let hash = crate::api::handlers::auth::hash_session_token(&f.token);
    sqlx::query("INSERT INTO user_mfa_challenge_sessions (user_id, session_hash, expires_at) VALUES ($1,$2,NOW()+INTERVAL '1 hour')")
        .bind(f.owner).bind(hash).execute(&f.db.pool).await?;
    assert_eq!(
        f.call("GET", "/clients", &f.token, None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[tokio::test]
async fn oauth_clients_and_scope_edges_cannot_cross_application_or_tenant() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("tenant-client").await?;
    let other = create_org_with_roles(&f.db.pool, f.owner, "Other", "other-org")
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let other_org = Uuid::parse_str(&other.id)?;
    let (_, _, other_app) = insert_application(&f.db.pool, other_org).await?;
    let wrong = f
        .base
        .replace(&f.application.to_string(), &other_app.to_string());
    assert_eq!(
        request(
            &f.router,
            "GET",
            &format!("{wrong}/clients"),
            &f.token,
            None
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &f.router,
            "POST",
            &format!("{wrong}/clients"),
            &f.token,
            Some(json!({"name":"wrong","client_type":"public"}))
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    let other_base =
        format!("/v1/orgs/other-org/projects/project/envs/prod/apps/{other_app}/oauth");
    let suffix = format!("/clients/{}", id(&client, "client_id")?);
    assert_eq!(
        request(
            &f.router,
            "GET",
            &format!("{other_base}{suffix}"),
            &f.token,
            None
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    let scope: Uuid = sqlx::query_scalar("INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'other:read','application') RETURNING id")
        .bind(other_app).fetch_one(&f.db.pool).await?;
    let edge = sqlx::query(
        "INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) VALUES ($1,$2,$3)",
    )
    .bind(id(&client, "id")?)
    .bind(f.application)
    .bind(scope)
    .execute(&f.db.pool)
    .await;
    assert!(
        edge.is_err(),
        "database must reject cross-application scope edge"
    );
    assert_eq!(
        f.call(
            "PUT",
            &format!("{suffix}/scopes"),
            &f.token,
            Some(json!({"scopes":["other:read"]}))
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    let grant = sqlx::query("INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4)")
        .bind(f.owner).bind(id(&client,"id")?).bind(f.application).bind(other_org).execute(&f.db.pool).await;
    assert!(
        grant.is_err(),
        "same user in both orgs must not bind a client to the wrong org"
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn oauth_configuration_validates_and_rolls_back_allow_lists() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let (status, scope) = f
        .call(
            "POST",
            "/scopes",
            &f.token,
            Some(json!({"name":"jobs:read","description":"Read jobs"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        f.call(
            "POST",
            "/scopes",
            &f.token,
            Some(json!({"name":"jobs:read"}))
        )
        .await?
        .0,
        StatusCode::CONFLICT
    );
    for name in [
        "openid",
        "OpenID",
        "profile",
        "email",
        "offline_access",
        "platform:admin",
        "users:write",
        "jobs read",
    ] {
        assert_eq!(
            f.call("POST", "/scopes", &f.token, Some(json!({"name":name})))
                .await?
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let client = f.client("configuration").await?;
    let suffix = format!("/clients/{}", id(&client, "client_id")?);
    for scopes in [
        vec!["missing"],
        vec!["openid", "openid"],
        vec!["jobs:read", "missing"],
    ] {
        assert_eq!(
            f.call(
                "PUT",
                &format!("{suffix}/scopes"),
                &f.token,
                Some(json!({"scopes":scopes}))
            )
            .await?
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            f.call("GET", &format!("{suffix}/scopes"), &f.token, None)
                .await?
                .1,
            json!(["openid"])
        );
    }
    assert_eq!(
        f.call(
            "PUT",
            &format!("{suffix}/scopes"),
            &f.token,
            Some(json!({"scopes":["openid","jobs:read"]}))
        )
        .await?
        .0,
        StatusCode::OK
    );
    for uris in [
        vec!["https://example.com/*"],
        vec!["https://example.com/cb#fragment"],
        vec!["https://example.com/cb", "https://example.com/cb"],
        vec!["http://127.0.0.1:8080/cb"],
    ] {
        assert_eq!(
            f.call(
                "PUT",
                &format!("{suffix}/redirect-uris"),
                &f.token,
                Some(json!({"redirect_uris":uris}))
            )
            .await?
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            f.call("GET", &format!("{suffix}/redirect-uris"), &f.token, None)
                .await?
                .1,
            json!(["https://example.com/callback"])
        );
    }
    let protocol: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_scopes WHERE application_id = $1 AND name = 'openid'",
    )
    .bind(f.application)
    .fetch_one(&f.db.pool)
    .await?;
    for (method, payload) in [
        ("PATCH", Some(json!({"description":"hijacked"}))),
        ("DELETE", None),
    ] {
        assert_eq!(
            f.call(method, &format!("/scopes/{protocol}"), &f.token, payload)
                .await?
                .0,
            StatusCode::NOT_FOUND
        );
    }
    let scope_id = id(&scope, "id")?;
    assert_eq!(
        f.call(
            "PATCH",
            &format!("/scopes/{scope_id}"),
            &f.token,
            Some(json!({"description":"Updated"}))
        )
        .await?
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.call("DELETE", &format!("/scopes/{scope_id}"), &f.token, None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call("GET", &format!("{suffix}/scopes"), &f.token, None)
            .await?
            .1,
        json!(["openid"])
    );
    assert_eq!(
        f.call(
            "POST",
            "/scopes",
            &f.token,
            Some(json!({"name":"jobs:read"}))
        )
        .await?
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        f.call("GET", &format!("{suffix}/scopes"), &f.token, None)
            .await?
            .1,
        json!(["openid"])
    );
    for payload in [
        json!({"name":"injected","client_type":"public","application_id":f.application}),
        json!({"name":"injected","client_type":"public","secret_hash":"anything"}),
    ] {
        assert_eq!(
            f.call("POST", "/clients", &f.token, Some(payload)).await?.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    assert_eq!(
        f.call(
            "POST",
            "/clients",
            &f.token,
            Some(json!({"name":"rolled-back","client_type":"public","scopes":["missing"]}))
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_clients WHERE name = 'rolled-back'")
            .fetch_one(&f.db.pool)
            .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn oauth_lifecycle_revokes_authority_and_never_serializes_credentials() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("lifecycle").await?;
    let public_id = id(&client, "client_id")?;
    let internal_id = id(&client, "id")?;
    assert_ne!(public_id, internal_id);
    let suffix = format!("/clients/{public_id}");
    let hash = "$argon2id$v=19$m=65536,t=3,p=1$test-only-hash";
    sqlx::query("INSERT INTO oauth_client_secrets (client_id,secret_hash) VALUES ($1,$2)")
        .bind(internal_id)
        .bind(hash)
        .execute(&f.db.pool)
        .await?;
    let grant: Uuid = sqlx::query_scalar("INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4) RETURNING id")
        .bind(f.owner).bind(internal_id).bind(f.application).bind(f.org).fetch_one(&f.db.pool).await?;
    let protocol: Uuid =
        sqlx::query_scalar("SELECT id FROM oauth_scopes WHERE application_id=$1 AND name='openid'")
            .bind(f.application)
            .fetch_one(&f.db.pool)
            .await?;
    sqlx::query("INSERT INTO oauth_grant_scopes (grant_id,client_id,application_id,scope_id) VALUES ($1,$2,$3,$4)")
        .bind(grant).bind(internal_id).bind(f.application).bind(protocol).execute(&f.db.pool).await?;
    for route in ["/clients", suffix.as_str()] {
        let (_, response) = f.call("GET", route, &f.token, None).await?;
        let serialized = response.to_string();
        for forbidden in [
            hash,
            "secret_hash",
            "client_secret",
            "revoked_at",
            "deleted_at",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
    assert!(
        load_active_client(&f.db.pool, public_id)
            .await?
            .context("active client")?
            .is_active()
    );
    assert_eq!(
        f.call("PATCH", &suffix, &f.token, Some(json!({"disabled":true})))
            .await?
            .0,
        StatusCode::OK
    );
    assert!(load_active_client(&f.db.pool, public_id).await?.is_none());
    let row = sqlx::query("SELECT g.revoked_at IS NOT NULL AS grant_revoked, s.revoked_at IS NOT NULL AS secret_revoked FROM oauth_grants g JOIN oauth_client_secrets s ON s.client_id=g.client_id WHERE g.id=$1")
        .bind(grant).fetch_one(&f.db.pool).await?;
    assert!(row.get::<bool, _>("grant_revoked") && row.get::<bool, _>("secret_revoked"));
    assert_eq!(
        f.call("PATCH", &suffix, &f.token, Some(json!({"disabled":false})))
            .await?
            .0,
        StatusCode::OK
    );
    assert!(load_active_client(&f.db.pool, public_id).await?.is_some());
    assert_eq!(
        f.call("DELETE", &suffix, &f.token, None).await?.0,
        StatusCode::NO_CONTENT
    );
    assert!(load_active_client(&f.db.pool, public_id).await?.is_none());
    assert_eq!(
        f.call("GET", &suffix, &f.token, None).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.call("GET", "/clients", &f.token, None).await?.1,
        json!([])
    );
    Ok(())
}

#[tokio::test]
async fn oauth_clients_require_active_ancestry_and_database_constraints() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("ancestry").await?;
    let public_id = id(&client, "client_id")?;
    for (query, resource) in [
        (
            "UPDATE applications SET deleted_at=CASE WHEN $2 THEN NOW() ELSE NULL END WHERE id=$1",
            f.application,
        ),
        (
            "UPDATE environments SET deleted_at=CASE WHEN $2 THEN NOW() ELSE NULL END WHERE id=$1",
            f.environment,
        ),
        (
            "UPDATE projects SET deleted_at=CASE WHEN $2 THEN NOW() ELSE NULL END WHERE id=$1",
            f.project,
        ),
        (
            "UPDATE organizations SET deleted_at=CASE WHEN $2 THEN NOW() ELSE NULL END WHERE id=$1",
            f.org,
        ),
    ] {
        sqlx::query(query)
            .bind(resource)
            .bind(true)
            .execute(&f.db.pool)
            .await?;
        assert_eq!(
            f.call("GET", "/clients", &f.token, None).await?.0,
            StatusCode::NOT_FOUND
        );
        assert!(load_active_client(&f.db.pool, public_id).await?.is_none());
        sqlx::query(query)
            .bind(resource)
            .bind(false)
            .execute(&f.db.pool)
            .await?;
    }
    let duplicate = sqlx::query("INSERT INTO oauth_client_redirect_uris (client_id,redirect_uri) VALUES ($1,'https://example.com/callback')")
        .bind(id(&client,"id")?).execute(&f.db.pool).await;
    assert!(duplicate.is_err());
    let duplicate = sqlx::query(
        "INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'openid','protocol')",
    )
    .bind(f.application)
    .execute(&f.db.pool)
    .await;
    assert!(duplicate.is_err());
    let redefine = sqlx::query(
        "INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'OpenID','application')",
    )
    .bind(f.application)
    .execute(&f.db.pool)
    .await;
    assert!(redefine.is_err());
    // A valid but unconfigured scope cannot enter a grant through direct SQL.
    let scope: Uuid = sqlx::query_scalar("INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'jobs:read','application') RETURNING id")
        .bind(f.application).fetch_one(&f.db.pool).await?;
    let grant: Uuid = sqlx::query_scalar("INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4) RETURNING id")
        .bind(f.owner).bind(id(&client,"id")?).bind(f.application).bind(f.org).fetch_one(&f.db.pool).await?;
    let edge = sqlx::query("INSERT INTO oauth_grant_scopes (grant_id,client_id,application_id,scope_id) VALUES ($1,$2,$3,$4)")
        .bind(grant).bind(id(&client,"id")?).bind(f.application).bind(scope).execute(&f.db.pool).await;
    assert!(edge.is_err());
    Ok(())
}

#[tokio::test]
async fn oauth_schema_reapplication_backfills_and_preserves_configuration() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("preserved").await?;
    sqlx::query("DROP TRIGGER seed_application_oauth_scopes ON applications")
        .execute(&f.db.pool)
        .await?;
    let unseeded: Uuid = sqlx::query_scalar(
        "INSERT INTO applications (environment_id, name) VALUES ($1, 'Existing app') RETURNING id",
    )
    .bind(f.environment)
    .fetch_one(&f.db.pool)
    .await?;
    let mut connection = f.db.pool.acquire().await?;
    test_support::sql::execute_script(
        &mut connection,
        "02_permesi.sql",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/sql/02_permesi.sql"
        )),
    )
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_scopes WHERE application_id=$1 AND kind='protocol'",
    )
    .bind(unseeded)
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(count, 6);
    let suffix = format!("/clients/{}/scopes", id(&client, "client_id")?);
    assert_eq!(
        f.call("GET", &suffix, &f.token, None).await?.1,
        json!(["openid"])
    );
    assert!(
        load_active_client(&f.db.pool, id(&client, "client_id")?)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn oauth_allow_list_changes_revoke_consent_and_remove_grant_scope_edges() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("consent").await?;
    let internal_id = id(&client, "id")?;
    let grant: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4) RETURNING id",
    ).bind(f.owner).bind(internal_id).bind(f.application).bind(f.org).fetch_one(&f.db.pool).await?;
    let scope: Uuid =
        sqlx::query_scalar("SELECT id FROM oauth_scopes WHERE application_id=$1 AND name='openid'")
            .bind(f.application)
            .fetch_one(&f.db.pool)
            .await?;
    sqlx::query("INSERT INTO oauth_grant_scopes (grant_id,client_id,application_id,scope_id) VALUES ($1,$2,$3,$4)")
        .bind(grant).bind(internal_id).bind(f.application).bind(scope).execute(&f.db.pool).await?;
    let suffix = format!("/clients/{}/scopes", id(&client, "client_id")?);
    assert_eq!(
        f.call("PUT", &suffix, &f.token, Some(json!({"scopes":[]})))
            .await?
            .0,
        StatusCode::OK
    );
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM oauth_grants WHERE id=$1")
            .bind(grant)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(revoked);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_grant_scopes WHERE grant_id=$1")
            .bind(grant)
            .fetch_one(&f.db.pool)
            .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn oauth_grant_insert_rechecks_client_after_concurrent_disable() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("grant-race").await?;
    assert_grant_race_rejected(
        &f,
        id(&client, "id")?,
        "UPDATE oauth_clients SET disabled_at=NOW() WHERE id=$1",
        id(&client, "id")?,
        true,
    )
    .await
}

/// Holds a lifecycle mutation until the grant waits or finishes, then requires rejection.
async fn assert_grant_race_rejected(
    f: &Fixture,
    client_id: Uuid,
    mutation: &'static str,
    target: Uuid,
    client_lock: bool,
) -> Result<()> {
    let mut disable = f.db.pool.begin().await?;
    let disable_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *disable)
        .await?;
    // Match the service's row lock, consent revocation, and lifecycle update.
    if client_lock {
        sqlx::query("SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE")
            .bind(client_id)
            .fetch_one(&mut *disable)
            .await?;
    }
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at=NOW() WHERE client_id=$1 AND revoked_at IS NULL",
    )
    .bind(client_id)
    .execute(&mut *disable)
    .await?;
    sqlx::query(mutation)
        .bind(target)
        .execute(&mut *disable)
        .await?;
    let mut grant_connection = f.db.pool.acquire().await?;
    let grant_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *grant_connection)
        .await?;
    let (user, application, org) = (f.owner, f.application, f.org);
    let insert = tokio::spawn(async move {
        sqlx::query("INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4)")
            .bind(user).bind(client_id).bind(application).bind(org)
            .execute(&mut *grant_connection).await
    });
    // Wait for a real lock dependency instead of relying on scheduling or fixed delays.
    timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $2 = ANY(pg_blocking_pids($1))")
                .bind(grant_pid)
                .bind(disable_pid)
                .fetch_one(&f.db.pool)
                .await?;
            if blocked || insert.is_finished() {
                return Ok::<(), sqlx::Error>(());
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    disable.commit().await?;
    let result = insert.await?;
    assert!(
        result.is_err(),
        "grant must not commit after its tenant context became inactive"
    );
    let error = result.err().context("grant should fail")?;
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_grants WHERE client_id=$1 AND revoked_at IS NULL",
    )
    .bind(client_id)
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn oauth_grant_insert_rechecks_membership_after_concurrent_suspension() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("membership-race").await?;
    assert_grant_race_rejected(
        &f,
        id(&client, "id")?,
        "UPDATE org_memberships SET status='suspended' WHERE user_id=$1",
        f.owner,
        false,
    )
    .await
}

#[tokio::test]
async fn oauth_grant_insert_rechecks_ancestry_after_concurrent_soft_delete() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("ancestry-race").await?;
    for (mutation, restore, target) in [
        (
            "UPDATE applications SET deleted_at=NOW() WHERE id=$1",
            "UPDATE applications SET deleted_at=NULL WHERE id=$1",
            f.application,
        ),
        (
            "UPDATE environments SET deleted_at=NOW() WHERE id=$1",
            "UPDATE environments SET deleted_at=NULL WHERE id=$1",
            f.environment,
        ),
        (
            "UPDATE projects SET deleted_at=NOW() WHERE id=$1",
            "UPDATE projects SET deleted_at=NULL WHERE id=$1",
            f.project,
        ),
        (
            "UPDATE organizations SET deleted_at=NOW() WHERE id=$1",
            "UPDATE organizations SET deleted_at=NULL WHERE id=$1",
            f.org,
        ),
    ] {
        assert_grant_race_rejected(&f, id(&client, "id")?, mutation, target, false).await?;
        sqlx::query(restore)
            .bind(target)
            .execute(&f.db.pool)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn oauth_grant_revocation_is_permanent_and_succeeds_after_suspension() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("permanent-revocation").await?;
    let grant: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4) RETURNING id",
    ).bind(f.owner).bind(id(&client,"id")?).bind(f.application).bind(f.org).fetch_one(&f.db.pool).await?;
    sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
        .bind(f.org)
        .bind(f.owner)
        .execute(&f.db.pool)
        .await?;
    sqlx::query("UPDATE oauth_grants SET revoked_at=NOW() WHERE id=$1")
        .bind(grant)
        .execute(&f.db.pool)
        .await?;
    sqlx::query("UPDATE oauth_clients SET disabled_at=NOW() WHERE id=$1")
        .bind(id(&client, "id")?)
        .execute(&f.db.pool)
        .await?;
    let result = sqlx::query("UPDATE oauth_grants SET revoked_at=NULL WHERE id=$1")
        .bind(grant)
        .execute(&f.db.pool)
        .await;
    assert!(result.is_err(), "revoked consent must never be restored");
    Ok(())
}

#[tokio::test]
async fn oauth_scope_replacement_and_scope_deletion_do_not_deadlock() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let scope: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_scopes (application_id,name,kind) VALUES ($1,'jobs:read','application') RETURNING id",
    ).bind(f.application).fetch_one(&f.db.pool).await?;
    let client = f.client("scope-lock-order").await?;
    let client_id = id(&client, "id")?;
    sqlx::query(
        "INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) VALUES ($1,$2,$3)",
    )
    .bind(client_id)
    .bind(f.application)
    .bind(scope)
    .execute(&f.db.pool)
    .await?;
    let mut delete = f.db.pool.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *delete)
        .await?;
    sqlx::query("SELECT id FROM oauth_scopes WHERE id=$1 FOR UPDATE")
        .bind(scope)
        .fetch_one(&mut *delete)
        .await?;
    let router = f.router.clone();
    let path = format!("{}/clients/{}/scopes", f.base, id(&client, "client_id")?);
    let token = f.token.clone();
    let replace = tokio::spawn(async move {
        request(
            &router,
            "PUT",
            &path,
            &token,
            Some(json!({"scopes":["jobs:read"]})),
        )
        .await
    });
    timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1 = ANY(pg_blocking_pids(pid)))",
            ).bind(pid).fetch_one(&f.db.pool).await?;
            if blocked { return Ok::<(), sqlx::Error>(()) }
            sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    // With the old order, replacement has already locked the scope edge, producing a cycle.
    sqlx::query("DELETE FROM oauth_scopes WHERE id=$1")
        .bind(scope)
        .execute(&mut *delete)
        .await?;
    delete.commit().await?;
    let (status, _) = replace.await??;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "deleted scope should fail validation, without a deadlock/500"
    );
    Ok(())
}

#[tokio::test]
async fn oauth_management_json_rejections_match_documented_status_codes() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    for (body, content_type, expected) in [
        ("{", true, StatusCode::BAD_REQUEST),
        (
            r#"{"name":"client","client_type":123}"#,
            true,
            StatusCode::BAD_REQUEST,
        ),
        (
            r#"{"name":123,"client_type":"public"}"#,
            true,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"name":"client","client_type":"public","unknown":true}"#,
            true,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"name":"client","client_type":"public"}"#,
            false,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{}/clients", f.base))
            .header(COOKIE, format!("permesi_session={}", f.token));
        if content_type {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        let response = f
            .router
            .clone()
            .oneshot(request.body(Body::from(body))?)
            .await?;
        assert_eq!(response.status(), expected, "{body}");
    }
    Ok(())
}
