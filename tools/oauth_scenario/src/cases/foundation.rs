//! Tenant provisioning, scope-registry and discovery assertions.
//! Each case retains its own tenant fixture and verifies the real service boundary.

use crate::error::Safe;

use super::{
    Api, Context, Fixture, Method, Resource, Result, StatusCode, Uuid, Value, check, json,
    text_field,
};

/// Checks real configuration reads and implemented discovery without overstating token support.
pub(super) async fn foundation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let replicas: i64 = sqlx::query_scalar("SELECT count(DISTINCT a.usesysid) FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_roles r ON r.oid=a.usesysid WHERE a.datname=current_database() AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND pg_has_role(r.oid,'permesi_runtime','MEMBER')")
        .fetch_one(context.pool).await.safe("Cannot inspect runtime replica identities.")?;
    check(
        replicas
            >= i64::try_from(context.services.replica_count()).safe("Invalid replica count.")?,
        "Every configured replica requires an independent runtime database identity.",
    )?;
    let orgs: Vec<Resource> = context
        .api
        .json(Method::GET, "/v1/orgs", None, StatusCode::OK)
        .await?;
    check(
        orgs.iter().any(|org| org.id == fixture.org.id),
        "Created organization missing from active list.",
    )?;
    let projects: Vec<Resource> = context
        .api
        .json(
            Method::GET,
            &format!("/v1/orgs/{}/projects", fixture.org.slug),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        projects.iter().any(|project| {
            project.id == fixture.project.id && project.name == fixture.project.name
        }),
        "Project identity/name did not round-trip.",
    )?;
    let envs: Vec<Resource> = context
        .api
        .json(
            Method::GET,
            &format!("{}/envs", fixture.project_path),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        envs.len() == fixture.environments.len(),
        "Environment manifest did not round-trip.",
    )?;
    for (expected, _, _) in &fixture.environments {
        check(
            envs.iter().any(|actual| {
                actual.id == expected.id
                    && actual.slug == expected.slug
                    && actual.name == expected.name
            }),
            "Environment identity/slug/name changed in the API.",
        )?;
    }
    let app = fixture.app()?;
    check(
        app.public.application_id == app.resource.id
            && app.public.client_type == "public"
            && app.confidential.client_type == "confidential",
        "Client classification/application binding is incorrect.",
    )?;
    let registry: Vec<Value> = context
        .api
        .json(
            Method::GET,
            &format!("{}/oauth/scopes", app.path),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        app.scopes.iter().all(|scope| {
            registry
                .iter()
                .any(|entry| entry.get("name").and_then(Value::as_str) == Some(scope))
        }),
        "Custom scope registry did not round-trip.",
    )?;
    immutable_protocol_scopes(context.api, &app.path, &registry).await?;
    // A successful custom DELETE proves the immutable-scope 404s came from an implemented route.
    let probe: Value = context.api.json(Method::POST, &format!("{}/oauth/scopes", app.path), Some(json!({"name":format!("probe-{}:read", Uuid::new_v4().simple()), "description":"Disposable deletion probe"})), StatusCode::CREATED).await?;
    context
        .api
        .status(
            Method::DELETE,
            &format!("{}/oauth/scopes/{}", app.path, text_field(&probe, "id")?),
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
    oidc_metadata(context.api).await?;
    let console = app.path.replacen("/v1/", "/console/", 1);
    context.browser.call(json!({"action":"inspect","actor":"owner","path":format!("{console}/oauth/scopes"),"labels":app.scopes})).await?;
    Ok(())
}

/// Requires every immutable OIDC row before testing deletion; an empty list cannot pass vacuously.
async fn immutable_protocol_scopes(api: &Api, app_path: &str, registry: &[Value]) -> Result<()> {
    let rows = registry
        .iter()
        .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("protocol"))
        .collect::<Vec<_>>();
    let names = rows
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<std::collections::HashSet<_>>();
    let expected = [
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
    ];
    check(
        rows.len() == expected.len()
            && names.len() == expected.len()
            && expected.iter().all(|name| names.contains(name)),
        "Immutable protocol registry is missing or incorrect.",
    )?;
    for entry in rows {
        let id: Uuid = text_field(entry, "id")?
            .parse()
            .safe("Invalid protocol scope identity.")?;
        api.status(
            Method::DELETE,
            &format!("{app_path}/oauth/scopes/{id}"),
            None,
            StatusCode::NOT_FOUND,
        )
        .await?;
    }
    Ok(())
}

/// Checks implemented discovery against explicit issuer/token capabilities and real public keys.
async fn oidc_metadata(api: &Api) -> Result<()> {
    let discovery: Value = api
        .json(
            Method::GET,
            "/.well-known/openid-configuration",
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        discovery.get("issuer").and_then(Value::as_str) == Some(api.origin.as_str())
            && discovery.get("token_endpoint").and_then(Value::as_str)
                == Some(format!("{}/token", api.origin).as_str())
            && discovery
                .get("authorization_response_iss_parameter_supported")
                .and_then(Value::as_bool)
                == Some(true),
        "Discovery overstates implementation or changes issuer.",
    )?;
    let jwks: Value = api
        .json(Method::GET, "/jwks.json", None, StatusCode::OK)
        .await?;
    check(
        jwks.get("keys")
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                !keys.is_empty()
                    && keys.iter().all(|key| {
                        key.get("kty").and_then(Value::as_str) == Some("RSA")
                            && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                                .iter()
                                .all(|private| key.get(private).is_none())
                    })
            }),
        "JWKS omitted public signing keys or exposed private material.",
    )?;
    Ok(())
}
