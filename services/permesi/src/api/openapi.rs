use super::handlers::{auth, authorize, health, me, me_webauthn, orgs, users};
use super::state::AppState;
use utoipa::openapi::{Contact, InfoBuilder, License, OpenApiBuilder, Tag};
use utoipa_axum::{router::OpenApiRouter, routes};

#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    // Reuse the same router wiring and only return the generated OpenAPI spec, with the
    // shared JSON error envelope documented on every error response that has no body.
    let (_router, mut openapi) = api_router().split_for_parts();
    service_utils::api_error::document_error_envelope(&mut openapi);
    openapi
}

/// Build the router that also drives the `OpenAPI` document.
///
/// Add new endpoints here via `.routes(routes!(...))` so they are both served
/// and included in the generated `OpenAPI` spec.
/// Routes added outside (like `/` or `OPTIONS /health`) are intentionally not documented.
pub(crate) fn api_router() -> OpenApiRouter<AppState> {
    let mut router = OpenApiRouter::with_openapi(cargo_openapi())
        .merge(oauth_router())
        .routes(routes!(health::live))
        .routes(routes!(health::ready))
        .routes(routes!(health::health))
        .routes(routes!(auth::opaque::signup::opaque_signup_start))
        .routes(routes!(auth::opaque::signup::opaque_signup_finish))
        .routes(routes!(auth::opaque::login::opaque_login_start))
        .routes(routes!(auth::opaque::login::opaque_login_finish))
        .routes(routes!(auth::passkeys::passkey_login_start))
        .routes(routes!(auth::passkeys::passkey_login_finish))
        .routes(routes!(auth::opaque::reauth::opaque_reauth_start))
        .routes(routes!(auth::opaque::reauth::opaque_reauth_finish))
        .routes(routes!(auth::opaque::password::opaque_password_start))
        .routes(routes!(auth::opaque::password::opaque_password_finish))
        .routes(routes!(auth::mfa::mfa_recovery))
        .routes(routes!(auth::mfa::totp_enroll_start))
        .routes(routes!(auth::mfa::totp_enroll_finish))
        .routes(routes!(auth::mfa::totp_verify))
        .routes(routes!(auth::mfa::webauthn::register_start))
        .routes(routes!(auth::mfa::webauthn::register_finish))
        .routes(routes!(auth::mfa::webauthn::authenticate_start))
        .routes(routes!(auth::mfa::webauthn::authenticate_finish))
        .routes(routes!(auth::verification::verify_email))
        .routes(routes!(auth::verification::resend_verification))
        .routes(routes!(auth::session::session))
        .routes(routes!(auth::session::logout))
        .routes(routes!(auth::admin::admin_status))
        .routes(routes!(auth::admin::admin_infra))
        .routes(routes!(auth::admin::admin_bootstrap))
        .routes(routes!(auth::admin::admin_elevate))
        .routes(routes!(me::get_me))
        .routes(routes!(me::patch_me))
        .routes(routes!(me::list_sessions))
        .routes(routes!(me::revoke_session))
        .routes(routes!(me::disable_totp))
        .routes(routes!(me::list_security_keys))
        .routes(routes!(auth::mfa::webauthn::delete_key))
        .routes(routes!(me_webauthn::register_options))
        .routes(routes!(me_webauthn::register_finish))
        .routes(routes!(me_webauthn::list_credentials))
        .routes(routes!(me_webauthn::delete_credential))
        .routes(routes!(me::regenerate_recovery_codes))
        .routes(routes!(users::list_users))
        .routes(routes!(users::get_user))
        .routes(routes!(users::patch_user))
        .routes(routes!(users::delete_user))
        .routes(routes!(users::set_user_role))
        .merge(tenant_routes())
        .routes(routes!(orgs::oauth::clients::create_client))
        .routes(routes!(orgs::oauth::clients::list_clients))
        .routes(routes!(orgs::oauth::clients::get_client))
        .routes(routes!(orgs::oauth::clients::patch_client))
        .routes(routes!(orgs::oauth::clients::delete_client))
        .routes(routes!(orgs::oauth::clients::get_redirects))
        .routes(routes!(orgs::oauth::clients::replace_redirects))
        .routes(routes!(orgs::oauth::clients::get_client_scopes))
        .routes(routes!(orgs::oauth::clients::replace_client_scopes))
        .routes(routes!(orgs::oauth::scopes::create_scope))
        .routes(routes!(orgs::oauth::scopes::list_scopes))
        .routes(routes!(orgs::oauth::scopes::patch_scope))
        .routes(routes!(orgs::oauth::scopes::delete_scope));

    let mut permesi_tag = Tag::new("permesi");
    permesi_tag.description = Some("Identity and access management API".to_string());

    let mut auth_tag = Tag::new("auth");
    auth_tag.description = Some("Signup and email verification".to_string());

    let mut me_tag = Tag::new("me");
    me_tag.description = Some("Current user self-service endpoints".to_string());

    let mut users_tag = Tag::new("users");
    users_tag.description = Some("Global user management".to_string());

    let mut orgs_tag = Tag::new("orgs");
    orgs_tag.description = Some("Organization endpoints".to_string());

    let mut projects_tag = Tag::new("projects");
    projects_tag.description = Some("Project endpoints".to_string());

    let mut environments_tag = Tag::new("environments");
    environments_tag.description = Some("Environment endpoints".to_string());

    let mut applications_tag = Tag::new("applications");
    applications_tag.description = Some("Application endpoints".to_string());

    router.get_openapi_mut().tags = Some(vec![
        permesi_tag,
        auth_tag,
        me_tag,
        users_tag,
        orgs_tag,
        projects_tag,
        environments_tag,
        applications_tag,
        Tag::new("oauth-clients"),
        Tag::new("oauth-scopes"),
    ]);

    router
}

/// Registers credential management and implemented protocol routes; token issuance is deferred.
fn oauth_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(orgs::oauth::credentials::list_secrets))
        .routes(routes!(orgs::oauth::credentials::create_secret))
        .routes(routes!(orgs::oauth::credentials::rotate_secret))
        .routes(routes!(orgs::oauth::credentials::revoke_secret))
        .layer(axum::middleware::map_response(
            orgs::oauth::credentials::prevent_cache,
        ))
        .routes(routes!(authorize::discovery))
        .routes(routes!(authorize::jwks))
        .routes(routes!(authorize::authorize))
        .routes(routes!(authorize::resume))
        .routes(routes!(authorize::consent))
}

fn cargo_openapi() -> utoipa::openapi::OpenApi {
    // Use Cargo.toml metadata instead of the utoipa-axum crate info defaults.
    let mut info = InfoBuilder::new()
        .title(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .description(optional_str(env!("CARGO_PKG_DESCRIPTION")))
        .build();

    info.contact = cargo_contact();
    info.license = cargo_license();

    OpenApiBuilder::new().info(info).build()
}

fn cargo_contact() -> Option<Contact> {
    // Cargo authors are `;` separated and may include "Name <email>".
    let authors = env!("CARGO_PKG_AUTHORS");
    let primary = authors.split(';').next().map(str::trim)?;
    if primary.is_empty() {
        return None;
    }

    let (name, email) = parse_author(primary);
    if name.is_none() && email.is_none() {
        return None;
    }

    let mut contact = Contact::new();
    contact.name = name.map(str::to_string);
    contact.email = email.map(str::to_string);
    Some(contact)
}

fn cargo_license() -> Option<License> {
    let identifier = optional_str(env!("CARGO_PKG_LICENSE"))?;
    let mut license = License::new(identifier);
    license.identifier = Some(identifier.to_string());
    Some(license)
}

fn optional_str(value: &'static str) -> Option<&'static str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn parse_author(author: &str) -> (Option<&str>, Option<&str>) {
    if let Some(start) = author.find('<') {
        let name = author[..start].trim();
        let email = author[start + 1..].trim_end_matches('>').trim();
        let name = if name.is_empty() { None } else { Some(name) };
        let email = if email.is_empty() { None } else { Some(email) };
        (name, email)
    } else {
        let name = author.trim();
        (if name.is_empty() { None } else { Some(name) }, None)
    }
}

/// Registers tenant management and its explicit bottom-up deletion endpoints.
/// Each handler enforces current session/tenant authority and soft-delete invariants.
fn tenant_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(orgs::organizations::create_org))
        .routes(routes!(orgs::organizations::list_orgs))
        .routes(routes!(orgs::organizations::get_org))
        .routes(routes!(orgs::organizations::patch_org))
        .routes(routes!(orgs::projects::create_project))
        .routes(routes!(orgs::projects::list_projects))
        .routes(routes!(orgs::environments::create_environment))
        .routes(routes!(orgs::environments::list_environments))
        .routes(routes!(orgs::applications::create_application))
        .routes(routes!(orgs::applications::list_applications))
        .routes(routes!(orgs::organizations::delete_org))
        .routes(routes!(orgs::projects::delete_project))
        .routes(routes!(orgs::environments::delete_environment))
        .routes(routes!(orgs::applications::delete_application))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[test]
    fn openapi_info_from_cargo() {
        let spec = openapi();
        assert_eq!(spec.info.title, env!("CARGO_PKG_NAME"));
        assert_eq!(spec.info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            spec.info.description.as_deref(),
            Some(env!("CARGO_PKG_DESCRIPTION"))
        );

        let contact = spec.info.contact;
        assert!(contact.is_some());
        if let Some(contact) = contact {
            assert_eq!(contact.name.as_deref(), Some("Team Permesi"));
            assert_eq!(contact.email.as_deref(), Some("team@permesi.dev"));
        }

        let license = spec.info.license;
        assert!(license.is_some());
        if let Some(license) = license {
            assert_eq!(license.name, "BSD-3-Clause");
            assert_eq!(license.identifier.as_deref(), Some("BSD-3-Clause"));
        }
    }

    /// Every actual lifecycle endpoint advertises success, session, isolation and conflict outcomes.
    #[test]
    fn tenant_deletion_openapi_describes_bottom_up_conflicts() -> Result<()> {
        let document = serde_json::to_value(openapi())?;
        for path in [
            "/v1/orgs/{org_slug}",
            "/v1/orgs/{org_slug}/projects/{project_slug}",
            "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}",
            "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}",
        ] {
            let deletion = document
                .get("paths")
                .and_then(|paths| paths.get(path))
                .and_then(|operations| operations.get("delete"))
                .context("Missing DELETE endpoint")?;
            let responses = deletion.get("responses").context("Missing responses")?;
            for status in ["204", "401", "404", "409"] {
                assert!(responses.get(status).is_some(), "{path}: {status}");
            }
            assert!(
                deletion.get("requestBody").is_none(),
                "Deletion accepts no recursive options"
            );
        }
        Ok(())
    }

    #[test]
    fn openapi_tags_and_paths() -> Result<()> {
        let spec = openapi();
        let tags = spec.tags.clone().unwrap_or_default();
        assert!(tags.iter().any(|tag| tag.name == "permesi"));
        assert!(tags.iter().any(|tag| tag.name == "auth"));
        assert!(spec.paths.paths.contains_key("/live"));
        assert!(spec.paths.paths.contains_key("/ready"));
        assert!(spec.paths.paths.contains_key("/health"));
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/auth/opaque/signup/start")
        );
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/auth/opaque/signup/finish")
        );
        assert!(spec.paths.paths.contains_key("/v1/auth/opaque/login/start"));
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/auth/opaque/login/finish")
        );
        assert!(!spec.paths.paths.contains_key("/user/login"));
        assert!(!spec.paths.paths.contains_key("/user/register"));
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/auth/resend-verification")
        );
        assert!(spec.paths.paths.contains_key("/v1/auth/mfa/recovery"));
        assert!(spec.paths.paths.contains_key("/v1/auth/session"));
        assert!(spec.paths.paths.contains_key("/v1/auth/logout"));
        assert!(spec.paths.paths.contains_key("/v1/auth/admin/status"));
        assert!(spec.paths.paths.contains_key("/v1/auth/admin/bootstrap"));
        assert!(spec.paths.paths.contains_key("/v1/auth/admin/elevate"));
        assert!(spec.paths.paths.contains_key("/v1/me"));
        assert!(spec.paths.paths.contains_key("/v1/me/sessions"));
        assert!(spec.paths.paths.contains_key("/v1/me/sessions/{sid}"));
        assert!(spec.paths.paths.contains_key("/v1/me/mfa/recovery-codes"));
        assert!(spec.paths.paths.contains_key("/v1/orgs"));
        assert!(spec.paths.paths.contains_key("/v1/orgs/{org_slug}"));
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/orgs/{org_slug}/projects")
        );
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/orgs/{org_slug}/projects/{project_slug}/envs")
        );
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps")
        );

        let document = serde_json::to_string(&spec)?;
        assert!(!document.contains("\"UserLogin\""));
        assert!(!document.contains("\"UserRegister\""));
        Ok(())
    }

    #[tokio::test]
    async fn legacy_password_routes_are_not_registered() -> Result<()> {
        // The full router needs its state even though no handler runs for these paths.
        let pool =
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?;
        let (router, _) = api_router().split_for_parts();
        let router = router.with_state(AppState::for_tests(pool)?);

        for path in ["/user/login", "/user/register"] {
            let response = router
                .clone()
                .oneshot(Request::post(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }

        Ok(())
    }

    #[test]
    fn oauth_openapi_registers_implemented_endpoints_without_token_placeholders() -> Result<()> {
        let spec = openapi();
        let base =
            "/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}/oauth";
        for suffix in [
            "/clients",
            "/clients/{client_id}",
            "/clients/{client_id}/redirect-uris",
            "/clients/{client_id}/scopes",
            "/scopes",
            "/scopes/{scope_id}",
        ] {
            assert!(spec.paths.paths.contains_key(&format!("{base}{suffix}")));
        }
        for path in ["/token", "/jwks"] {
            assert!(!spec.paths.paths.contains_key(path));
        }
        for path in [
            "/authorize",
            "/authorize/resume",
            "/authorize/consent",
            "/.well-known/openid-configuration",
            "/jwks.json",
        ] {
            assert!(spec.paths.paths.contains_key(path));
        }
        let tags = spec.tags.as_ref().context("OpenAPI tags missing")?;
        for name in ["oauth-clients", "oauth-scopes"] {
            assert!(tags.iter().any(|tag| tag.name == name));
        }
        let document = serde_json::to_string(&spec)?;
        assert!(!document.contains("secret_hash"));
        let json = serde_json::to_value(&spec)?;
        let schemas = json
            .get("components")
            .and_then(|v| v.get("schemas"))
            .context("missing components")?
            .as_object()
            .context("missing schemas")?;
        for (name, schema) in schemas {
            assert_eq!(
                schema
                    .get("properties")
                    .and_then(|v| v.get("client_secret"))
                    .is_some(),
                name == "IssuedSecretResponse",
                "{name}"
            );
        }
        let issuance = "#/components/schemas/IssuedSecretResponse";
        let exposed: Vec<_> = json
            .get("paths")
            .context("missing paths")?
            .as_object()
            .context("missing paths")?
            .iter()
            .filter(|(_, value)| value.to_string().contains(issuance))
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(
            exposed,
            vec![
                format!("{base}/clients/{{client_id}}/secrets"),
                format!("{base}/clients/{{client_id}}/secrets/rotate")
            ]
        );
        let json = serde_json::to_value(&spec)?;
        let paths = json
            .get("paths")
            .and_then(serde_json::Value::as_object)
            .context("missing paths")?;
        for (path, methods) in paths.iter().filter(|(path, _)| path.starts_with(base)) {
            for (method, operation) in methods.as_object().context("missing methods")? {
                let responses = operation.get("responses").context("missing responses")?;
                if operation.get("requestBody").is_some() {
                    assert!(responses.get("415").is_some(), "{path} {method}");
                    assert!(responses.get("422").is_some(), "{path} {method}");
                } else {
                    assert!(responses.get("415").is_none(), "{path} {method}");
                    assert!(responses.get("422").is_none(), "{path} {method}");
                }
                if method == "get" || method == "delete" {
                    assert!(responses.get("409").is_none(), "{path} {method}");
                }
            }
        }
        assert_eq!(document, serde_json::to_string(&openapi())?);
        Ok(())
    }
}
