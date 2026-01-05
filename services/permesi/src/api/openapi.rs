use super::handlers::{auth, health, me, orgs, user_login, user_register};
use utoipa::openapi::{Contact, InfoBuilder, License, OpenApiBuilder, Tag};
use utoipa_axum::{router::OpenApiRouter, routes};

#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    // Reuse the same router wiring and only return the generated OpenAPI spec.
    let (_router, openapi) = api_router().split_for_parts();
    openapi
}

/// Build the router that also drives the `OpenAPI` document.
///
/// Add new endpoints here via `.routes(routes!(...))` so they are both served
/// and included in the generated `OpenAPI` spec.
/// Routes added outside (like `/` or `OPTIONS /health`) are intentionally not documented.
pub(crate) fn api_router() -> OpenApiRouter {
    // `routes!` reads #[utoipa::path] to bind HTTP method + path and add the route to OpenAPI.
    let mut router = OpenApiRouter::with_openapi(cargo_openapi())
        .routes(routes!(health::health))
        .routes(routes!(user_register::register))
        .routes(routes!(user_login::login))
        .routes(routes!(auth::opaque::signup::opaque_signup_start))
        .routes(routes!(auth::opaque::signup::opaque_signup_finish))
        .routes(routes!(auth::opaque::login::opaque_login_start))
        .routes(routes!(auth::opaque::login::opaque_login_finish))
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
        .routes(routes!(orgs::create_org))
        .routes(routes!(orgs::list_orgs))
        .routes(routes!(orgs::get_org))
        .routes(routes!(orgs::patch_org))
        .routes(routes!(orgs::create_project))
        .routes(routes!(orgs::list_projects))
        .routes(routes!(orgs::create_environment))
        .routes(routes!(orgs::list_environments))
        .routes(routes!(orgs::create_application))
        .routes(routes!(orgs::list_applications));

    let mut permesi_tag = Tag::new("permesi");
    permesi_tag.description = Some("Identity and access management API".to_string());

    let mut auth_tag = Tag::new("auth");
    auth_tag.description = Some("Signup and email verification".to_string());

    let mut me_tag = Tag::new("me");
    me_tag.description = Some("Current user self-service endpoints".to_string());

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
        orgs_tag,
        projects_tag,
        environments_tag,
        applications_tag,
    ]);

    router
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn openapi_tags_and_paths() {
        let spec = openapi();
        let tags = spec.tags.clone().unwrap_or_default();
        assert!(tags.iter().any(|tag| tag.name == "permesi"));
        assert!(tags.iter().any(|tag| tag.name == "auth"));
        assert!(
            spec.paths
                .paths
                .contains_key("/v1/auth/resend-verification")
        );
        assert!(spec.paths.paths.contains_key("/v1/auth/session"));
        assert!(spec.paths.paths.contains_key("/v1/auth/logout"));
        assert!(spec.paths.paths.contains_key("/v1/auth/admin/status"));
        assert!(spec.paths.paths.contains_key("/v1/auth/admin/bootstrap"));
        assert!(spec.paths.paths.contains_key("/v1/auth/admin/elevate"));
        assert!(spec.paths.paths.contains_key("/v1/me"));
        assert!(spec.paths.paths.contains_key("/v1/me/sessions"));
        assert!(spec.paths.paths.contains_key("/v1/me/sessions/{sid}"));
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
    }
}
