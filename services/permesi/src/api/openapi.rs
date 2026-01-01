use super::handlers::{auth, health, user_login, user_register};
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
        .routes(routes!(auth::opaque_signup::opaque_signup_start))
        .routes(routes!(auth::opaque_signup::opaque_signup_finish))
        .routes(routes!(auth::opaque_login::opaque_login_start))
        .routes(routes!(auth::opaque_login::opaque_login_finish))
        .routes(routes!(auth::verification::verify_email))
        .routes(routes!(auth::verification::resend_verification));

    let mut permesi_tag = Tag::new("permesi");
    permesi_tag.description = Some("Identity and access management API".to_string());

    let mut auth_tag = Tag::new("auth");
    auth_tag.description = Some("Signup and email verification".to_string());

    router.get_openapi_mut().tags = Some(vec![permesi_tag, auth_tag]);

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
    }
}
