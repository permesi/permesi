use crate::api::handlers::{headers, health, paserk, token};
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
/// Routes added outside (like `OPTIONS /health`) are intentionally not documented.
pub(crate) fn api_router() -> OpenApiRouter {
    // `routes!` reads #[utoipa::path] to bind HTTP method + path and add the route to OpenAPI.
    let mut router = OpenApiRouter::with_openapi(cargo_openapi())
        .routes(routes!(health::health))
        .routes(routes!(headers::headers))
        .routes(routes!(token::token))
        .routes(routes!(paserk::paserk));

    let mut genesis_tag = Tag::new("genesis");
    genesis_tag.description = Some("Token Zero generator API".to_string());
    router.get_openapi_mut().tags = Some(vec![genesis_tag]);

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
