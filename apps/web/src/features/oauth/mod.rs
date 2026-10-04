//! Session-authenticated OAuth management client and shared console models.
//!
//! Flow Overview: routes collect configuration, this client calls the existing
//! cookie-authenticated helpers, and the server validates tenant membership and
//! allow-lists. Credential APIs return plaintext once for ephemeral disclosure; internal
//! scopes never become delegated authority. Token issuance remains deferred.

pub(crate) mod client;
pub(crate) use permesi_web::oauth::{model, paths, scope, types};
