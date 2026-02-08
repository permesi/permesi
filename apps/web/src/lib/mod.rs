//! Shared frontend utilities for API access, configuration, errors, and build metadata.
//!
//! ## Core Authentication Flows
//!
//! ### Signup & Email Verification
//!
//! 1. **Start:** The client fetches a Genesis Zero Token and POSTs to `/v1/auth/opaque/signup/start`.
//! 2. **Finish:** After receiving the `OPAQUE` response, the client fetches a new Zero Token and POSTs to `/v1/auth/opaque/signup/finish`.
//! 3. **Verification:** The user clicks a link (fragment-based token) which the frontend consumes via `/v1/auth/verify-email`.
//!
//! ### Admin Elevation (Step-up)
//!
//! Platform operators must elevate their session to access administrative routes.
//! 1. **Claim:** The operator provides a Vault token at `/admin/claim`.
//! 2. **Exchange:** The API validates the Vault token and returns a short-lived **Admin `PASETO`** (`v4.public`).
//! 3. **Usage:** The frontend stores this token in memory and includes it in the
//!    `Authorization: Bearer` header for elevated admin routes such as
//!    `/v1/auth/admin/infra`.
//!
//! Centralizing these helpers keeps network behavior consistent and avoids duplicated
//! logic in routes and features. These utilities do not handle secrets directly, but
//! callers must still avoid logging sensitive data.

pub(crate) mod api;
#[allow(clippy::doc_markdown, clippy::needless_raw_string_hashes)]
pub(crate) mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}
pub(crate) mod config;
pub(crate) mod errors;
pub(crate) mod theme;

pub(crate) const GIT_COMMIT_HASH: &str = match built_info::GIT_COMMIT_HASH {
    Some(hash) => hash,
    None => "unknown",
};

pub(crate) use api::{
    delete_json_with_headers_with_credentials, get_json_with_base, get_json_with_credentials,
    get_json_with_headers, get_optional_json_with_credentials, post_empty_with_credentials,
    post_json_with_headers, post_json_with_headers_response,
    post_json_with_headers_with_credentials, post_json_with_headers_with_credentials_response,
};
pub(crate) use errors::AppError;
