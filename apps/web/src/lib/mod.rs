//! Shared frontend utilities for API access, configuration, errors, and build metadata.
//! Centralizing these helpers keeps network behavior consistent and avoids duplicated
//! logic in routes and features. These utilities do not handle secrets directly, but
//! callers must still avoid logging sensitive data.

pub(crate) mod api;
pub(crate) mod build_info;
pub(crate) mod config;
pub(crate) mod errors;

pub(crate) use api::{
    get_json_with_base, get_json_with_credentials, get_json_with_headers_with_credentials,
    get_optional_json_with_credentials, get_optional_json_with_headers_with_credentials,
    post_empty_with_credentials, post_json_with_headers, post_json_with_headers_response,
    post_json_with_headers_with_credentials, post_json_with_headers_with_credentials_raw,
    post_json_with_headers_with_credentials_response,
};
pub(crate) use errors::AppError;
