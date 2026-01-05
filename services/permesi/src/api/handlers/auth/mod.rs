//! Auth handlers and supporting modules.

pub(crate) mod admin;
mod admin_rate_limit;
mod admin_storage;
mod admin_token;
pub(crate) mod opaque;
pub(crate) mod principal;
mod rate_limit;
pub(crate) mod session;
mod state;
mod storage;
pub(crate) mod types;
mod utils;
pub(crate) mod verification;
mod zero_token;

pub use admin::{AdminConfig, AdminState};
pub use rate_limit::NoopRateLimiter;
pub use state::{AuthConfig, AuthState, OpaqueState};
#[cfg(test)]
pub(crate) use utils::{generate_session_token, hash_session_token};

#[cfg(test)]
mod tests;
