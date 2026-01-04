//! Auth handlers and supporting modules.

pub(crate) mod opaque;
pub(crate) mod principal;
mod rate_limit;
pub(crate) mod session;
mod state;
mod storage;
mod types;
mod utils;
pub(crate) mod verification;
mod zero_token;

pub use rate_limit::NoopRateLimiter;
pub use state::{AuthConfig, AuthState, OpaqueState};
#[cfg(test)]
pub(crate) use utils::{generate_session_token, hash_session_token};

#[cfg(test)]
mod tests;
