//! Auth handlers and supporting modules.

pub(crate) mod opaque_login;
pub(crate) mod opaque_signup;
mod rate_limit;
mod state;
mod storage;
mod types;
mod utils;
pub(crate) mod verification;
mod zero_token;

pub use rate_limit::NoopRateLimiter;
pub use state::{AuthConfig, AuthState, OpaqueState};

#[cfg(test)]
mod tests;
