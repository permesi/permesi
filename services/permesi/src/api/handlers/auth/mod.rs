//! Auth handlers and supporting modules.
//!
//! This module coordinates authentication (`OPAQUE`), session management, and
//! administrative elevation.
//!
//! ## Admin Rate Limiting
//!
//! Administrative endpoints (`/v1/auth/admin/*`) are strictly rate-limited to
//! prevent brute-force attacks on Vault tokens used for bootstrapping and elevation.
//!
//! - **Attempt Limit:** 3 attempts per user and 10 attempts per IP within 10 minutes.
//! - **Failure Cooldown:** 3 consecutive failures trigger a 15-minute cooldown.
//!
//! ## `OPAQUE` Seed (Vault KV v2)
//!
//! The server's `OPAQUE` state is derived from a 32-byte seed stored in Vault.
//! All instances of `permesi` must share this seed to ensure that user
//! registration records remain valid across the cluster.
//!
//! > **Warning:** Rotating this seed invalidates all existing user registrations.

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
