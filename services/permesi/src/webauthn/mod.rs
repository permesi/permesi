//! Passkey and hardware-key proofs backed by shared sealed PostgreSQL ceremonies.
//!
//! Flow Overview: begin binds library state to trusted origin/RP/user/session policy;
//! finish consumes it once before proof verification and persists permanent credentials
//! or issues authority. Replicas share the Vault seed; challenge storage has no local fallback.
pub(crate) mod exchange;
pub mod models;
pub mod passkey_repo;
pub mod passkeys;
pub mod repo;
pub mod service;

pub use models::*;
pub use passkey_repo::*;
pub use passkeys::*;
pub use repo::*;
pub use service::*;
