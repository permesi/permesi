//! Browser-independent tenant/OAuth console contracts and state transitions.
//!
//! Keeping these helpers outside the wasm entrypoint makes route generation,
//! serialization, and configuration edits testable on the host. They confer no
//! authority; session and tenant policy remain enforced by the backend.

#[path = "features/oauth/domain.rs"]
pub mod oauth;

#[path = "features/orgs/types.rs"]
pub mod orgs_types;
