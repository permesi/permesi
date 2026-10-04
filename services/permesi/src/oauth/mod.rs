//! OAuth registration and delegated-authority foundation, independent of session permissions.
//!
//! Applications remain tenant resources; each owns multiple OAuth clients and a scope
//! registry. Client configuration is an upper bound on future delegation, never proof
//! that a user may access a resource. Protocol scopes have fixed server semantics.
//! Authorization Code + S256 PKCE uses PostgreSQL request/code state; token issuance
//! remains deferred. OIDC metadata and shared Vault public keys are opt-in.
//!
//! Flow Overview:
//! Session-authenticated management resolves active organization membership and the
//! complete application ancestry before calling the service. The service validates
//! configuration, commits allow-lists atomically, and returns domain records without
//! credentials. Authorization independently reloads active client ancestry, exact
//! redirects, tenant membership, registry allow-lists and saved/explicit consent.

pub mod authorization;
pub mod client;
pub mod config;
pub mod grant;
pub mod oidc;
pub mod redirect_uri;
pub mod scope;
pub(crate) mod service;

/// Configuration validation failure with a stable message and no submitted values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValidationError(pub(crate) &'static str);
