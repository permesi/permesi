//! OAuth registration and delegated-authority foundation, independent of session permissions.
//!
//! Applications remain tenant resources; each owns multiple OAuth clients and a scope
//! registry. Client configuration is an upper bound on future delegation, never proof
//! that a user may access a resource. Protocol scopes have fixed server semantics.
//! No authorization or token protocol is implemented here.
//!
//! Flow Overview:
//! Session-authenticated management resolves active organization membership and the
//! complete application ancestry before calling the service. The service validates
//! configuration, commits allow-lists atomically, and returns domain records without
//! credentials. Future protocol handlers must load an active client and intersect its
//! allow-list with consent and independently verified user authorization in one tenant.

pub mod client;
pub mod grant;
pub mod redirect_uri;
pub mod scope;
pub(crate) mod service;

/// Configuration validation failure with a stable message and no submitted values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValidationError(pub(crate) &'static str);
