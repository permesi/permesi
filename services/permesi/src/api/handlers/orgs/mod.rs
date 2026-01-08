//! Organization, project, environment, and application endpoints.
//!
//! Organizations are the tenant boundary, so every handler scopes by org slug
//! and derives authorization from org membership roles. We return 404 for
//! unauthorized access (including inactive memberships) to avoid exposing
//! resource existence, and we normalize slugs to stable URL-safe identifiers.
//! Environment creation enforces a single production tier per project, with
//! non-production environments gated until a production environment exists.
//!
//! This module is split into small route-focused files plus a shared storage
//! layer so the HTTP surface stays easy to read and the SQL logic stays easy to
//! test. The handler modules only parse inputs and map the high-level flow,
//! while `storage` owns database queries and response shaping.
//!
//! Flow Overview:
//! 1) Authenticate via session cookie.
//! 2) Resolve the organization by slug and verify active membership.
//! 3) Enforce org-scoped roles for write operations.
//! 4) Perform scoped CRUD for projects, environments, and applications.

pub(crate) mod applications;
pub(crate) mod environments;
pub(crate) mod organizations;
pub(crate) mod projects;
mod slug;
mod storage;
mod types;

const ORG_SLUG_MIN: usize = 3;
const ORG_SLUG_MAX: usize = 63;
const PROJECT_SLUG_MIN: usize = 3;
const PROJECT_SLUG_MAX: usize = 63;
const ENV_SLUG_MIN: usize = 2;
const ENV_SLUG_MAX: usize = 32;

const ORG_ROLE_OWNER: &str = "owner";
const ORG_ROLE_ADMIN: &str = "admin";

#[cfg(test)]
mod tests;
