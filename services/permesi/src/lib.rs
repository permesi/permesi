//! # Permesi (Core IAM & OIDC Authority)
//!
//! `permesi` is the core identity and access management authority. It handles
//! `OPAQUE`-based authentication, user session management, and organization-scoped
//! authorization.
//!
//! ## Tenant Model (Organizations, Projects, Environments)
//!
//! Organizations are the primary tenant boundary. Each organization owns projects,
//! which in turn own environments.
//!
//! - **Slug Normalization:** All identifiers (orgs, projects, envs) are normalized to
//!   lowercase, URL-safe strings (`[a-z0-9-]`).
//! - **Environment Tiers:** Each project must have exactly one `production` environment.
//!   Non-production environments are blocked until the production environment is created.
//! - **Soft Deletes:** Deleting resources does not reserve their names or slugs; new
//!   resources can reuse the identifiers of deleted ones.
//!
//! ## Authentication (`OPAQUE`)
//!
//! Authentication uses the **`OPAQUE`** password-authenticated key exchange (PAKE) protocol.
//! Passwords never leave the client; the database only stores an `OPAQUE` registration record.
//!
//! All sensitive authentication `POST` requests require a **Genesis Zero Token** for
//! additional rate-limiting and abuse protection, verified offline via a `PASERK` keyset.
//!
//! ## Authorization & Membership
//!
//! Access is controlled by organization membership and roles (`owner`, `admin`, `member`, `readonly`).
//! Unauthorized access attempts return `404 Not Found` rather than `403 Forbidden` to
//! prevent resource enumeration by unauthenticated or unauthorized users.

pub mod api;
pub mod cli;
pub mod totp;
pub mod vault;
pub mod webauthn;
