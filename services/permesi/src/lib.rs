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
pub mod tls;
pub mod totp;
pub mod vault;
pub mod webauthn;

#[allow(clippy::doc_markdown, clippy::needless_raw_string_hashes)]
pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = match built_info::GIT_COMMIT_HASH {
    Some(hash) => hash,
    None => "unknown",
};

pub const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_commit_hash_format() {
        if GIT_COMMIT_HASH == "unknown" {
            // Acceptable in non-git build environments
            return;
        }
        // Should be a hex string (full SHA-1 is 40 chars, but could be short)
        assert!(
            GIT_COMMIT_HASH.chars().all(|c| c.is_ascii_hexdigit()),
            "GIT_COMMIT_HASH should be a hex string, got: {GIT_COMMIT_HASH}"
        );
        assert!(
            GIT_COMMIT_HASH.len() >= 7,
            "GIT_COMMIT_HASH should be at least 7 characters long, got: {GIT_COMMIT_HASH}"
        );
    }

    #[test]
    fn test_app_user_agent_format() {
        assert!(APP_USER_AGENT.starts_with(env!("CARGO_PKG_NAME")));
        assert!(APP_USER_AGENT.contains(env!("CARGO_PKG_VERSION")));
    }
}
