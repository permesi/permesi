//! User self-service routes for profile management and account security.
//!
//! This module is organized into:
//! - **Overview** (`page.rs`): Displays user identity, roles, and basic profile information.
//! - **Security** (`security.rs`): Management of sign-in methods, including OPAQUE password rotation and MFA.

pub(crate) mod page;
pub(crate) mod security;

pub(crate) use page::MePage;
pub(crate) use security::MeSecurityPage;
