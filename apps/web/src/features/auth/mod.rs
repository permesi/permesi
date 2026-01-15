//! Auth feature module covering OPAQUE flows, zero-token gating, and session
//! hydration. It keeps authentication logic out of the UI and must stay aligned
//! with backend protocol expectations. This module touches security boundaries
//! and must avoid logging secrets or token material.
//!
//! Flow Overview: Signup performs OPAQUE start/finish and then email verification.
//! Login performs OPAQUE start/finish and hydrates the session cookie. Verify and
//! resend endpoints submit tokens with a zero-token header and return 204 on
//! success.

pub(crate) mod client;
mod guards;
pub(crate) mod opaque;
pub(crate) mod state;
pub(crate) mod token;
pub(crate) mod types;
pub(crate) mod webauthn;

pub(crate) use guards::RequireAdmin;
