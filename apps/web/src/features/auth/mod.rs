//! Resend endpoints submit tokens with a zero-token header and return 204 on
//! success.

pub(crate) mod client;

mod guards;

pub(crate) mod opaque;

pub(crate) mod state;

pub(crate) mod token;

pub(crate) mod types;

pub(crate) mod webauthn;

pub(crate) use guards::RequireAdmin;
