//! OPAQUE signup and login handlers. These routes run the server-side half of
//! the protocol so passwords never traverse the API surface, and they return
//! opaque responses to avoid account enumeration.
//!
//! Flow Overview: Signup start builds a registration response, and signup finish
//! stores the registration record plus a verification token. Login start builds
//! a login response and stores a short-lived login state, and login finish
//! completes the exchange and issues a session cookie. Re-auth updates the
//! session auth timestamp after a password check, and password change replaces
//! the registration record for the authenticated user.

pub(crate) mod login;
pub(crate) mod password;
pub(crate) mod reauth;
pub(crate) mod signup;

#[cfg(test)]
mod test_support;
