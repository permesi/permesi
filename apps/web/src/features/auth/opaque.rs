//! OPAQUE client helpers and suite configuration for the frontend. These helpers
//! must stay aligned with the server suite to preserve protocol correctness and
//! password security, and they must never log derived material.
//!
//! Flow Overview: Routes use these helpers to build identifiers and KSF parameters
//! before running the OPAQUE start/finish steps.

use argon2::Argon2;
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::{CipherSuite, Identifiers};

/// OPAQUE cipher suite used by the client; must match the server configuration.
/// Changing this requires coordinated updates with the backend.
pub struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Argon2<'static>;
}

/// Normalizes emails for stable OPAQUE identifiers and API requests.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Constructs OPAQUE identifiers to bind client and server identities.
/// These identifiers are part of the protocol transcript and must be stable.
pub fn identifiers<'a>(client_id: &'a [u8], server_id: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(client_id),
        server: Some(server_id),
    }
}

/// Returns the key stretching function used by OPAQUE; must match server policy.
/// Mismatched parameters will break login and signup flows.
pub fn ksf() -> Argon2<'static> {
    Argon2::default()
}
