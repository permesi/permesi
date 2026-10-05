//! OPAQUE client helpers and suite configuration for the frontend. These helpers
//! must stay aligned with the server suite to preserve protocol correctness and
//! password security, and they must never log derived material.
//!
//! Flow Overview: Routes use these helpers to build identifiers and KSF parameters
//! before running the OPAQUE start/finish steps.
//! Password reauthentication reuses the existing admission-protected endpoints and
//! only refreshes the current session's authentication time; it performs no mutation.

use opaque_argon2::Argon2;
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::{CipherSuite, Identifiers};

/// OPAQUE cipher suite used by the client; must match the server configuration.
/// Its `opaque_*` crypto aliases isolate `opaque-ke 4`'s older trait versions;
/// changing the suite or aliases requires a coordinated backend migration.
pub struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, opaque_sha2::Sha512>;
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

/// Proves the current account's password without transmitting the password itself.
/// Callers own confirmation and identity checks; success never triggers a destructive action.
/// Plaintext stays transient in this future and is never logged or stored in browser storage.
pub async fn reauthenticate(email: &str, password: String) -> Result<(), crate::app_lib::AppError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
    use opaque_rand_core::OsRng;

    use crate::{
        app_lib::{AppError, config::AppConfig},
        features::auth::{
            client, token,
            types::{OpaqueReauthFinishRequest, OpaqueReauthStartRequest},
        },
    };

    let client_id = normalize_email(email);
    let server_id = AppConfig::load().opaque_server_id;
    let mut rng = OsRng;
    let start = ClientLogin::<OpaqueSuite>::start(&mut rng, password.as_bytes())
        .map_err(|_| AppError::Config("Unable to start secure re-authentication.".to_owned()))?;
    let request = OpaqueReauthStartRequest {
        credential_request: STANDARD.encode(start.message.serialize()),
    };
    let admission = token::fetch_zero_token().await?;
    let response = client::opaque_reauth_start(&request, &admission).await?;
    let bytes = STANDARD
        .decode(response.credential_response)
        .map_err(|_| AppError::Config("Invalid re-authentication response.".to_owned()))?;
    let credential_response = CredentialResponse::<OpaqueSuite>::deserialize(&bytes)
        .map_err(|_| AppError::Config("Invalid re-authentication response.".to_owned()))?;
    let ksf_params = ksf();
    let params = ClientLoginFinishParameters::new(
        None,
        identifiers(client_id.as_bytes(), server_id.as_bytes()),
        Some(&ksf_params),
    );
    let finish = start
        .state
        .finish(&mut rng, password.as_bytes(), credential_response, params)
        .map_err(|_| AppError::Config("Unable to verify password. Please try again.".to_owned()))?;
    drop(password);
    let request = OpaqueReauthFinishRequest {
        login_id: response.login_id,
        credential_finalization: STANDARD.encode(finish.message.serialize()),
    };
    let admission = token::fetch_zero_token().await?;
    client::opaque_reauth_finish(&request, &admission).await
}
