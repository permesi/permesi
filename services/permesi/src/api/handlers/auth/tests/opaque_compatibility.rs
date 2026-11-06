//! Preserve the deployed OPAQUE suite across library upgrades using public test material.
//!
//! Flow Overview: fixtures generated with opaque-ke 4.0.1 freeze deterministic setup,
//! registration and login bytes. Current clients and servers exchange proofs with those
//! legacy states, ensuring upgrades preserve stored records and pending transcripts.
//! Replay the encoded request directly: voprf's scalar sampling can change the mapping
//! from a deterministic RNG seed to a fresh request without changing protocol encoding.

use super::{OpaqueState, OpaqueSuite, identifiers};
use anyhow::{Context, Result};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    ServerLogin, ServerLoginParameters, ServerRegistration, errors::ProtocolError,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct LegacyFixture {
    setup: String,
    record: String,
    credential_request: String,
    credential_response: String,
    client_login: String,
    server_login: String,
    finalization: String,
    session_key: String,
}

/// Loads only deterministic, public test keys and transcripts produced by opaque-ke 4.0.1.
fn legacy_fixture() -> Result<LegacyFixture> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/opaque-ke-4.0.1.json"
    ))?)
}

/// Exercises the production Vault-seed derivation with the fixture's public test seed.
fn opaque_state() -> OpaqueState {
    OpaqueState::from_seed(
        [42; 32],
        "api.permesi.dev".into(),
        Duration::from_secs(300),
        10,
    )
}

#[test]
fn opaque_setup_preserves_4_0_1_seed_derivation() -> Result<()> {
    let fixture = legacy_fixture()?;
    assert_eq!(
        hex::encode(opaque_state().server_setup().serialize()),
        fixture.setup
    );
    Ok(())
}

/// Both directions must accept the old state without changing the suite, identifiers or KSF.
#[test]
fn opaque_login_accepts_4_0_1_records_and_pending_transcripts() -> Result<()> {
    let fixture = legacy_fixture()?;
    let state = opaque_state();
    let password = b"public compatibility fixture password";
    let client_id = b"compatibility@example.com";
    let mut client_rng = ChaCha20Rng::from_seed([44; 32]);
    let mut server_rng = ChaCha20Rng::from_seed([45; 32]);
    let request = CredentialRequest::deserialize(&hex::decode(&fixture.credential_request)?)?;
    assert_eq!(hex::encode(request.serialize()), fixture.credential_request);
    let legacy_client =
        ClientLogin::<OpaqueSuite>::deserialize(&hex::decode(&fixture.client_login)?)?;
    assert_eq!(hex::encode(legacy_client.serialize()), fixture.client_login);
    let record = ServerRegistration::<OpaqueSuite>::deserialize(&hex::decode(&fixture.record)?)?;
    assert_eq!(hex::encode(record.serialize()), fixture.record);
    let server = ServerLogin::start(
        &mut server_rng,
        state.server_setup(),
        Some(record),
        request,
        client_id,
        ServerLoginParameters {
            context: None,
            identifiers: identifiers(client_id, state.server_id()),
        },
    )?;
    assert_eq!(
        hex::encode(server.message.serialize()),
        fixture.credential_response
    );
    assert_eq!(hex::encode(server.state.serialize()), fixture.server_login);
    let ksf = argon2::Argon2::default();
    let client = legacy_client.finish(
        &mut client_rng,
        password,
        server.message,
        ClientLoginFinishParameters::new(
            None,
            identifiers(client_id, state.server_id()),
            Some(&ksf),
        ),
    )?;
    assert_eq!(
        hex::encode(client.message.serialize()),
        fixture.finalization
    );
    let legacy_server =
        ServerLogin::<OpaqueSuite>::deserialize(&hex::decode(&fixture.server_login)?)?;
    let legacy_server = legacy_server.finish(client.message, ServerLoginParameters::default())?;
    let server = server.state.finish(
        CredentialFinalization::deserialize(&hex::decode(&fixture.finalization)?)?,
        ServerLoginParameters::default(),
    )?;
    assert_eq!(hex::encode(client.session_key), fixture.session_key);
    assert_eq!(hex::encode(server.session_key), fixture.session_key);
    assert_eq!(hex::encode(legacy_server.session_key), fixture.session_key);
    Ok(())
}

/// A fresh upgraded client must authenticate against the unchanged legacy password record.
#[test]
fn opaque_login_fresh_client_accepts_4_0_1_record() -> Result<()> {
    let fixture = legacy_fixture()?;
    let state = opaque_state();
    let password = b"public compatibility fixture password";
    let client_id = b"compatibility@example.com";
    let mut client_rng = ChaCha20Rng::from_seed([44; 32]);
    let mut server_rng = ChaCha20Rng::from_seed([45; 32]);
    let client = ClientLogin::<OpaqueSuite>::start(&mut client_rng, password)?;
    let record = ServerRegistration::<OpaqueSuite>::deserialize(&hex::decode(&fixture.record)?)?;
    assert_eq!(hex::encode(record.serialize()), fixture.record);
    let server = ServerLogin::start(
        &mut server_rng,
        state.server_setup(),
        Some(record),
        client.message,
        client_id,
        ServerLoginParameters {
            context: None,
            identifiers: identifiers(client_id, state.server_id()),
        },
    )?;
    let ksf = argon2::Argon2::default();
    let client = client.state.finish(
        &mut client_rng,
        password,
        server.message,
        ClientLoginFinishParameters::new(
            None,
            identifiers(client_id, state.server_id()),
            Some(&ksf),
        ),
    )?;
    let server = server
        .state
        .finish(client.message, ServerLoginParameters::default())?;
    assert_eq!(client.session_key, server.session_key);
    Ok(())
}

/// A well-formed, altered MAC must fail even when the pending state came from the older library.
#[test]
fn opaque_login_rejects_tampered_4_0_1_finalization() -> Result<()> {
    let fixture = legacy_fixture()?;
    let server = ServerLogin::<OpaqueSuite>::deserialize(&hex::decode(&fixture.server_login)?)?;
    let mut finalization = hex::decode(&fixture.finalization)?;
    *finalization.first_mut().context("fixture MAC is empty")? ^= 1;
    let result = server.finish(
        CredentialFinalization::deserialize(&finalization)?,
        ServerLoginParameters::default(),
    );
    assert!(matches!(result, Err(ProtocolError::InvalidLoginError)));
    Ok(())
}
