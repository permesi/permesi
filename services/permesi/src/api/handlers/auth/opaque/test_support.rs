//! Shared helpers for OPAQUE handler tests.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        mfa::MfaConfig,
        rate_limit::{NoopRateLimiter, RateLimiter},
        state::{AuthConfig, AuthState, OpaqueState},
    },
};
use admission_token::{PaserkKey, PaserkKeySet};
use anyhow::Result;
use std::{sync::Arc, time::Duration};

pub(super) fn admission_verifier() -> Result<Arc<AdmissionVerifier>> {
    let key = PaserkKey::from_ed25519_public_key_bytes(&[7u8; 32])?;
    let keyset = PaserkKeySet {
        version: "v4".to_string(),
        purpose: "public".to_string(),
        active_kid: key.kid.clone(),
        keys: vec![key],
    };
    Ok(Arc::new(AdmissionVerifier::new(
        keyset,
        "https://genesis.test".to_string(),
        "permesi".to_string(),
    )))
}

pub(super) fn auth_state() -> Arc<AuthState> {
    let config = AuthConfig::new("https://permesi.dev".to_string());
    let opaque = OpaqueState::from_seed(
        [1u8; 32],
        "api.permesi.dev".to_string(),
        Duration::from_secs(30),
    );
    let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
    Arc::new(AuthState::new(config, opaque, limiter, MfaConfig::new()))
}
