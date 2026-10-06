//! Shared state for the permesi HTTP router.
//!
//! Every long-lived dependency a handler needs is a field of [`AppState`], and
//! the router is finished with `with_state`. A handler that asks for a
//! dependency the router does not provide is therefore a compile error, where a
//! missing `Extension` layer used to surface as a runtime 500 on that route.
//!
//! `#[derive(FromRef)]` lets each handler extract only the parts it uses
//! (`State<PgPool>`, `State<Arc<AuthState>>`, ...), so handler signatures stay
//! narrow and tests can route a handler with any smaller state type that
//! provides the same parts. Per-request values, such as the server-issued
//! `RequestId`, remain request extensions.

use crate::{
    api::handlers::{
        AdmissionVerifier,
        auth::{AdminState, AuthState},
    },
    totp::TotpService,
    vault::renew::ShutdownSignal,
    webauthn::{PasskeyService, SecurityKeyService},
};
use axum::extract::FromRef;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Dependencies shared by every permesi route.
#[derive(Clone, FromRef)]
pub struct AppState {
    /// OPAQUE, session, MFA, and rate-limit state for the auth endpoints.
    pub auth: Arc<AuthState>,
    /// Shared OAuth policy and Vault verification key source.
    pub oauth: Arc<crate::oauth::oidc::OAuthState>,
    /// Platform-admin elevation state.
    pub admin: Arc<AdminState>,
    /// Admission (zero) token verifier backed by the Genesis PASERK keyset.
    pub admission: Arc<AdmissionVerifier>,
    /// Fail-closed shutdown channel used by readiness probes.
    pub shutdown: mpsc::UnboundedSender<ShutdownSignal>,
    /// Shared PostgreSQL pool.
    pub pool: PgPool,
    /// TOTP enrollment and verification.
    pub totp: TotpService,
    /// Security-key (second factor) `WebAuthn` flows.
    pub security_keys: Arc<SecurityKeyService>,
    /// Passkey (primary credential) `WebAuthn` flows.
    pub passkeys: Arc<PasskeyService>,
}

#[cfg(test)]
impl AppState {
    /// Build a complete state with inert defaults for router tests.
    ///
    /// Nothing here contacts Vault or the network: the Vault transport points at an
    /// unused address and `pool` may be lazy. Tests override the parts they exercise
    /// with struct-update syntax, e.g. `AppState { auth, ..AppState::for_tests(pool)? }`.
    pub(crate) fn for_tests(pool: PgPool) -> anyhow::Result<Self> {
        use crate::{
            api::handlers::auth::{
                AdminConfig, AuthConfig, OpaqueState, RateLimiter, mfa::MfaConfig,
            },
            cli::globals::GlobalArgs,
            totp::DekManager,
            webauthn::PasskeyConfig,
        };
        use admission_token::{PaserkKey, PaserkKeySet};
        use std::time::Duration;

        let vault_url = "http://127.0.0.1:1".to_string();
        let transport = vault_client::VaultTransport::from_target(
            crate::APP_USER_AGENT,
            vault_client::VaultTarget::Tcp {
                base_url: vault_url.clone(),
            },
        )?;
        let key = PaserkKey::from_ed25519_public_key_bytes(&[7u8; 32])?;
        let keyset = PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key],
        };
        let origins = vec!["https://permesi.dev".to_string()];

        let globals = GlobalArgs::new(vault_url.clone(), transport.clone());
        Ok(Self {
            oauth: Arc::new(crate::oauth::oidc::OAuthState::new(
                crate::oauth::config::OAuthConfig::disabled(),
                &globals,
            )),
            auth: Arc::new(AuthState::new(
                AuthConfig::new("https://permesi.dev".to_string()),
                OpaqueState::from_seed(
                    [1u8; 32],
                    "api.permesi.dev".to_string(),
                    Duration::from_secs(30),
                    10_000,
                ),
                Arc::new(RateLimiter::noop()),
                MfaConfig::new(),
            )),
            admin: Arc::new(AdminState::new(
                AdminConfig::new(vault_url.clone()),
                pool.clone(),
                transport.clone(),
            )?),
            admission: Arc::new(AdmissionVerifier::new(
                keyset,
                "https://genesis.test".to_string(),
                "permesi".to_string(),
            )),
            shutdown: mpsc::unbounded_channel().0,
            totp: TotpService::new(
                DekManager::new(GlobalArgs::new(vault_url, transport)),
                pool.clone(),
                "Permesi".to_string(),
            ),
            security_keys: Arc::new(SecurityKeyService::new(
                pool.clone(),
                "permesi.dev",
                &origins,
                &[1; 32],
                300,
                100,
                1000,
            )?),
            passkeys: Arc::new(PasskeyService::new(
                PasskeyConfig::new(
                    "permesi.dev".to_string(),
                    "Permesi".to_string(),
                    origins,
                    Duration::from_mins(5),
                    true,
                )?,
                100,
                pool.clone(),
                &[1; 32],
                1000,
            )?),
            pool,
        })
    }
}
