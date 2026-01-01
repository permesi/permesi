//! Auth state, configuration, and `OPAQUE` server setup.

use crate::api::APP_USER_AGENT;
use anyhow::{Context, Result};
use opaque_ke::{CipherSuite, ServerLogin, ServerSetup, key_exchange::tripledh::TripleDh};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::rate_limit::RateLimiter;

const DEFAULT_TOKEN_TTL_SECONDS: i64 = 30 * 60;
const DEFAULT_RESEND_COOLDOWN_SECONDS: i64 = 60;
const DEFAULT_OPAQUE_LOGIN_TTL_SECONDS: u64 = 5 * 60;
const DEFAULT_OPAQUE_KV_MOUNT: &str = "kv";
const DEFAULT_OPAQUE_KV_PATH: &str = "permesi/opaque";
const DEFAULT_OPAQUE_SERVER_ID: &str = "api.permesi.dev";

#[derive(Clone, Debug)]
pub struct AuthConfig {
    zero_token_validate_url: String,
    frontend_base_url: String,
    email_token_ttl_seconds: i64,
    resend_cooldown_seconds: i64,
    opaque_kv_mount: String,
    opaque_kv_path: String,
    opaque_server_id: String,
    opaque_login_ttl_seconds: u64,
}

impl AuthConfig {
    #[must_use]
    pub fn new(zero_token_validate_url: String, frontend_base_url: String) -> Self {
        Self {
            zero_token_validate_url,
            frontend_base_url,
            email_token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            resend_cooldown_seconds: DEFAULT_RESEND_COOLDOWN_SECONDS,
            opaque_kv_mount: DEFAULT_OPAQUE_KV_MOUNT.to_string(),
            opaque_kv_path: DEFAULT_OPAQUE_KV_PATH.to_string(),
            opaque_server_id: DEFAULT_OPAQUE_SERVER_ID.to_string(),
            opaque_login_ttl_seconds: DEFAULT_OPAQUE_LOGIN_TTL_SECONDS,
        }
    }

    #[must_use]
    pub fn with_email_token_ttl_seconds(mut self, seconds: i64) -> Self {
        self.email_token_ttl_seconds = seconds;
        self
    }

    #[must_use]
    pub fn with_resend_cooldown_seconds(mut self, seconds: i64) -> Self {
        self.resend_cooldown_seconds = seconds;
        self
    }

    #[must_use]
    pub fn with_opaque_kv_mount(mut self, mount: String) -> Self {
        self.opaque_kv_mount = mount;
        self
    }

    #[must_use]
    pub fn with_opaque_kv_path(mut self, path: String) -> Self {
        self.opaque_kv_path = path;
        self
    }

    #[must_use]
    pub fn with_opaque_server_id(mut self, server_id: String) -> Self {
        self.opaque_server_id = server_id;
        self
    }

    #[must_use]
    pub fn with_opaque_login_ttl_seconds(mut self, seconds: u64) -> Self {
        self.opaque_login_ttl_seconds = seconds;
        self
    }

    #[must_use]
    pub fn opaque_kv_mount(&self) -> &str {
        &self.opaque_kv_mount
    }

    #[must_use]
    pub fn opaque_kv_path(&self) -> &str {
        &self.opaque_kv_path
    }

    #[must_use]
    pub fn opaque_server_id(&self) -> &str {
        &self.opaque_server_id
    }

    #[must_use]
    pub fn opaque_login_ttl_seconds(&self) -> u64 {
        self.opaque_login_ttl_seconds
    }

    pub(super) fn zero_token_validate_url(&self) -> &str {
        &self.zero_token_validate_url
    }

    pub(super) fn frontend_base_url(&self) -> &str {
        &self.frontend_base_url
    }

    pub(super) fn email_token_ttl_seconds(&self) -> i64 {
        self.email_token_ttl_seconds
    }

    pub(super) fn resend_cooldown_seconds(&self) -> i64 {
        self.resend_cooldown_seconds
    }
}

pub(super) struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = argon2::Argon2<'static>;
}

pub(super) struct OpaqueLoginState {
    pub(super) state: ServerLogin<OpaqueSuite>,
    pub(super) user_id: Option<Uuid>,
    created_at: Instant,
}

pub struct OpaqueState {
    server_setup: ServerSetup<OpaqueSuite>,
    server_id: Vec<u8>,
    login_ttl: Duration,
    login_states: Mutex<HashMap<Uuid, OpaqueLoginState>>,
}

impl OpaqueState {
    pub fn from_seed(seed: [u8; 32], server_id: String, login_ttl: Duration) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let server_setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
        Self {
            server_setup,
            server_id: server_id.into_bytes(),
            login_ttl,
            login_states: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn server_setup(&self) -> &ServerSetup<OpaqueSuite> {
        &self.server_setup
    }

    pub(super) fn server_id(&self) -> &[u8] {
        &self.server_id
    }

    pub(super) async fn store_login_state(
        &self,
        state: ServerLogin<OpaqueSuite>,
        user_id: Option<Uuid>,
    ) -> Uuid {
        let login_id = Uuid::new_v4();
        let mut states = self.login_states.lock().await;
        states.retain(|_, entry| entry.created_at.elapsed() < self.login_ttl);
        states.insert(
            login_id,
            OpaqueLoginState {
                state,
                user_id,
                created_at: Instant::now(),
            },
        );
        login_id
    }

    pub(super) async fn take_login_state(&self, login_id: Uuid) -> Option<OpaqueLoginState> {
        let mut states = self.login_states.lock().await;
        if let Some(state) = states.remove(&login_id)
            && state.created_at.elapsed() < self.login_ttl
        {
            Some(state)
        } else {
            None
        }
    }
}

pub struct AuthState {
    config: AuthConfig,
    opaque: OpaqueState,
    client: Client,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl AuthState {
    /// # Errors
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(
        config: AuthConfig,
        opaque: OpaqueState,
        rate_limiter: Arc<dyn RateLimiter>,
    ) -> Result<Self> {
        let client = Client::builder()
            .user_agent(APP_USER_AGENT)
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build auth HTTP client")?;
        Ok(Self {
            config,
            opaque,
            client,
            rate_limiter,
        })
    }

    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    #[must_use]
    pub fn opaque(&self) -> &OpaqueState {
        &self.opaque
    }

    pub(super) fn client(&self) -> &Client {
        &self.client
    }

    pub(super) fn rate_limiter(&self) -> &dyn RateLimiter {
        self.rate_limiter.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::super::rate_limit::{NoopRateLimiter, RateLimiter};
    use super::{AuthConfig, AuthState, OpaqueState};
    use anyhow::Result;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn auth_config_defaults_and_overrides() {
        let config = AuthConfig::new(
            "http://genesis.test/v1/zero-token/validate".to_string(),
            "https://permesi.dev".to_string(),
        );

        assert_eq!(
            config.zero_token_validate_url(),
            "http://genesis.test/v1/zero-token/validate"
        );
        assert_eq!(config.frontend_base_url(), "https://permesi.dev");
        assert_eq!(
            config.email_token_ttl_seconds(),
            super::DEFAULT_TOKEN_TTL_SECONDS
        );
        assert_eq!(
            config.resend_cooldown_seconds(),
            super::DEFAULT_RESEND_COOLDOWN_SECONDS
        );
        assert_eq!(config.opaque_kv_mount(), super::DEFAULT_OPAQUE_KV_MOUNT);
        assert_eq!(config.opaque_kv_path(), super::DEFAULT_OPAQUE_KV_PATH);
        assert_eq!(config.opaque_server_id(), super::DEFAULT_OPAQUE_SERVER_ID);
        assert_eq!(
            config.opaque_login_ttl_seconds(),
            super::DEFAULT_OPAQUE_LOGIN_TTL_SECONDS
        );

        let config = config
            .with_email_token_ttl_seconds(120)
            .with_resend_cooldown_seconds(30)
            .with_opaque_kv_mount("kv-v2".to_string())
            .with_opaque_kv_path("permesi/opaque-v2".to_string())
            .with_opaque_server_id("api.test".to_string())
            .with_opaque_login_ttl_seconds(42);

        assert_eq!(config.email_token_ttl_seconds(), 120);
        assert_eq!(config.resend_cooldown_seconds(), 30);
        assert_eq!(config.opaque_kv_mount(), "kv-v2");
        assert_eq!(config.opaque_kv_path(), "permesi/opaque-v2");
        assert_eq!(config.opaque_server_id(), "api.test");
        assert_eq!(config.opaque_login_ttl_seconds(), 42);
    }

    #[test]
    fn opaque_state_exposes_server_id_bytes() {
        let state = OpaqueState::from_seed(
            [42u8; 32],
            "opaque.test".to_string(),
            Duration::from_secs(5),
        );
        assert_eq!(state.server_id(), b"opaque.test");
        assert_eq!(state.login_ttl, Duration::from_secs(5));
    }

    #[test]
    fn auth_state_constructs_with_noop_rate_limiter() -> Result<()> {
        let config = AuthConfig::new(
            "http://genesis.test/v1/zero-token/validate".to_string(),
            "https://permesi.dev".to_string(),
        );
        let opaque = OpaqueState::from_seed(
            [7u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(5),
        );
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        let state = AuthState::new(config, opaque, limiter)?;
        assert_eq!(state.opaque().server_id(), b"api.permesi.dev");
        Ok(())
    }
}
