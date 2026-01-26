//! Background renewal tasks for Vault tokens and database leases.
//!
//! This module ensures that the application's access to Vault and the database
//! remains valid by periodically renewing leases before they expire.
//!
//! Flow Overview:
//! 1. `try_renew` determines the connectivity mode (Agent vs Direct).
//! 2. In Direct (TCP) mode, it spawns a task to renew the application's Vault token.
//! 3. In all modes, it spawns a task to renew the dynamic database lease.
//! 4. Tasks use jittered intervals (70-90% of lease duration) to avoid synchronized
//!    thundering herds.
//! 5. If renewal fails repeatedly (3 attempts), a signal is sent via `tx` to
//!    trigger a graceful application shutdown, failing closed.

use crate::globals::GlobalArgs;
use anyhow::Result;
use rand::{Rng, SeedableRng, rngs::StdRng};
use secrecy::ExposeSecret;
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};
use tracing::{debug, error, info, instrument, warn};

/// Reason for triggering a process shutdown after failed Vault renewals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownSignal {
    /// The Vault auth token could not be renewed after retrying.
    TokenRenewalFailed,
    /// The Vault database lease could not be renewed after retrying.
    DbLeaseRenewalFailed,
}

impl ShutdownSignal {
    /// Human-readable reason for logs and shutdown errors.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ShutdownSignal::TokenRenewalFailed => "vault_token_renewal_failed",
            ShutdownSignal::DbLeaseRenewalFailed => "vault_db_lease_renewal_failed",
        }
    }
}

/// Spawn background tasks to keep Vault and database leases renewed.
///
/// If running in Agent mode, the Vault token renewal is skipped as the Agent
/// handles its own authentication. Database renewal is always performed by the
/// application to ensure connection continuity.
///
/// # Errors
/// Returns an error if the tasks cannot be initialized.
#[instrument(skip(globals, tx))]
pub async fn try_renew(
    globals: &GlobalArgs,
    tx: mpsc::UnboundedSender<ShutdownSignal>,
) -> Result<()> {
    // In Agent Proxy mode, the Agent handles its own auth token renewal.
    // The app only needs to renew its own (TCP mode) token.
    if globals.vault_transport.is_agent_proxy() {
        info!("Vault agent proxy mode enabled; skipping token renewals");
    } else {
        spawn_token_renewer(globals, tx.clone());
    }

    spawn_db_lease_renewer(globals, tx);

    Ok(())
}

fn spawn_token_renewer(globals: &GlobalArgs, tx: mpsc::UnboundedSender<ShutdownSignal>) {
    tokio::spawn({
        let mut rng = StdRng::from_entropy();
        let mut jittered_lease_duration: Duration = Duration::default();

        let transport = globals.vault_transport.clone();
        let token_secret = globals.vault_token.clone();

        async move {
            loop {
                let token_str = token_secret.expose_secret();
                let token = if token_str.is_empty() {
                    None
                } else {
                    Some(token_str)
                };

                for attempt in 1..=3 {
                    let backoff_time = 2u64.pow(attempt - 1);

                    if attempt > 1 {
                        warn!("Backing off for {} seconds", backoff_time);
                        sleep(Duration::from_secs(backoff_time)).await;
                    }

                    match transport.renew_token(token, None).await {
                        Ok(lease_duration) => {
                            let factor = rng.gen_range(70..90);

                            jittered_lease_duration =
                                Duration::from_secs(lease_duration * factor / 100);
                            info!(
                                lease_duration,
                                next_renew_seconds = jittered_lease_duration.as_secs(),
                                "Vault token renewed"
                            );

                            break;
                        }

                        Err(e) => {
                            error!("Failed to renew token: {}", e);

                            if attempt == 3 {
                                error!("Failed to renew token after 3 attempts: {}", e);
                                let _ = tx.send(ShutdownSignal::TokenRenewalFailed);
                                return;
                            }
                        }
                    }
                }

                debug!(
                    "Will renew token in {} seconds",
                    jittered_lease_duration.as_secs()
                );

                sleep(jittered_lease_duration).await;
            }
        }
    });
}

fn spawn_db_lease_renewer(globals: &GlobalArgs, tx: mpsc::UnboundedSender<ShutdownSignal>) {
    tokio::spawn({
        let mut rng = StdRng::from_entropy();
        let mut jittered_lease_duration: Duration = Duration::default();

        let transport = globals.vault_transport.clone();
        let token_secret = globals.vault_token.clone();
        let db_lease_id = globals.vault_db_lease_id.clone();
        let db_lease_duration = globals.vault_db_lease_duration;

        async move {
            loop {
                let token_str = token_secret.expose_secret();
                let token = if token_str.is_empty() {
                    None
                } else {
                    Some(token_str)
                };

                for attempt in 1..=3 {
                    let backoff_time = 2u64.pow(attempt - 1);

                    if attempt > 1 {
                        warn!("Backing off for {} seconds", backoff_time);
                        sleep(Duration::from_secs(backoff_time)).await;
                    }

                    match transport
                        .renew_db_lease(token, &db_lease_id, db_lease_duration)
                        .await
                    {
                        Ok(lease_duration) => {
                            let factor = rng.gen_range(70..90);

                            jittered_lease_duration =
                                Duration::from_secs(lease_duration * factor / 100);
                            info!(
                                lease_duration,
                                next_renew_seconds = jittered_lease_duration.as_secs(),
                                "Vault DB lease renewed"
                            );

                            break;
                        }

                        Err(e) => {
                            error!("Failed to renew DB lease: {}", e);

                            if attempt == 3 {
                                error!("Failed to renew DB lease after 3 attempts: {}", e);
                                let _ = tx.send(ShutdownSignal::DbLeaseRenewalFailed);
                                return;
                            }
                        }
                    }
                }

                debug!(
                    "Will renew DB lease in {} seconds",
                    jittered_lease_duration.as_secs()
                );

                sleep(jittered_lease_duration).await;
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ShutdownSignal, try_renew};
    use crate::globals::GlobalArgs;
    use anyhow::{Result, bail};
    use secrecy::SecretString;
    use serde_json::json;
    use std::net::TcpListener;
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };
    use vault_client::{VaultTarget, VaultTransport};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DB_LEASE_DURATION_SECONDS: u64 = 2;
    const DB_LEASE_ID: &str = "lease-1";

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    fn create_global_args(url: &str) -> GlobalArgs {
        let target = VaultTarget::parse(url).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        GlobalArgs::new(url.to_string(), transport)
    }

    async fn wait_for_shutdown(
        rx: &mut mpsc::UnboundedReceiver<ShutdownSignal>,
    ) -> Result<ShutdownSignal> {
        match timeout(Duration::from_secs(15), rx.recv()).await {
            Ok(Some(signal)) => Ok(signal),
            Ok(None) => bail!("shutdown channel disconnected unexpectedly"),
            Err(_) => bail!("expected shutdown signal after 3 failed renew attempts"),
        }
    }

    #[tokio::test]
    async fn try_renew_token_failure_triggers_shutdown() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("vault-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "vault-token"))
            .and(body_json(json!({ "increment": 0 })))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "errors": ["boom"]
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "vault-token"))
            .and(body_json(json!({
                "increment": DB_LEASE_DURATION_SECONDS,
                "lease_id": DB_LEASE_ID
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": DB_LEASE_DURATION_SECONDS
            })))
            .mount(&server)
            .await;

        let mut globals = create_global_args(&server.uri());
        globals.set_token(token);
        globals.vault_db_lease_id = DB_LEASE_ID.to_string();
        globals.vault_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        let signal = wait_for_shutdown(&mut rx).await?;
        if signal != ShutdownSignal::TokenRenewalFailed {
            bail!("expected token renewal failure, got {:?}", signal);
        }

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };

        let token_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/auth/token/renew-self")
            .count();
        if token_renew_requests != 3 {
            bail!("expected 3 token renew attempts, got {token_renew_requests}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn try_renew_db_lease_failure_triggers_shutdown() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("vault-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "vault-token"))
            .and(body_json(json!({ "increment": 0 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "lease_duration": DB_LEASE_DURATION_SECONDS }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "vault-token"))
            .and(body_json(json!({
                "increment": DB_LEASE_DURATION_SECONDS,
                "lease_id": DB_LEASE_ID
            })))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "errors": ["boom"]
            })))
            .mount(&server)
            .await;

        let mut globals = create_global_args(&server.uri());
        globals.set_token(token);
        globals.vault_db_lease_id = DB_LEASE_ID.to_string();
        globals.vault_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        let signal = wait_for_shutdown(&mut rx).await?;
        if signal != ShutdownSignal::DbLeaseRenewalFailed {
            bail!("expected DB lease renewal failure, got {:?}", signal);
        }

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };

        let lease_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/sys/leases/renew")
            .count();
        if lease_renew_requests != 3 {
            bail!("expected 3 DB lease renew attempts, got {lease_renew_requests}");
        }
        Ok(())
    }
}
