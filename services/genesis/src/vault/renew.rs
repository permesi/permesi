use crate::{cli::globals::GlobalArgs, vault};
use anyhow::Result;
use rand::{Rng, SeedableRng, rngs::StdRng};
use secrecy::SecretString;
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};
use tracing::{debug, error, info, instrument, warn};

/// Renew a Vault token
#[instrument(skip(token))]
async fn renew_token(url: &str, token: &SecretString, increment: Option<u64>) -> Result<u64> {
    vault_client::renew_token(vault::APP_USER_AGENT, url, token, increment).await
}

#[instrument(skip(token))]
async fn renew_db_token(
    url: &str,
    token: &SecretString,
    lease_id: &str,
    increment: u64,
) -> Result<u64> {
    vault_client::renew_db_token(vault::APP_USER_AGENT, url, token, lease_id, increment).await
}

/// Refresh a Vault token
/// # Errors
/// Returns an error if the initial renewal task setup fails (e.g. request construction).
#[instrument(skip(globals, tx))]
pub async fn try_renew(globals: &GlobalArgs, tx: mpsc::UnboundedSender<()>) -> Result<()> {
    // In Agent Proxy mode, the Agent handles its own auth token renewal.
    // The app only needs to renew its own (TCP mode) token.
    if globals.vault_transport.is_agent_proxy() {
        info!("Vault agent proxy mode enabled; skipping token renewals");
    } else {
        // renew the token
        tokio::spawn({
            let mut rng = StdRng::from_entropy();
            let mut jittered_lease_duration: Duration = Duration::default();

            let url = globals.vault_url.clone();
            let token = globals.vault_token.clone();
            let tx = tx.clone();

            async move {
                loop {
                    for attempt in 1..=3 {
                        let backoff_time = 2u64.pow(attempt - 1);

                        if attempt > 1 {
                            warn!("Backing off for {} seconds", backoff_time);
                            sleep(Duration::from_secs(backoff_time)).await;
                        }

                        match renew_token(&url, &token, None).await {
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
                                    let _ = tx.send(());
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

    // renew the DB lease_id
    tokio::spawn({
        let mut rng = StdRng::from_entropy();
        let mut jittered_lease_duration: Duration = Duration::default();

        let url = globals.vault_url.clone();
        let token = globals.vault_token.clone();
        let db_lease_id = globals.vault_db_lease_id.clone();
        let db_lease_duration = globals.vault_db_lease_duration;
        let tx = tx.clone();

        async move {
            loop {
                for attempt in 1..=3 {
                    let backoff_time = 2u64.pow(attempt - 1);

                    if attempt > 1 {
                        warn!("Backing off for {} seconds", backoff_time);
                        sleep(Duration::from_secs(backoff_time)).await;
                    }

                    match renew_db_token(&url, &token, &db_lease_id, db_lease_duration).await {
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
                                let _ = tx.send(());
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

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{renew_db_token, renew_token, try_renew};
    use crate::cli::globals::GlobalArgs;
    use anyhow::{Result, bail};
    use secrecy::SecretString;
    use serde_json::json;
    use std::net::TcpListener;
    use tokio::{
        sync::mpsc,
        time::{Duration, sleep, timeout},
    };
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DB_LEASE_DURATION_SECONDS: u64 = 2;
    const DB_LEASE_ID: &str = "lease-1";

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    async fn wait_for_shutdown(rx: &mut mpsc::UnboundedReceiver<()>) -> Result<()> {
        match timeout(Duration::from_secs(15), rx.recv()).await {
            Ok(Some(())) => Ok(()),
            Ok(None) => bail!("shutdown channel disconnected unexpectedly"),
            Err(_) => bail!("expected shutdown signal after 3 failed renew attempts"),
        }
    }

    #[tokio::test]
    async fn renew_token_returns_lease_duration() -> Result<()> {
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
                "auth": { "lease_duration": 42 }
            })))
            .mount(&server)
            .await;

        let lease_duration = renew_token(&server.uri(), &token, None).await?;
        assert_eq!(lease_duration, 42);
        Ok(())
    }

    #[tokio::test]
    async fn renew_db_token_returns_lease_duration() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("vault-token".to_string());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("X-Vault-Token", "vault-token"))
            .and(body_json(json!({
                "increment": 120,
                "lease_id": "lease-1"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": 120
            })))
            .mount(&server)
            .await;

        let lease_duration = renew_db_token(&server.uri(), &token, "lease-1", 120).await?;
        assert_eq!(lease_duration, 120);
        Ok(())
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

        let target = crate::vault::VaultTarget::parse(&server.uri()).unwrap();
        let transport = crate::vault::VaultTransport::from_target("test-agent", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(token);
        globals.vault_db_lease_id = DB_LEASE_ID.to_string();
        globals.vault_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        wait_for_shutdown(&mut rx).await?;

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

        let target = crate::vault::VaultTarget::parse(&server.uri()).unwrap();
        let transport = crate::vault::VaultTransport::from_target("test-agent", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(token);
        globals.vault_db_lease_id = DB_LEASE_ID.to_string();
        globals.vault_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        wait_for_shutdown(&mut rx).await?;

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

    #[tokio::test]
    async fn try_renew_success_does_not_trigger_shutdown_immediately() -> Result<()> {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": DB_LEASE_DURATION_SECONDS
            })))
            .mount(&server)
            .await;

        let target = crate::vault::VaultTarget::parse(&server.uri()).unwrap();
        let transport = crate::vault::VaultTransport::from_target("test-agent", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(token);
        globals.vault_db_lease_id = DB_LEASE_ID.to_string();
        globals.vault_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, mut rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        // Let the renewal tasks run at least twice (jittered to 1 second for a 2-second lease).
        sleep(Duration::from_secs(3)).await;

        match timeout(Duration::from_millis(50), rx.recv()).await {
            Ok(Some(())) => bail!("unexpected shutdown signal"),
            Ok(None) => bail!("shutdown channel disconnected unexpectedly"),
            Err(_) => {}
        }

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };

        let token_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/auth/token/renew-self")
            .count();
        let lease_renew_requests = requests
            .iter()
            .filter(|request| request.url.path() == "/v1/sys/leases/renew")
            .count();

        if token_renew_requests < 2 {
            bail!("expected at least 2 token renew attempts, got {token_renew_requests}");
        }
        if lease_renew_requests < 2 {
            bail!("expected at least 2 DB lease renew attempts, got {lease_renew_requests}");
        }

        Ok(())
    }

    #[tokio::test]
    async fn try_renew_runs_db_renewal_task() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let token = SecretString::from("vault-token".to_string());

        // We expect the DB renewal to be attempted.
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lease_duration": DB_LEASE_DURATION_SECONDS
            })))
            .mount(&server)
            .await;

        // We also expect token renewal (since we are forced to use TCP mode for mocking)
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "lease_duration": 100 }
            })))
            .mount(&server)
            .await;

        let target = crate::vault::VaultTarget::parse(&server.uri()).unwrap();
        let transport = crate::vault::VaultTransport::from_target("test-agent", target).unwrap();
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.set_token(token);
        globals.vault_db_lease_id = DB_LEASE_ID.to_string();
        globals.vault_db_lease_duration = DB_LEASE_DURATION_SECONDS;

        let (tx, _rx) = mpsc::unbounded_channel();
        try_renew(&globals, tx).await?;

        // Wait a bit to ensure tasks start and requests are made
        sleep(Duration::from_millis(500)).await;

        let Some(requests) = server.received_requests().await else {
            bail!("wiremock request recording is disabled");
        };

        // Check that DB renewal was attempted
        let db_renewals = requests
            .iter()
            .filter(|r| r.url.path() == "/v1/sys/leases/renew")
            .count();
        assert!(db_renewals > 0, "DB renewal should be attempted");

        Ok(())
    }
}
