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
mod tests {
    use super::{renew_db_token, renew_token};
    use anyhow::Result;
    use secrecy::SecretString;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
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
}
