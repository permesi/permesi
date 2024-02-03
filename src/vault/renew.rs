use crate::{cli::globals::GlobalArgs, permesi, vault};
use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use serde_json::{json, Value};
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};
use tracing::{debug, error, instrument, warn};

/// Renew a Vault token
#[instrument]
async fn renew_token(url: &str, token: &Secret<String>, increment: Option<u64>) -> Result<u64> {
    let client = Client::builder()
        .user_agent(permesi::APP_USER_AGENT)
        .build()?;

    let payload = json!({
        "increment": increment.map_or(0, |increment| increment)
    });

    // Parse the URL
    let renew_url = vault::endpoint_url(url, "/v1/auth/token/renew-self")?;

    let response = client
        .post(&renew_url)
        .json(&payload)
        .header("X-Vault-Token", token.expose_secret())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            renew_url,
            status,
            json_response["errors"][0].as_str().unwrap_or("")
        ));
    }

    let json_response: Value = response.json().await?;

    json_response["auth"]["lease_duration"]
        .as_u64()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

#[instrument]
async fn renew_db_token(
    url: &str,
    token: &Secret<String>,
    lease_id: &str,
    increment: u64,
) -> Result<u64> {
    let client = Client::builder()
        .user_agent(permesi::APP_USER_AGENT)
        .build()?;

    let payload = json!({
        "increment": increment,
        "lease_id": lease_id
    });

    // Parse the URL
    let renew_url = vault::endpoint_url(url, "/v1/sys/leases/renew")?;

    let response = client
        .post(&renew_url)
        .json(&payload)
        .header("X-Vault-Token", token.expose_secret())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            renew_url,
            status,
            json_response["errors"][0].as_str().unwrap_or("")
        ));
    }

    let json_response: Value = response.json().await?;

    json_response["lease_duration"]
        .as_u64()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Refresh a Vault token
#[instrument]
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

                            break;
                        }

                        Err(e) => {
                            error!("Failed to renew token: {}", e);

                            if attempt == 3 {
                                error!("Failed to renew token after 3 attempts: {}", e);
                                let _ = tx.send(());
                                return;
                            }

                            continue;
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

                            break;
                        }

                        Err(e) => {
                            error!("Failed to renew DB lease: {}", e);

                            if attempt == 3 {
                                error!("Failed to renew DB lease after 3 attempts: {}", e);
                                let _ = tx.send(());
                                return;
                            }

                            continue;
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
