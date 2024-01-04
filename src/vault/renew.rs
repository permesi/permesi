use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, instrument, warn};

/// Renew a Vault token
#[instrument]
async fn renew_token(
    globals: &GlobalArgs,
    lease_id: Option<&str>,
    increment: Option<u64>,
) -> Result<u64> {
    let client = Client::builder()
        .user_agent(vault::APP_USER_AGENT)
        .build()?;

    let mut payload = json!({
        "increment": increment.map_or(0, |increment| increment)
    });

    // default to renew-self endpoint
    let endpoint = lease_id.map_or_else(
        || "/v1/auth/token/renew-self".to_string(),
        |lid| {
            payload["lease_id"] = json!(lid);
            "/v1/sys/leases/renew".to_string()
        },
    );

    // Parse the URL
    let renew_url = vault::endpoint_url(globals, &endpoint)?;

    let response = client
        .post(&renew_url)
        .json(&payload)
        .header("X-Vault-Token", &globals.vault_token)
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

    if lease_id.is_none() {
        json_response["auth"]["lease_duration"]
            .as_u64()
            .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
    } else {
        json_response["lease_duration"]
            .as_u64()
            .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
    }
}

/// Refresh a Vault token
#[instrument]
pub async fn try_renew(globals: &GlobalArgs, lease_duration: u64) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    let mut jittered_lease_duration =
        Duration::from_secs((lease_duration as f64 * rng.gen_range(0.7..0.9)) as u64);

    let mut jittered_lease_duration_db = Duration::from_secs(
        (globals.vault_db_lease_duration as f64 * rng.gen_range(0.7..0.9)) as u64,
    );

    let globals = globals.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sleep(jittered_lease_duration) => {
                    for attempt in 1..=3 {

                        let backoff_time = 2u64.pow(attempt - 1);

                        if attempt > 1 {
                            warn!("Backing off for {} seconds", backoff_time);
                            sleep(Duration::from_secs(backoff_time)).await;
                        }

                        debug!("Renewing token");
                        match renew_token(&globals, None, None).await {
                            Ok(lease_duration) => {

                        jittered_lease_duration = Duration::from_secs(
                            (lease_duration as f64 * rng.gen_range(0.7..0.9)) as u64);

                                debug!("Will renew token in {} seconds", jittered_lease_duration.as_secs());

                                break;
                            }

                            Err(e) => {
                                error!("Error renewing token: {}", e);

                                if attempt == 3 {
                                    error!("Failed to renew token after 3 attempts");
                                    return;
                                }

                                continue;
                            }
                        }
                    }

                }

                _ = sleep(jittered_lease_duration_db) => {
                    for attempt in 1..=3 {

                        let backoff_time = 2u64.pow(attempt - 1);

                        if attempt > 1 {
                            warn!("Backing off for {} seconds", backoff_time);
                            sleep(Duration::from_secs(backoff_time)).await;
                        }

                        debug!("Renewing DB lease ID");
                        match renew_token(&globals, Some(&globals.vault_db_lease_id), Some(globals.vault_db_lease_duration)).await {
                            Ok(lease_duration) => {

                        jittered_lease_duration_db = Duration::from_secs(
                            (lease_duration as f64 * rng.gen_range(0.7..0.9)) as u64);

                                debug!("Will renew DB lease ID in {} seconds", jittered_lease_duration_db.as_secs());

                                break;
                            }

                            Err(e) => {
                                error!("Error renewing token: {}", e);

                                if attempt == 3 {
                                    error!("Failed to renew DB token after 3 attempts");
                                    return;
                                }

                                continue;
                            }
                        }
                    }

                }
            }
        }
    });

    Ok(())
}
