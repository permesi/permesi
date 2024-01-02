use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::time::{interval, sleep, Duration};
use tracing::{debug, error, info, instrument, warn};

/// Renew a Vault token
#[instrument]
async fn renew_token(globals: &GlobalArgs, increment: Option<u64>) -> Result<u64> {
    let client = Client::builder()
        .user_agent(vault::APP_USER_AGENT)
        .build()?;

    // Parse the URL
    let renew_url = vault::endpoint_url(globals, "/v1/auth/token/renew-self")?;

    let payload = json!({
        "increment": increment.map_or(0, |increment| increment)
    });

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

    json_response["auth"]["lease_duration"]
        .as_u64()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Refresh a Vault token
#[instrument]
pub async fn try_renew(globals: &GlobalArgs, lease_duration: u64) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    let mut jittered_lease_duration = (lease_duration as f64 * rng.gen_range(0.7..0.9)) as u64;

    let mut renew_token_interval = interval(Duration::from_secs(jittered_lease_duration));

    let globals = globals.clone();

    tokio::spawn(async move {
        loop {
            renew_token_interval.tick().await;

            for attempt in 1..=3 {
                let backoff_time = 2u64.pow(attempt - 1);

                if attempt > 1 {
                    warn!("Backing off for {} seconds", backoff_time);
                    sleep(Duration::from_secs(backoff_time)).await;
                }

                match renew_token(&globals, None).await {
                    Ok(lease_duration) => {
                        debug!("token lease duration {} seconds", lease_duration);

                        jittered_lease_duration =
                            (lease_duration as f64 * rng.gen_range(0.7..0.9)) as u64;

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

            info!("Will renew token in {} seconds", jittered_lease_duration);
        }
    });

    Ok(())
}
