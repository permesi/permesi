use crate::{cli::globals::GlobalArgs, permesi};
use anyhow::Result;
use rand::{Rng, SeedableRng, rngs::StdRng};
use secrecy::SecretString;
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};
use tracing::{debug, error, instrument, warn};

/// Renew a Vault token
#[instrument(skip(token))]
async fn renew_token(url: &str, token: &SecretString, increment: Option<u64>) -> Result<u64> {
    vault_client::renew_token(permesi::APP_USER_AGENT, url, token, increment).await
}

#[instrument(skip(token))]
async fn renew_db_token(
    url: &str,
    token: &SecretString,
    lease_id: &str,
    increment: u64,
) -> Result<u64> {
    vault_client::renew_db_token(permesi::APP_USER_AGENT, url, token, lease_id, increment).await
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
