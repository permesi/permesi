use anyhow::{Context, Result};
use permesi::cli;
use rustls::crypto::ring;

// Main function
#[tokio::main]
async fn main() -> Result<()> {
    ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))
        .context("TLS crypto provider initialization failed")?;
    let action = cli::start()?;

    action.execute().await?;

    Ok(())
}
