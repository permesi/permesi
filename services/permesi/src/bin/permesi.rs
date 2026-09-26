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

    let result = action.execute().await;

    // Flush batched spans even when the action failed, so the trace explaining the exit
    // is exported. Shutdown blocks on the exporter, so keep it off the async workers.
    let _ = tokio::task::spawn_blocking(cli::telemetry::shutdown_tracer).await;

    result
}
