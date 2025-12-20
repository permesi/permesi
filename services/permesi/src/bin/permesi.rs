use anyhow::Result;
use permesi::cli;

// Main function
#[tokio::main]
async fn main() -> Result<()> {
    let action = cli::start()?;

    action.execute().await?;

    Ok(())
}
