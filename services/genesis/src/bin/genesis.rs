use anyhow::Result;
use genesis::cli;

// Main function
#[tokio::main]
async fn main() -> Result<()> {
    let action = cli::start()?;

    action.execute().await?;

    Ok(())
}
