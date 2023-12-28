use anyhow::Result;
use permesi::cli::{actions, actions::Action, start};

// Main function
#[tokio::main]
async fn main() -> Result<()> {
    // Start the program
    let (action, globals) = start().await?;

    // Handle the action
    match action {
        Action::Server { .. } => actions::server::handle(action, &globals).await?,
    }

    Ok(())
}
