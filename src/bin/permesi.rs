use anyhow::Result;
use permesi::cli::{actions, actions::Action, start};

// Main function
#[tokio::main]
async fn main() -> Result<()> {
    // Start the program
    let action = start()?;

    // Handle the action
    match action {
        Action::Server { .. } => actions::server::handle(action).await?,
    }

    Ok(())
}
