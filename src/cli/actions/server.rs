use crate::cli::actions::Action;
use crate::permesi::new;
use anyhow::Result;

/// Handle the create action
pub async fn handle(action: Action) -> Result<()> {
    match action {
        Action::Server { port, dsn } => {
            new(port, dsn).await?;
        }
    }

    Ok(())
}
