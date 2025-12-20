use crate::cli::actions::{Action, server};
use anyhow::Result;

/// Execute the provided action.
// This is the single dispatch point for all CLI actions.
// To add a new action, add a new `Action::*` variant and a corresponding `*_::execute` call here.
/// # Errors
/// Returns an error if the action fails.
pub async fn execute(action: Action) -> Result<()> {
    match action {
        Action::Server(args) => server::execute(args).await,
    }
}
