pub mod server;

// Internal "interpreter" for `Action`.
// We keep the match in a separate module so `mod.rs` stays small as more actions are added.
mod run;

#[derive(Debug)]
pub enum Action {
    Server(server::Args),
}

impl Action {
    // Convenience wrapper so call sites can do `action.execute().await`.
    // When adding new actions (e.g. `Foo`, `Bar`), extend the match in `run::execute`.
    /// Execute the action.
    /// # Errors
    /// Returns an error if the action fails.
    pub async fn execute(self) -> anyhow::Result<()> {
        run::execute(self).await
    }
}
