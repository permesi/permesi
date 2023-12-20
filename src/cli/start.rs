use crate::cli::{actions::Action, commands, dispatch::handler};
use anyhow::Result;

/// Start the CLI
pub fn start() -> Result<Action> {
    let matches = commands::new().get_matches();

    let verbosity_level = match matches.get_one::<u8>("verbosity").map_or(0, |&v| v) {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };

    tracing_subscriber::fmt()
        .with_max_level(verbosity_level)
        .with_target(false)
        .init();

    let action = handler(&matches)?;

    Ok(action)
}
