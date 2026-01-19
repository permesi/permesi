use crate::cli::{actions::Action, commands, dispatch, telemetry};
use anyhow::Result;

/// Map verbosity count to tracing level
const fn get_verbosity_level(verbosity: u8) -> Option<tracing::Level> {
    match verbosity {
        0 => None,
        1 => Some(tracing::Level::WARN),
        2 => Some(tracing::Level::INFO),
        3 => Some(tracing::Level::DEBUG),
        _ => Some(tracing::Level::TRACE),
    }
}

/// Main entry point for the CLI - builds and returns the Action
///
/// # Errors
///
/// Returns an error if argument parsing, telemetry initialization, or action dispatch fails
pub fn start() -> Result<Action> {
    // 1. Parse command-line arguments
    let matches = commands::new().get_matches();

    // 2. Extract verbosity level
    let verbosity_level = get_verbosity_level(
        matches
            .get_one::<u8>(commands::logging::ARG_VERBOSITY)
            .copied()
            .unwrap_or(0),
    );

    // 3. Initialize telemetry
    telemetry::init(verbosity_level)?;

    // 4. Dispatch to appropriate action
    let action = dispatch::handler(&matches)?;

    // 5. Return the action for execution by the binary
    Ok(action)
}
