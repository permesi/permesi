//! Shared error type for frontend network and config failures. It keeps error
//! handling consistent across features without exposing sensitive payloads, and
//! the enum stays lightweight for reactive UI state.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Uniform error type surfaced by API helpers and route actions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AppError {
    Config(String),
    Network(String),
    Timeout(String),
    Http { status: u16, message: String },
    Parse(String),
    Serialization(String),
}

impl fmt::Display for AppError {
    /// Formats user-facing error strings for alerts and logs.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Config(message) => write!(formatter, "Config error: {message}"),
            AppError::Network(message) => write!(formatter, "Network error: {message}"),
            AppError::Timeout(message) => write!(formatter, "Timeout: {message}"),
            AppError::Http { status, message } => {
                write!(formatter, "Request failed ({status}): {message}")
            }
            AppError::Parse(message) => write!(formatter, "Response error: {message}"),
            AppError::Serialization(message) => {
                write!(formatter, "Request error: {message}")
            }
        }
    }
}

impl std::error::Error for AppError {}
