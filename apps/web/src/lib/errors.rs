use std::fmt;

#[derive(Clone, Debug)]
pub enum AppError {
    Config(String),
    Network(String),
    Timeout(String),
    Http { status: u16, message: String },
    Parse(String),
    Serialization(String),
}

impl fmt::Display for AppError {
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
