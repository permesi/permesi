//! Value-free failures shared by HTTP, browser, infrastructure and scenario checks.
//!
//! External errors can include passwords, DSNs, cookies or callback queries. They
//! are intentionally discarded at this boundary; diagnostics carry only curated
//! static messages and a classification, never arbitrary error strings.

use serde::Serialize;

/// Distinguishes failed expectations from unavailable infrastructure and harness faults.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Assertion,
    Infrastructure,
    Harness,
    Cleanup,
}

/// A serializable diagnostic whose message cannot contain an external value.
#[derive(Clone, Debug, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct Failure {
    pub kind: Kind,
    pub message: &'static str,
}

pub type Result<T> = std::result::Result<T, Failure>;

impl Failure {
    /// Records infrastructure failure without retaining the underlying error or credentials.
    pub const fn infrastructure(message: &'static str) -> Self {
        Self {
            kind: Kind::Infrastructure,
            message,
        }
    }

    /// Records a concrete expectation failure without serializing the actual secret-bearing value.
    pub const fn assertion(message: &'static str) -> Self {
        Self {
            kind: Kind::Assertion,
            message,
        }
    }

    /// Records a harness invariant failure with a caller-authored static message.
    pub const fn harness(message: &'static str) -> Self {
        Self {
            kind: Kind::Harness,
            message,
        }
    }
}

/// Converts third-party failures to curated diagnostics before reports or stderr see them.
pub trait Safe<T> {
    /// Discards external error data at the boundary and retains only the caller-authored message.
    fn safe(self, message: &'static str) -> Result<T>;
}

impl<T, E> Safe<T> for std::result::Result<T, E> {
    fn safe(self, message: &'static str) -> Result<T> {
        self.map_err(|_| Failure::infrastructure(message))
    }
}

/// Asserts an independently calculated expectation without interpolating actual values.
pub fn check(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Failure::assertion(message))
    }
}
