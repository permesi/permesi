pub mod genesis;
pub mod postgres;
pub mod runtime;
pub mod vault;

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TestNetwork {
    name: String,
}

impl TestNetwork {
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self {
            name: unique_name(prefix),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}
