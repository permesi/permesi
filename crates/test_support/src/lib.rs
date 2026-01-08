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
    format!("permesi-test-{prefix}-{}", Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_name_includes_prefix() {
        let name = unique_name("test");
        assert!(name.starts_with("permesi-test-test-"));
        assert!(name.len() > "permesi-test-test-".len());
    }

    #[test]
    fn test_network_name_includes_prefix() {
        let network = TestNetwork::new("net");
        assert!(network.name().starts_with("permesi-test-net-"));
    }
}
