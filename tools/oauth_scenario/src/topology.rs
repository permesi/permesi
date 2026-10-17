//! Bounded local replica topology, shared by supervision, routing and assertions.
//!
//! These paths always live in the run's private directory. They cannot select an
//! external service or change the product's deployment configuration.

use crate::error::{Result, check};
use std::path::{Path, PathBuf};

/// Distinct private sockets for every Permesi process and the separate admission service.
pub struct Topology {
    pub replicas: Vec<PathBuf>,
    pub genesis: PathBuf,
}

impl Topology {
    /// Bounds resource usage before constructing runner-authored socket paths.
    pub fn new(root: &Path, count: u16) -> Result<Self> {
        check(
            (3..=5).contains(&count),
            "Replica count must be between three and five.",
        )?;
        Ok(Self {
            replicas: (0..count)
                .map(|index| root.join(format!("permesi-{index}.sock")))
                .collect(),
            genesis: root.join("genesis.sock"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_bounds_and_separates_all_service_sockets() -> Result<()> {
        for count in [3, 4, 5] {
            let topology = Topology::new(Path::new("/private/run"), count)?;
            assert_eq!(topology.replicas.len(), usize::from(count));
            let paths = topology
                .replicas
                .iter()
                .chain([&topology.genesis])
                .collect::<std::collections::HashSet<_>>();
            assert_eq!(paths.len(), usize::from(count) + 1);
            assert!(
                paths
                    .iter()
                    .all(|path| path.parent() == Some(Path::new("/private/run")))
            );
        }
        for count in [0, 1, 2, 6, u16::MAX] {
            assert!(Topology::new(Path::new("/private/run"), count).is_err());
        }
        Ok(())
    }
}
