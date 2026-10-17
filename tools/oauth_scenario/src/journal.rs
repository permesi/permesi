//! Atomic, secret-free recovery records for changing process incarnations.
//!
//! Flow Overview: register the run before startup, persist each stored child handle
//! before awaiting readiness, and replace PID/birth-tick records after stops and
//! restarts. Cancellation leaves handles in the supervisor for normal cleanup;
//! SIGKILL recovery can identify the current incarnation without trusting a reused PID.

use crate::{
    error::{Result, Safe},
    files::atomic_write,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::process::Child;

/// Linux birth ticks distinguish the owned child from a later process with the same PID.
#[derive(Clone, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
}

impl ProcessIdentity {
    /// Missing/reaped handles have no live identity; unexpected /proc errors fail closed.
    pub fn read(child: &Child) -> Result<Option<Self>> {
        let Some(pid) = child.id() else {
            return Ok(None);
        };
        Ok(Some(Self {
            pid,
            start_ticks: birth_ticks(pid)?,
        }))
    }
}

/// Missing /proc data for an unreaped child fails closed instead of publishing an incomplete recovery record.
fn birth_ticks(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .safe("Cannot identify owned process.")?;
    let start_ticks = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .ok_or_else(|| crate::error::Failure::harness("Missing owned process birth ticks."))?
        .parse()
        .safe("Invalid owned process birth ticks.")?;
    Ok(start_ticks)
}

/// Allowlisted recovery metadata; credentials, command lines and HTTP values are excluded.
#[derive(Serialize)]
struct Ownership {
    schema_version: u32,
    run_id: String,
    engine: &'static str,
    network: String,
    containers: [String; 3],
    private_directory: PathBuf,
    processes: Vec<ProcessIdentity>,
    resource_origin: Option<String>,
}

/// One atomic artifact retains the existing ownership format across all process generations.
pub struct Journal {
    directory: PathBuf,
    name: String,
    ownership: Ownership,
}

impl Journal {
    /// Records only resources created for this generated run, before any child can start.
    pub fn new(
        directory: &Path,
        repetition: u32,
        run_id: &str,
        network: &str,
        private: &Path,
    ) -> Self {
        Self {
            directory: directory.into(),
            name: format!("ownership-{repetition}.json"),
            ownership: Ownership {
                schema_version: 1,
                run_id: run_id.into(),
                engine: "local Podman",
                network: network.into(),
                containers: ["postgres", "vault", "browser"]
                    .map(|name| format!("ps-{run_id}-{name}")),
                private_directory: private.into(),
                processes: Vec::new(),
                resource_origin: None,
            },
        }
    }

    /// Retains the owned public resource origin independently of later process restarts.
    pub fn resource_origin(&mut self, origin: &str) {
        self.ownership.resource_origin = Some(origin.into());
    }

    /// Replaces only the current PID/birth-tick set, preserving complete metadata on every write.
    pub fn record(&mut self, processes: Vec<ProcessIdentity>) -> Result<()> {
        self.ownership.processes = processes;
        atomic_write(
            &self.directory,
            &self.name,
            &serde_json::to_vec_pretty(&self.ownership).safe("Cannot encode ownership record.")?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::PrivateDir;

    /// An impossible live PID must fail rather than produce a valid-looking incomplete identity.
    #[test]
    fn journal_rejects_missing_process_metadata() {
        assert!(birth_ticks(u32::MAX).is_err());
    }

    #[test]
    fn journal_replaces_incarnations_without_losing_resource_ownership() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut journal = Journal::new(
            &directory.0,
            1,
            "owned-run",
            "owned-network",
            Path::new("/private/run"),
        );
        journal.resource_origin("https://localhost:1234");
        for pid in [100, 200] {
            journal.record(vec![ProcessIdentity {
                pid,
                start_ticks: u64::from(pid) + 1,
            }])?;
            let bytes = std::fs::read(directory.0.join("ownership-1.json"))
                .safe("Cannot read test journal.")?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).safe("Invalid test journal.")?;
            assert_eq!(
                value.get("processes"),
                Some(&serde_json::json!([{"pid":pid,"start_ticks":u64::from(pid)+1}]))
            );
            assert_eq!(
                value.get("resource_origin"),
                Some(&serde_json::json!("https://localhost:1234"))
            );
            assert_eq!(
                value.get("network"),
                Some(&serde_json::json!("owned-network"))
            );
            assert_eq!(
                value.pointer("/containers/0"),
                Some(&serde_json::json!("ps-owned-run-postgres"))
            );
            let mode = std::os::unix::fs::PermissionsExt::mode(
                &std::fs::metadata(directory.0.join("ownership-1.json"))
                    .safe("Cannot stat test journal.")?
                    .permissions(),
            );
            assert_eq!(mode & 0o777, 0o600);
        }
        journal.record(Vec::new())?;
        assert_eq!(
            std::fs::read_dir(&directory.0)
                .safe("Cannot inspect test journal directory.")?
                .count(),
            1
        );
        Ok(())
    }
}
