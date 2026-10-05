//! Supervision for owned local processes. Output is discarded before it can expose secrets.

use crate::error::{Result, Safe};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

/// A kill-on-drop child, additionally reaped explicitly during reported cleanup.
pub struct Process(pub Child);

impl Process {
    /// Starts a product binary with no inherited product, proxy, Vault or deployment configuration.
    pub fn service(binary: &Path, arguments: &[String], secrets: &[(&str, &str)]) -> Result<Self> {
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin");
        command.args(arguments).envs(secrets.iter().copied());
        Self::spawn(&mut command)
    }

    /// Owns the child handle before returning; stdout/stderr never enter reports or terminal logs.
    pub fn spawn(command: &mut Command) -> Result<Self> {
        command
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(Self(command.spawn().safe("Cannot start owned process.")?))
    }

    /// Stops and reaps only this child. Repeated cleanup is harmless.
    pub async fn stop(&mut self) -> Result<()> {
        if self
            .0
            .try_wait()
            .safe("Cannot inspect owned process.")?
            .is_none()
        {
            self.0.start_kill().safe("Cannot stop owned process.")?;
        }
        tokio::time::timeout(Duration::from_secs(5), self.0.wait())
            .await
            .safe("Owned process did not stop.")?
            .safe("Cannot reap owned process.")?;
        Ok(())
    }
}

/// Executes a bounded command, keeping all output private even on unsuccessful exit.
pub async fn output(command: &mut Command, seconds: u64) -> Result<Vec<u8>> {
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let result = tokio::time::timeout(Duration::from_secs(seconds), command.output())
        .await
        .safe("Local command exceeded its deadline.")?
        .safe("Cannot execute local command.")?;
    if !result.status.success() {
        return Err(crate::error::Failure::infrastructure(
            "Local command failed.",
        ));
    }
    Ok(result.stdout)
}
