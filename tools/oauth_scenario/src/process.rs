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
    /// Sends SIGTERM to this unreaped owned child and requires graceful exit within five seconds.
    /// A timeout remains a test failure; the retained handle still permits forced cleanup.
    pub async fn terminate(&mut self) -> Result<()> {
        crate::error::check(
            self.0
                .try_wait()
                .safe("Cannot inspect owned process.")?
                .is_none(),
            "Owned process exited before graceful shutdown.",
        )?;
        let pid = self
            .0
            .id()
            .ok_or_else(|| crate::error::Failure::harness("Missing owned process ID."))?;
        output(
            Command::new("kill")
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .args(["-TERM", &pid.to_string()]),
            5,
        )
        .await?;
        let status = tokio::time::timeout(Duration::from_secs(5), self.0.wait())
            .await
            .safe("Owned process did not terminate gracefully.")?
            .safe("Cannot reap terminated process.")?;
        crate::error::check(
            status.success(),
            "Owned process did not exit cleanly after SIGTERM.",
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A crashed child cannot count as a successful rolling shutdown or become an invisible retry.
    #[tokio::test]
    async fn graceful_shutdown_rejects_a_previously_exited_child() -> Result<()> {
        let mut process = Process::spawn(Command::new("sh").args(["-c", "exit 7"]))?;
        let status = process.0.wait().await.safe("Cannot reap crash fixture.")?;
        assert_eq!(status.code(), Some(7));
        assert!(process.terminate().await.is_err());
        process.stop().await?;
        Ok(())
    }
}
