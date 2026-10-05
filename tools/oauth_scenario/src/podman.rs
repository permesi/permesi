//! Local Podman ownership without global cleanup or development-stack reuse.
//!
//! Every run gets a private network, names and ownership label. Commands use the
//! local engine explicitly; a supplied Unix Podman API is supported for CI. Remote
//! TCP engines and Docker sockets are rejected before resources are created.

use crate::{
    error::{Result, Safe, check},
    process::output,
};
use std::path::Path;
use tokio::process::Command;

/// Explicit local-engine selector; no command relies on inherited container context.
pub struct Podman {
    socket: Option<String>,
    pub run_id: String,
    pub network: String,
    pub names: Vec<String>,
}

impl Podman {
    /// Verifies Podman and rejects a nonlocal or non-Podman endpoint before starting a run.
    pub async fn new(run_id: String) -> Result<Self> {
        let socket = std::env::var("DOCKER_HOST").ok().filter(|s| !s.is_empty());
        if let Some(socket) = &socket {
            check(
                socket.starts_with("unix:///") && !socket.contains(['\n', '\r']),
                "Only a local Unix Podman API is permitted.",
            )?;
        }
        let engine = Self {
            network: format!("ps-{run_id}"),
            run_id,
            socket,
            names: Vec::new(),
        };
        let info = output(engine.command().args(["info", "--format", "json"]), 10).await?;
        let info: serde_json::Value =
            serde_json::from_slice(&info).safe("Cannot identify local Podman engine.")?;
        check(
            info.get("version").is_some() || info.get("Version").is_some(),
            "Container engine must be Podman.",
        )?;
        Ok(engine)
    }

    /// Constructs structured arguments; clearing context prevents accidental host-engine retargeting.
    pub fn command(&self) -> Command {
        let mut command = Command::new("podman");
        command
            .env_remove("DOCKER_HOST")
            .env_remove("CONTAINER_HOST")
            .env_remove("CONTAINER_CONNECTION");
        if let Some(socket) = &self.socket {
            command.args(["--url", socket]);
        } else {
            command.arg("--remote=false");
        }
        command
    }

    /// Creates the exact per-run network. An existing name is never adopted or removed.
    pub async fn create_network(&self) -> Result<()> {
        output(
            self.command().args([
                "network",
                "create",
                "--label",
                &format!("io.permesi.scenario={}", self.run_id),
                &self.network,
            ]),
            20,
        )
        .await?;
        Ok(())
    }

    /// Records ownership before startup so cancellation can remove a partially started container.
    pub async fn container(
        &mut self,
        suffix: &str,
        image: &str,
        env_file: &Path,
        port: u16,
    ) -> Result<(String, u16)> {
        let name = format!("ps-{}-{suffix}", self.run_id);
        self.names.push(name.clone());
        output(
            self.command()
                .args([
                    "run",
                    "--detach",
                    "--log-driver=none",
                    "--name",
                    &name,
                    "--label",
                    &format!("io.permesi.scenario={}", self.run_id),
                    "--network",
                    &self.network,
                    "--publish",
                    &format!("127.0.0.1::{port}"),
                    "--env-file",
                ])
                .arg(env_file)
                .arg(image),
            180,
        )
        .await?;
        let mapping = output(
            self.command().args(["port", &name, &format!("{port}/tcp")]),
            10,
        )
        .await?;
        let mapping = std::str::from_utf8(&mapping)
            .safe("Invalid local port mapping.")?
            .trim();
        let number = mapping.strip_prefix("127.0.0.1:").ok_or_else(|| {
            crate::error::Failure::infrastructure("Container port is not loopback-only.")
        })?;
        Ok((name, number.parse().safe("Invalid container port.")?))
    }

    /// Ensures an image exists; pull/build failures are infrastructure failures, never skips.
    pub async fn browser_image(&self, image: &str, directory: &Path) -> Result<String> {
        check(
            image.starts_with("localhost/")
                && image
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b)),
            "Browser image must be a local image name.",
        )?;
        // Building the embedded context each time lets Podman reuse unchanged layers
        // without silently reusing a browser worker from an older runner binary.
        let mut source = Vec::new();
        for file in ["Containerfile", "browser.mjs", "entrypoint.sh"] {
            source.extend(
                std::fs::read(directory.join(file)).safe("Cannot read browser build context.")?,
            );
        }
        let image = format!("{image}-{}", crate::files::fingerprint(&source));
        output(
            self.command()
                .args(["build", "--tag", &image])
                .arg(directory),
            300,
        )
        .await?;
        Ok(image)
    }

    /// Records the resolved image identity, validating it before it becomes report metadata.
    pub async fn image_identity(&self, image: &str) -> Result<String> {
        let bytes = output(
            self.command()
                .args(["image", "inspect", "--format", "{{.Id}}", image]),
            10,
        )
        .await?;
        let identity = std::str::from_utf8(&bytes)
            .safe("Invalid container image identity.")?
            .trim();
        let hex = identity.strip_prefix("sha256:").unwrap_or(identity);
        check(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "Unexpected container image identity.",
        )?;
        Ok(format!("{image}@sha256:{hex}"))
    }

    /// Checks the engine's effective log driver without reading log payloads or container environments.
    pub async fn verify_private_logs(&self) -> Result<()> {
        for name in &self.names {
            let driver = output(
                self.command().args([
                    "container",
                    "inspect",
                    "--format",
                    "{{.HostConfig.LogConfig.Type}}",
                    name,
                ]),
                10,
            )
            .await?;
            check(
                std::str::from_utf8(&driver).is_ok_and(|value| value.trim() == "none"),
                "Run container logging must be disabled.",
            )?;
        }
        Ok(())
    }

    /// Removes each owned container even if another removal fails, then the exact owned network.
    pub async fn cleanup_bounded(&mut self, seconds: u64) -> Vec<crate::error::Failure> {
        let mut errors = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
        for (kind, name) in self
            .names
            .iter()
            .map(|name| ("container", name))
            .chain(std::iter::once(("network", &self.network)))
        {
            let seconds = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_secs()
                .clamp(1, 10);
            if self.remove_owned(kind, name, seconds).await.is_err() {
                errors.push(crate::error::Failure {
                    kind: crate::error::Kind::Cleanup,
                    message: "Cannot remove a labeled owned resource; use ownership records for recovery.",
                });
            }
        }
        errors
    }

    /// Confirms existence and matching ownership before removal; an occupied foreign name is never adopted.
    async fn remove_owned(&self, kind: &str, name: &str, seconds: u64) -> Result<()> {
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(seconds),
            self.command()
                .args([kind, "exists", name])
                .kill_on_drop(true)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status(),
        )
        .await
        .safe("Ownership check exceeded its deadline.")?
        .safe("Cannot inspect resource existence.")?;
        if status.code() == Some(1) {
            return Ok(());
        }
        check(status.success(), "Cannot establish resource ownership.")?;
        let template = if kind == "network" {
            "{{index .Labels \"io.permesi.scenario\"}}"
        } else {
            "{{index .Config.Labels \"io.permesi.scenario\"}}"
        };
        let label = output(
            self.command()
                .args([kind, "inspect", "--format", template, name]),
            seconds,
        )
        .await?;
        check(
            std::str::from_utf8(&label).is_ok_and(|value| value.trim() == self.run_id),
            "Refusing to remove a foreign resource.",
        )?;
        let mut command = self.command();
        command.args([kind, "rm"]);
        if kind == "container" {
            command.arg("--force");
        }
        output(command.arg(name), seconds).await?;
        Ok(())
    }
}
