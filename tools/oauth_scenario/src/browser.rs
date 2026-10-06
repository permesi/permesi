//! Real Chromium with private IPC and a per-container CA trust store.
//!
//! Browser output is a typed control response kept in memory. Screenshots, traces,
//! console messages and network logs are disabled, since they can expose credentials.

use crate::{
    error::{Failure, Result, Safe, check},
    podman::Podman,
};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout},
};

/// Owns the disposable browser, its private stdin/stdout channel, and bounded actions.
pub struct Browser {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    seconds: u64,
}

/// Checks positive navigation with static status diagnostics, never echoing URLs or browser data.
pub fn expect_stage(result: &Value, expected: &str, fallback: &'static str) -> Result<()> {
    check(
        result.get("stage").and_then(Value::as_str) == Some(expected),
        match result.get("status").and_then(Value::as_u64) {
            Some(400) => "Browser authorization returned a protocol error (400).",
            Some(401) => "Browser authorization requires authentication (401).",
            Some(403) => "Browser authorization rejected the request (403).",
            Some(429) => "Browser authorization exceeded the shared rate limit (429).",
            Some(500) => "Browser authorization failed internally (500).",
            Some(503) => "Browser authorization dependency is unavailable (503).",
            _ => fallback,
        },
    )
}

impl Browser {
    /// Uses host networking to reach owned loopback listeners; mounts the public CA, never keys.
    pub async fn start(engine: &mut Podman, image: &str, ca: &Path, seconds: u64) -> Result<Self> {
        let name = format!("ps-{}-browser", engine.run_id);
        engine.names.push(name.clone());
        let mut command = engine.command();
        command
            .args([
                "run",
                "--interactive",
                "--log-driver=none",
                "--name",
                &name,
                "--label",
                &format!("io.permesi.scenario={}", engine.run_id),
                "--network",
                "host",
                "--volume",
            ])
            .arg(format!("{}:/scenario-ca.pem:ro", ca.display()))
            .arg(image);
        let mut child = command
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .safe("Cannot start isolated browser.")?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| Failure::harness("Missing browser input channel."))?;
        let output = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| Failure::harness("Missing browser output channel."))?,
        );
        let mut browser = Self {
            child,
            input,
            output,
            seconds,
        };
        browser.read(45).await?;
        Ok(browser)
    }

    /// Sends a private command; neither request nor response becomes a report diagnostic.
    pub async fn call(&mut self, mut input: Value) -> Result<Value> {
        input
            .as_object_mut()
            .ok_or_else(|| Failure::harness("Invalid browser command."))?
            .insert("seconds".into(), json!(self.seconds));
        let mut bytes = serde_json::to_vec(&input).safe("Cannot encode browser command.")?;
        bytes.push(b'\n');
        tokio::time::timeout(
            Duration::from_secs(self.seconds),
            self.input.write_all(&bytes),
        )
        .await
        .safe("Browser input exceeded its deadline.")?
        .safe("Cannot send private browser command.")?;
        self.read(self.seconds + 5).await.map_err(|error| Failure {
            kind: error.kind,
            message: match input.get("action").and_then(Value::as_str) {
                Some("authorize") => "Browser authorization navigation did not complete.",
                Some("decision") => "Browser consent did not reach the registered callback.",
                Some("login") => "Browser OPAQUE login did not establish a full session.",
                Some("inspect") => "Real console did not display the provisioned fixture.",
                _ => "Browser action failed.",
            },
        })
    }

    /// Reads one bounded private response. Unexpected output fails without echoing it.
    async fn read(&mut self, seconds: u64) -> Result<Value> {
        let mut line = Vec::new();
        let size = tokio::time::timeout(
            Duration::from_secs(seconds),
            (&mut self.output).take(65537).read_until(b'\n', &mut line),
        )
        .await
        .safe("Browser exceeded action deadline.")?
        .safe("Browser control channel failed.")?;
        check(
            size > 0 && size <= 65536 && line.ends_with(b"\n"),
            "Invalid browser response size.",
        )?;
        let response: Value =
            serde_json::from_slice(&line).safe("Invalid private browser response.")?;
        check(
            response.get("ok").and_then(Value::as_bool) == Some(true),
            "Browser action failed.",
        )?;
        response
            .get("result")
            .cloned()
            .ok_or_else(|| Failure::harness("Browser omitted its result."))
    }

    /// Closes the private channel and reaps the Podman child; the owned container is also removed.
    pub async fn stop(&mut self) -> Result<()> {
        let _ = self.input.shutdown().await;
        if self
            .child
            .try_wait()
            .safe("Cannot inspect browser process.")?
            .is_none()
        {
            self.child
                .start_kill()
                .safe("Cannot stop browser process.")?;
        }
        self.child
            .wait()
            .await
            .safe("Cannot reap browser process.")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_diagnostics_distinguish_status_without_disclosing_browser_values() {
        let fallback = "Unexpected navigation stage.";
        assert!(
            expect_stage(
                &json!({"stage":"consent","status":200}),
                "consent",
                fallback
            )
            .is_ok()
        );
        for (status, expected) in [
            (
                429,
                "Browser authorization exceeded the shared rate limit (429).",
            ),
            (500, "Browser authorization failed internally (500)."),
            (
                503,
                "Browser authorization dependency is unavailable (503).",
            ),
        ] {
            let result = json!({"stage":"protocol_error","status":status,"url":"https://issuer.invalid/authorize?secret=do-not-disclose","error":"private database diagnostic"});
            let failure = expect_stage(&result, "callback", fallback).err();
            assert_eq!(failure.map(|error| error.message), Some(expected));
        }
        assert_eq!(
            expect_stage(
                &json!({"stage":"protocol_error","status":"private-value"}),
                "consent",
                fallback
            )
            .err()
            .map(|error| error.message),
            Some(fallback)
        );
    }
}
