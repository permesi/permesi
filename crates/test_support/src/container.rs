//! Loopback fixture publication and container start with bounded port-race retries.
//!
//! Explicit IPv4 bindings keep test services private and make their allocated ports
//! discoverable across Podman versions, including 4.x empty publish-all metadata.
//!
//! Test containers publish their service port on a random host port. Rootless Podman
//! picks that port itself (`rootlessport`), and when many containers start in
//! parallel another process can take the chosen port between the pick and the bind,
//! so the start fails with `bind: address already in use`. Nothing is wrong with the
//! container or the test, so that one failure is retried: each attempt gets a fresh
//! container name (a failed start can leave the name taken) and the half-created
//! container is removed on a best-effort basis. Every other start error fails at once.

use anyhow::{Error, Result};
use std::{
    future::Future,
    process::{Command, Stdio},
};
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt,
    bollard::models::{HostConfig, PortBinding},
    runners::AsyncRunner,
};
use tokio::time::{Duration, sleep};

use crate::unique_name;

/// Attempts before a host-port race is reported as a failure.
const PORT_RACE_ATTEMPTS: u32 = 5;

/// Publishes an automatically allocated IPv4 loopback port explicitly.
/// Podman 4.x reports an empty `HostIp` for publish-all mappings, which testcontainers
/// cannot resolve. Explicit binding works on both 4.x and 5.x and keeps fixtures off LANs.
pub(crate) fn with_loopback_port(
    image: ContainerRequest<GenericImage>,
    port: u16,
) -> ContainerRequest<GenericImage> {
    image.with_host_config_modifier(move |config| bind_loopback(config, port))
}

/// Owns the fixture's sole published port; the engine selects its ephemeral host number.
fn bind_loopback(config: &mut HostConfig, port: u16) {
    config.publish_all_ports = Some(false);
    config.port_bindings = Some(std::collections::HashMap::from([(
        format!("{port}/tcp"),
        Some(vec![PortBinding {
            host_ip: Some("127.0.0.1".into()),
            host_port: Some(String::new()),
        }]),
    )]));
}

/// Start the container `build` describes for a given name, retrying only when the
/// runtime lost a race for its random host port. Returns the running container and the
/// name of the attempt that succeeded.
///
/// # Errors
/// Returns the start error when it is not a host-port race, or when the race persists
/// for `PORT_RACE_ATTEMPTS` attempts.
pub(crate) async fn start_with_port_retry<F>(
    what: &str,
    prefix: &str,
    build: F,
) -> Result<(ContainerAsync<GenericImage>, String)>
where
    F: Fn(&str) -> ContainerRequest<GenericImage>,
{
    retry_port_race(what, prefix, PORT_RACE_ATTEMPTS, |name: String| {
        build(&name).start()
    })
    .await
}

/// The retry loop behind `start_with_port_retry`, over any start function: each attempt
/// gets a fresh name, a host-port race is retried up to `attempts` times (removing the
/// half-created container), and any other error is returned at once.
async fn retry_port_race<T, E, S, Fut>(
    what: &str,
    prefix: &str,
    attempts: u32,
    mut start: S,
) -> Result<(T, String)>
where
    S: FnMut(String) -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut attempt = 1;
    loop {
        let name = unique_name(prefix);
        match start(name.clone()).await {
            Ok(started) => return Ok((started, name)),
            Err(err) => {
                let err = Error::new(err);
                // A failed start can leave the created container behind, whatever failed.
                remove_leftover(&name);
                if attempt >= attempts || !is_port_race(&err) {
                    return Err(err.context(format!("Failed to start {what} container")));
                }
                eprintln!(
                    "{what} container lost a race for its host port ({attempt}/{attempts}); retrying: {err:#}"
                );
                sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                attempt += 1;
            }
        }
    }
}

/// Whether a start error is the host-port race: the runtime chose a host port that
/// something else bound first (Podman's `rootlessport ... bind: address already in
/// use`, Docker's `port is already allocated`). Checks the whole error chain.
pub(crate) fn is_port_race(err: &Error) -> bool {
    let message = format!("{err:#}");
    message.contains("bind: address already in use")
        || message.contains("port is already allocated")
}

/// Remove a container a failed start may have left behind, with whichever runtime
/// knows it; failures are ignored because every attempt uses a new name anyway.
fn remove_leftover(name: &str) {
    for runtime in ["podman", "docker"] {
        let removed = Command::new(runtime)
            .args(["rm", "--force", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if removed.is_ok_and(|status| status.success()) {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::{fmt, sync::Mutex};

    /// The engine's allocated port stays discoverable without wildcard/empty `HostIp` metadata.
    #[test]
    fn loopback_port_is_resolvable_and_never_requests_publish_all() -> Result<()> {
        for network in ["bridge", "private-test-network"] {
            let postgres = crate::postgres::fixture_request(
                &crate::postgres::PostgresConfig::new(),
                "postgres-test",
                network,
            );
            let vault = crate::vault::fixture_request(
                &crate::vault::VaultConfig::new(),
                "vault-test",
                network,
            );
            assert_loopback(&postgres, 5432)?;
            assert_loopback(&vault, 8200)?;
        }
        Ok(())
    }

    fn assert_loopback(image: &ContainerRequest<GenericImage>, port: u16) -> Result<()> {
        use testcontainers::core::{IntoContainerPort, ports::Ports};
        let mut config = HostConfig::default();
        image
            .host_config_modifier()
            .ok_or_else(|| anyhow!("missing port modifier"))?(&mut config);
        assert_eq!(config.publish_all_ports, Some(false));
        let ports = config
            .port_bindings
            .as_mut()
            .ok_or_else(|| anyhow!("missing bindings"))?;
        let values = ports
            .get_mut(&format!("{port}/tcp"))
            .and_then(Option::as_mut)
            .ok_or_else(|| anyhow!("missing TCP binding"))?;
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(values[0].host_port.as_deref(), Some(""));
        values[0].host_port = Some("49152".into()); // emulate the runtime's random allocation
        let resolved = Ports::try_from(ports.clone())?;
        assert_eq!(resolved.map_to_host_port_ipv4(port.tcp()), Some(49152));
        assert_eq!(resolved.map_to_host_port_ipv6(port.tcp()), None);
        Ok(())
    }

    #[derive(Debug)]
    struct StartError(&'static str);

    impl fmt::Display for StartError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for StartError {}

    const RACE: &str = "failed to start a container: rootlessport listen tcp 0.0.0.0:36991: bind: address already in use";

    #[tokio::test]
    async fn retry_port_race_retries_until_the_start_succeeds() {
        let names = Mutex::new(Vec::new());
        let result = retry_port_race("Test", "race", 5, |name: String| {
            let mut seen = names.lock().unwrap();
            seen.push(name);
            let attempt = seen.len();
            async move {
                if attempt < 3 {
                    Err(StartError(RACE))
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;
        let (attempt, name) = result.unwrap();
        let seen = names.lock().unwrap();
        assert_eq!(attempt, 3);
        assert_eq!(seen.len(), 3);
        assert_eq!(&name, &seen[2]);
        assert!(
            seen[0] != seen[1] && seen[1] != seen[2],
            "each attempt gets a fresh name"
        );
    }

    #[tokio::test]
    async fn retry_port_race_fails_at_once_on_other_errors() {
        let calls = Mutex::new(0);
        let result = retry_port_race("Test", "other", 5, |_name: String| {
            *calls.lock().unwrap() += 1;
            async { Err::<(), _>(StartError("image not found")) }
        })
        .await;
        let err = result.unwrap_err();
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(format!("{err:#}").contains("Failed to start Test container"));
    }

    #[tokio::test]
    async fn retry_port_race_gives_up_after_the_attempt_limit() {
        let calls = Mutex::new(0);
        let result = retry_port_race("Test", "persistent", 3, |_name: String| {
            *calls.lock().unwrap() += 1;
            async { Err::<(), _>(StartError(RACE)) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(*calls.lock().unwrap(), 3);
    }

    #[test]
    fn is_port_race_detects_rootlessport_bind_error() {
        let err = anyhow!(
            "failed to start a container: Docker responded with status code 500: rootlessport listen tcp 0.0.0.0:36991: bind: address already in use"
        );
        assert!(is_port_race(&err));
    }

    #[test]
    fn is_port_race_checks_the_whole_error_chain() {
        let err = anyhow!("bind: address already in use").context("failed to start a container");
        assert!(is_port_race(&err));
    }

    #[test]
    fn is_port_race_detects_docker_port_allocation_error() {
        let err = anyhow!(
            "failed to start a container: driver failed programming external connectivity: Bind for 0.0.0.0:32768 failed: port is already allocated"
        );
        assert!(is_port_race(&err));
    }

    #[test]
    fn is_port_race_ignores_an_address_in_use_that_is_not_the_host_port() {
        let err =
            anyhow!("failed to start a container: vault: listen tcp :8200: address already in use");
        assert!(!is_port_race(&err));
    }

    #[test]
    fn is_port_race_ignores_other_start_errors() {
        let err = anyhow!("failed to start a container: image not found: hashicorp/vault:1.17.3");
        assert!(!is_port_race(&err));
    }
}
