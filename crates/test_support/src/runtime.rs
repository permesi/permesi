use anyhow::{Result, bail};
use std::{
    env,
    fmt::Write as _,
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    thread,
    time::Duration,
};

const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Ensure a container runtime socket is available for testcontainers.
///
/// testcontainers talks to the Docker API; we prefer Podman and point
/// `DOCKER_HOST` at the Podman socket when available.
///
/// # Errors
/// Returns an error if no Docker/Podman socket can be found or configured.
pub fn ensure_container_runtime() -> Result<()> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    match INIT.get_or_init(init_container_runtime) {
        Ok(()) => Ok(()),
        Err(message) => bail!("{message}"),
    }
}

fn init_container_runtime() -> Result<(), String> {
    if let Ok(docker_host) = env::var("DOCKER_HOST") {
        return validate_docker_host(&docker_host);
    }

    let docker_socket = Path::new("/var/run/docker.sock");
    if wait_for_socket(docker_socket, SOCKET_WAIT_TIMEOUT) {
        return Ok(());
    }
    let docker_error = if docker_socket.exists() {
        let mut message = format!(
            "Docker socket found at `{}`, but it is not accepting connections.",
            docker_socket.display()
        );
        if let Some(err) = warm_up_docker() {
            let _ = write!(message, " docker info error: {err}");
        }
        message.push_str(" Start the Docker daemon or set `DOCKER_HOST`.");
        Some(message)
    } else {
        None
    };

    if let Some(path) = find_podman_socket() {
        if wait_for_socket(&path, SOCKET_WAIT_TIMEOUT) {
            set_docker_host(&path);
            return Ok(());
        }
        let mut message = format!(
            "Podman socket found at `{}`, but it is not accepting connections.",
            path.display()
        );
        if let Some(err) = warm_up_podman() {
            let _ = write!(message, " podman info error: {err}");
            if err.contains("permission denied") && err.contains("libpod") {
                message.push_str(
                    " Check ownership/permissions for the libpod runtime dir (for example: /run/user/<uid>/libpod).",
                );
            }
        }
        message.push_str(" Start `podman.socket` or run `podman system service`.");
        return Err(message);
    }

    match start_podman_service() {
        Ok(Some(path)) => {
            if wait_for_socket(&path, SOCKET_WAIT_TIMEOUT) {
                set_docker_host(&path);
                return Ok(());
            }
            return Err("podman system service did not become ready".to_string());
        }
        Ok(None) => {}
        Err(err) => {
            return Err(format!(
                "Podman service failed to start: {err}. Start `podman.socket`, run `podman system service`, or set `DOCKER_HOST`."
            ));
        }
    }

    let mut message = "No container runtime socket found or reachable. Start `podman.socket`, run `podman system service`, or set `DOCKER_HOST` (for example: unix:///run/user/<uid>/podman/podman.sock).".to_string();
    if let Some(docker_error) = docker_error {
        message.push(' ');
        message.push_str(&docker_error);
    }
    if env::var("GITHUB_ACTIONS").is_ok() {
        message.push_str(
            " GitHub Actions: ensure Docker is installed and running (container jobs must mount `/var/run/docker.sock`).",
        );
    }
    Err(message)
}

fn find_podman_socket() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(runtime_dir).join("podman/podman.sock"));
    }
    if let Some(uid) = read_uid() {
        candidates.push(PathBuf::from(format!("/run/user/{uid}/podman/podman.sock")));
    }
    candidates.push(PathBuf::from("/var/run/podman/podman.sock"));
    candidates.push(PathBuf::from("/run/podman/podman.sock"));

    candidates.into_iter().find(|path| path.exists())
}

fn validate_docker_host(docker_host: &str) -> Result<(), String> {
    if let Some(path) = docker_host.strip_prefix("unix://") {
        let path = Path::new(path);
        if wait_for_socket(path, SOCKET_WAIT_TIMEOUT) {
            return Ok(());
        }
        return Err(format!(
            "`DOCKER_HOST` points to `{docker_host}`, but the socket is not accepting connections. Start `podman.socket` or the Docker daemon."
        ));
    }

    if docker_host.starts_with('/') {
        let path = Path::new(docker_host);
        if wait_for_socket(path, SOCKET_WAIT_TIMEOUT) {
            return Ok(());
        }
        return Err(format!(
            "`DOCKER_HOST` points to `{docker_host}`, but the socket is not accepting connections. Start `podman.socket` or the Docker daemon."
        ));
    }

    Ok(())
}

fn socket_connectable(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    UnixStream::connect(path).is_ok()
}

fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if socket_connectable(path) {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

fn warm_up_podman() -> Option<String> {
    let output = match Command::new("podman").arg("info").output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => return Some(err.to_string()),
    };

    if output.status.success() {
        return None;
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        Some(format!("podman info exited with {}", output.status))
    } else {
        Some(stderr)
    }
}

fn warm_up_docker() -> Option<String> {
    let output = match Command::new("docker").arg("info").output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => return Some(err.to_string()),
    };

    if output.status.success() {
        return None;
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        Some(format!("docker info exited with {}", output.status))
    } else {
        Some(stderr)
    }
}

fn set_docker_host(path: &Path) {
    let docker_host = format!("unix://{}", path.display());
    // SAFETY: We set this once during test setup before starting containers.
    unsafe {
        env::set_var("DOCKER_HOST", docker_host);
    }
}

fn start_podman_service() -> Result<Option<PathBuf>, String> {
    let socket_path = env::temp_dir().join(format!("permesi-podman-{}.sock", std::process::id()));
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    let socket_arg = format!("unix://{}", socket_path.display());
    let mut child = match Command::new("podman")
        .args(["system", "service", "--time=300", &socket_arg])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!("Failed to start podman system service: {err}"));
        }
    };

    for _ in 0..20 {
        if socket_connectable(&socket_path) {
            thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(Some(socket_path));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut message = format!("podman system service exited with {status}");
                if let Some(ref mut stderr) = child.stderr
                    && let Ok(output) = read_child_stderr(stderr)
                    && !output.is_empty()
                {
                    let _ = write!(message, ": {output}");
                }
                return Err(message);
            }
            Ok(None) => {}
            Err(err) => {
                return Err(format!(
                    "Failed to check podman system service status: {err}"
                ));
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    let _ = child.kill();
    let _ = child.wait();
    Err("podman system service did not become ready".to_string())
}

fn read_child_stderr(stderr: &mut std::process::ChildStderr) -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut output = String::new();
    let _ = stderr.read_to_string(&mut output)?;
    Ok(output.trim().to_string())
}

fn read_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid = rest.split_whitespace().next()?;
            return uid.parse::<u32>().ok();
        }
    }
    None
}
