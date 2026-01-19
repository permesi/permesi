#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use vault_client::{VaultTarget, VaultTransport};

#[test]
fn test_agent_socket_missing() {
    let dir = temp_env::with_vars(Vec::<(&str, Option<&str>)>::new(), std::env::temp_dir);
    let socket_path = dir.join("missing-socket.sock");

    // Ensure it doesn't exist
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let target = VaultTarget::parse(&format!("unix://{}", socket_path.display())).unwrap();
    let result = VaultTransport::from_target("test-suite", target);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        err.to_string()
            .contains("Vault Agent socket not accessible")
    );
    assert!(err.to_string().contains("No such file or directory")); // Standard IO error message
}

#[test]
fn test_agent_socket_bad_permissions() {
    // This test relies on unix permissions.
    let dir = temp_env::with_vars(Vec::<(&str, Option<&str>)>::new(), std::env::temp_dir);
    let socket_path = dir.join(format!("bad-perm-{}.sock", uuid::Uuid::new_v4()));

    // Create a dummy file acting as socket
    {
        use std::fs::File;
        File::create(&socket_path).expect("failed to create dummy socket file");
    }

    // Set permissions to 0000 (no access)
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o000))
        .expect("failed to set permissions");

    // Ensure cleanup
    let _guard = SocketGuard {
        path: socket_path.clone(),
    };

    // Note: If running as root (e.g. inside some containers), 0000 might still be accessible.
    // We check if we are not root.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Skipping permission test because running as root");
        return;
    }

    // Try validation - Wait, fs::metadata usually works on 0000 files if the directory is accessible.
    // However, if we can't stat it? No, we can stat it if we own it.
    // The check `check_socket_accessibility` uses `std::fs::metadata`.
    // Metadata usually succeeds even if mode is 0000, as long as we have access to the parent dir.

    // So the check inside `from_target` might actually PASS for 0000 file if we own it.
    // The real failure happens at `request_json` (connect).

    // Let's verify `from_target` behavior first.
    let target = VaultTarget::parse(&format!("unix://{}", socket_path.display())).unwrap();
    let result = VaultTransport::from_target("test-suite", target);

    // If metadata succeeds, this passes.
    if let Ok(transport) = result {
        // If it passed, we should verify that `request_json` gives the improved error.
        // But `request_json` requires a running server to connect to.
        // Here we have a file, but not a listener. So connect will fail.

        // We need an async runtime for this part
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let res = transport
                .request_json(http::Method::GET, "/v1/test", None, None)
                .await;
            assert!(res.is_err());
            let err = res.err().unwrap();
            // Check for our improved error message
            assert!(err.to_string().contains("Check permissions for socket"));
            assert!(err.to_string().contains(socket_path.to_str().unwrap()));
        });
    }
}

struct SocketGuard {
    path: std::path::PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        // Try to restore permissions so we can delete it
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_file(&self.path);
    }
}
