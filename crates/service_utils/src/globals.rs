//! Global runtime arguments and state.
//!
//! This module defines the `GlobalArgs` struct, which serves as a container for
//! shared application state derived from command-line arguments and runtime
//! initialization.
//!
//! It primarily holds:
//! - OpenBao connectivity configuration (`OpenBaoTransport`, `openbao_url`, `openbao_token`).
//! - Dynamic database credentials (`openbao_db_username`, `openbao_db_password`, lease info).
//!
//! This struct is passed around to various subsystems (API handlers, background tasks)
//! to provide access to these shared resources.

use openbao_client::OpenBaoTransport;
use secrecy::SecretString;

/// Container for global runtime arguments and shared state.
#[derive(Clone)]
pub struct GlobalArgs {
    /// The base URL of the OpenBao server.
    pub openbao_url: String,
    /// The configured transport for communicating with OpenBao (TCP or Agent).
    pub openbao_transport: OpenBaoTransport,
    /// The current OpenBao authentication token (if using TCP mode).
    pub openbao_token: SecretString,
    /// The OpenBao Transit secrets engine mount path.
    pub openbao_transit_mount: String,
    /// The lease ID for the current database credentials.
    pub openbao_db_lease_id: String,
    /// The duration (in seconds) of the current database lease.
    pub openbao_db_lease_duration: u64,
    /// The dynamic database username issued by OpenBao.
    pub openbao_db_username: String,
    /// The dynamic database password issued by OpenBao.
    pub openbao_db_password: SecretString,
}

impl GlobalArgs {
    /// Create a new `GlobalArgs` instance with initial OpenBao configuration.
    ///
    /// The database fields and token are initialized to default/empty values
    /// and should be populated during the startup sequence (e.g., via `database_creds`
    /// or `approle_login`).
    #[must_use]
    pub fn new(vurl: String, transport: OpenBaoTransport) -> Self {
        Self {
            openbao_url: vurl,
            openbao_transport: transport,
            openbao_token: SecretString::default(),
            openbao_transit_mount: String::new(),
            openbao_db_lease_id: String::new(),
            openbao_db_lease_duration: 0,
            openbao_db_username: String::new(),
            openbao_db_password: SecretString::default(),
        }
    }

    /// Update the stored OpenBao token.
    pub fn set_token(&mut self, token: SecretString) {
        self.openbao_token = token;
    }
}

impl std::fmt::Debug for GlobalArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalArgs")
            .field("openbao_url", &self.openbao_url)
            .field("openbao_transport", &self.openbao_transport)
            .field("openbao_token", &"***")
            .field("openbao_transit_mount", &self.openbao_transit_mount)
            .field("openbao_db_lease_id", &self.openbao_db_lease_id)
            .field("openbao_db_lease_duration", &self.openbao_db_lease_duration)
            .field("openbao_db_username", &self.openbao_db_username)
            .field("openbao_db_password", &"***")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use openbao_client::OpenBaoTarget;
    use secrecy::ExposeSecret;

    #[test]
    fn test_global_args() {
        let vurl = "https://localhost:8200".to_string();
        let target = OpenBaoTarget::parse(&vurl).unwrap();
        let transport = OpenBaoTransport::from_target("test", target).unwrap();
        let args = GlobalArgs::new(vurl, transport);
        assert_eq!(args.openbao_url, "https://localhost:8200");
        assert_eq!(args.openbao_token.expose_secret(), "");
    }
}
