//! Global runtime arguments and state.
//!
//! This module defines the `GlobalArgs` struct, which serves as a container for
//! shared application state derived from command-line arguments and runtime
//! initialization.
//!
//! It primarily holds:
//! - Vault connectivity configuration (`VaultTransport`, `vault_url`, `vault_token`).
//! - Dynamic database credentials (`vault_db_username`, `vault_db_password`, lease info).
//!
//! This struct is passed around to various subsystems (API handlers, background tasks)
//! to provide access to these shared resources.

use secrecy::SecretString;
use vault_client::VaultTransport;

/// Container for global runtime arguments and shared state.
#[derive(Clone)]
pub struct GlobalArgs {
    /// The base URL of the Vault server.
    pub vault_url: String,
    /// The configured transport for communicating with Vault (TCP or Agent).
    pub vault_transport: VaultTransport,
    /// The current Vault authentication token (if using TCP mode).
    pub vault_token: SecretString,
    /// The lease ID for the current database credentials.
    pub vault_db_lease_id: String,
    /// The duration (in seconds) of the current database lease.
    pub vault_db_lease_duration: u64,
    /// The dynamic database username issued by Vault.
    pub vault_db_username: String,
    /// The dynamic database password issued by Vault.
    pub vault_db_password: SecretString,
}

impl GlobalArgs {
    /// Create a new `GlobalArgs` instance with initial Vault configuration.
    ///
    /// The database fields and token are initialized to default/empty values
    /// and should be populated during the startup sequence (e.g., via `database_creds`
    /// or `approle_login`).
    #[must_use]
    pub fn new(vurl: String, transport: VaultTransport) -> Self {
        Self {
            vault_url: vurl,
            vault_transport: transport,
            vault_token: SecretString::default(),
            vault_db_lease_id: String::new(),
            vault_db_lease_duration: 0,
            vault_db_username: String::new(),
            vault_db_password: SecretString::default(),
        }
    }

    /// Update the stored Vault token.
    pub fn set_token(&mut self, token: SecretString) {
        self.vault_token = token;
    }
}

impl std::fmt::Debug for GlobalArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalArgs")
            .field("vault_url", &self.vault_url)
            .field("vault_transport", &self.vault_transport)
            .field("vault_token", &"***")
            .field("vault_db_lease_id", &self.vault_db_lease_id)
            .field("vault_db_lease_duration", &self.vault_db_lease_duration)
            .field("vault_db_username", &self.vault_db_username)
            .field("vault_db_password", &"***")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use vault_client::VaultTarget;

    #[test]
    fn test_global_args() {
        let vurl = "https://localhost:8200".to_string();
        let target = VaultTarget::parse(&vurl).unwrap();
        let transport = VaultTransport::from_target("test", target).unwrap();
        let args = GlobalArgs::new(vurl, transport);
        assert_eq!(args.vault_url, "https://localhost:8200");
        assert_eq!(args.vault_token.expose_secret(), "");
    }
}
