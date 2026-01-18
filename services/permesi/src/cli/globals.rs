use secrecy::SecretString;
use vault_client::VaultTransport;

#[derive(Clone)]
pub struct GlobalArgs {
    pub vault_url: String,
    pub vault_transport: VaultTransport,
    pub vault_token: SecretString,
    pub vault_db_lease_id: String,
    pub vault_db_lease_duration: u64,
    pub vault_db_username: String,
    pub vault_db_password: SecretString,
}

impl GlobalArgs {
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
