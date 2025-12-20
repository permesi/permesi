use secrecy::SecretString;

#[derive(Debug, Clone)]
pub struct GlobalArgs {
    pub vault_url: String,
    pub vault_token: SecretString,
    pub vault_db_lease_id: String,
    pub vault_db_lease_duration: u64,
    pub vault_db_username: String,
    pub vault_db_password: SecretString,
}

impl GlobalArgs {
    #[must_use]
    pub fn new(vurl: String) -> Self {
        Self {
            vault_url: vurl,
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

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_global_args() {
        let vurl = "https://localhost:8200".to_string();
        let args = GlobalArgs::new(vurl);
        assert_eq!(args.vault_url, "https://localhost:8200");
        assert_eq!(args.vault_token.expose_secret(), "");
    }
}
