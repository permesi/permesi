// Define the global arguments
#[derive(Debug, Clone, Default)]
pub struct GlobalArgs {
    pub vault_url: String,
    pub vault_token: String,
    pub vault_db_lease_id: String,
    pub vault_db_lease_duration: u64,
    pub vault_db_username: String,
    pub vault_db_password: String,
}

impl GlobalArgs {
    #[must_use]
    pub fn new(vurl: String) -> Self {
        Self {
            vault_url: vurl,
            ..Default::default()
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.vault_token = token;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_args() {
        let vurl = "https://localhost:8200".to_string();
        let args = GlobalArgs::new(vurl);
        assert_eq!(args.vault_url, "https://localhost:8200");
        assert_eq!(args.vault_token, "");
    }
}
