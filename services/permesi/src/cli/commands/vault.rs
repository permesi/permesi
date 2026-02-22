use clap::{Arg, ArgGroup, ArgMatches, Command};

pub const ARG_VAULT_URL: &str = "vault-url";
pub const ARG_VAULT_ROLE_ID: &str = "vault-role-id";
pub const ARG_VAULT_SECRET_ID: &str = "vault-secret-id";
pub const ARG_VAULT_WRAPPED_TOKEN: &str = "vault-wrapped-token";
pub const ARG_VAULT_KV_MOUNT: &str = "vault-kv-mount";
pub const ARG_VAULT_KV_PATH: &str = "vault-kv-path";
pub const ARG_VAULT_TRANSIT_MOUNT: &str = "vault-transit-mount";

#[derive(Debug, Clone)]
pub struct Options {
    pub url: String,
    pub role_id: Option<String>,
    pub secret_id: Option<String>,
    pub wrapped_token: Option<String>,
    pub kv_mount: String,
    pub kv_path: String,
    pub transit_mount: String,
}

impl Options {
    /// Parse vault arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Self> {
        let url = matches
            .get_one::<String>(ARG_VAULT_URL)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing required argument: --{ARG_VAULT_URL}"))?;

        Ok(Self {
            url,
            role_id: matches.get_one::<String>(ARG_VAULT_ROLE_ID).cloned(),
            secret_id: matches.get_one::<String>(ARG_VAULT_SECRET_ID).cloned(),
            wrapped_token: matches.get_one::<String>(ARG_VAULT_WRAPPED_TOKEN).cloned(),
            kv_mount: matches
                .get_one::<String>(ARG_VAULT_KV_MOUNT)
                .cloned()
                .unwrap_or_else(|| "secret/permesi".to_string()),
            kv_path: matches
                .get_one::<String>(ARG_VAULT_KV_PATH)
                .cloned()
                .unwrap_or_else(|| "config".to_string()),
            transit_mount: matches
                .get_one::<String>(ARG_VAULT_TRANSIT_MOUNT)
                .cloned()
                .unwrap_or_else(|| "transit/permesi".to_string()),
        })
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_VAULT_URL)
                .long(ARG_VAULT_URL)
                .help("Vault base URL (http(s)://host:port) or unix socket path (unix:///path or /path)")
                .env("PERMESI_VAULT_URL")
                .required(true),
        )
        .arg(
            Arg::new(ARG_VAULT_ROLE_ID)
                .long(ARG_VAULT_ROLE_ID)
                .help("Vault role id (Required for TCP mode)")
                .env("PERMESI_VAULT_ROLE_ID"),
        )
        .arg(
            Arg::new(ARG_VAULT_SECRET_ID)
                .long(ARG_VAULT_SECRET_ID)
                .help("Vault secret id (Required for TCP mode unless using wrapped token)")
                .env("PERMESI_VAULT_SECRET_ID")
                .conflicts_with(ARG_VAULT_WRAPPED_TOKEN),
        )
        .arg(
            Arg::new(ARG_VAULT_WRAPPED_TOKEN)
                .long(ARG_VAULT_WRAPPED_TOKEN)
                .help("Vault wrapped token (TCP mode only)")
                .env("PERMESI_VAULT_WRAPPED_TOKEN"),
        )
        .arg(
            Arg::new(ARG_VAULT_KV_MOUNT)
                .long(ARG_VAULT_KV_MOUNT)
                .help("Vault KV-v2 mount path for configuration secrets")
                .env("PERMESI_VAULT_KV_MOUNT")
                .default_value("secret/permesi"),
        )
        .arg(
            Arg::new(ARG_VAULT_KV_PATH)
                .long(ARG_VAULT_KV_PATH)
                .help("Vault KV-v2 secret path for configuration secrets")
                .env("PERMESI_VAULT_KV_PATH")
                .default_value("config"),
        )
        .arg(
            Arg::new(ARG_VAULT_TRANSIT_MOUNT)
                .long(ARG_VAULT_TRANSIT_MOUNT)
                .help("Vault Transit secrets engine mount path")
                .env("PERMESI_VAULT_TRANSIT_MOUNT")
                .default_value("transit/permesi"),
        )
        .group(
            ArgGroup::new("vault-auth")
                .args([ARG_VAULT_ROLE_ID, ARG_VAULT_SECRET_ID, ARG_VAULT_WRAPPED_TOKEN])
                .multiple(true),
        )
}
