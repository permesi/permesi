use clap::{Arg, ArgGroup, Command};

pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("vault-url")
                .long("vault-url")
                .help("Vault base URL (http(s)://host:port) or unix socket path (unix:///path or /path)")
                .env("PERMESI_VAULT_URL")
                .required(true),
        )
        .arg(
            Arg::new("vault-role-id")
                .long("vault-role-id")
                .help("Vault role id (Required for TCP mode)")
                .env("PERMESI_VAULT_ROLE_ID"),
        )
        .arg(
            Arg::new("vault-secret-id")
                .long("vault-secret-id")
                .help("Vault secret id (Required for TCP mode unless using wrapped token)")
                .env("PERMESI_VAULT_SECRET_ID")
                .conflicts_with("vault-wrapped-token"),
        )
        .arg(
            Arg::new("vault-wrapped-token")
                .long("vault-wrapped-token")
                .help("Vault wrapped token (TCP mode only)")
                .env("PERMESI_VAULT_WRAPPED_TOKEN"),
        )
        .group(
            ArgGroup::new("vault-auth")
                .args(["vault-role-id", "vault-secret-id", "vault-wrapped-token"])
                .multiple(true),
        )
}
