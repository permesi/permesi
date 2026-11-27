use clap::{Arg, ArgGroup, Command};

pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("openbao-url")
                .long("openbao-url")
                .help("OpenBao base URL (http(s)://host:port) or unix socket path (unix:///path or /path)")
                .env("GENESIS_OPENBAO_URL")
                .hide_env_values(true)
                .required(true),
        )
        .arg(
            Arg::new("openbao-role-id")
                .long("openbao-role-id")
                .help("OpenBao role id (Required for TCP mode)")
                .env("GENESIS_OPENBAO_ROLE_ID")
                .hide_env_values(true),
        )
        .arg(
            Arg::new("openbao-secret-id")
                .long("openbao-secret-id")
                .help("OpenBao secret id (Required for TCP mode unless using wrapped token)")
                .env("GENESIS_OPENBAO_SECRET_ID")
                .hide_env_values(true)
                .conflicts_with("openbao-wrapped-token"),
        )
        .arg(
            Arg::new("openbao-wrapped-token")
                .long("openbao-wrapped-token")
                .help("OpenBao wrapped token (TCP mode only)")
                .env("GENESIS_OPENBAO_WRAPPED_TOKEN")
                .hide_env_values(true)
        )
        .arg(
            Arg::new("openbao-transit-mount")
                .long("openbao-transit-mount")
                .help("OpenBao Transit secrets engine mount path")
                .env("GENESIS_TRANSIT_MOUNT")
                .default_value("transit/genesis"),
        )
        .arg(
            Arg::new("openbao-allow-insecure-http")
                .long("openbao-allow-insecure-http")
                .help("Accept a plain http OpenBao address to a host that is not loopback; tokens and secrets then cross the network in clear text")
                .env("GENESIS_OPENBAO_ALLOW_INSECURE_HTTP")
                .action(clap::ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("openbao-auth")
                .args(["openbao-role-id", "openbao-secret-id", "openbao-wrapped-token"])
                .multiple(true),
        )
}
