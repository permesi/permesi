use clap::{Arg, ArgGroup, Command};

pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("openbao-url")
                .long("openbao-url")
                .help("OpenBao base URL (http(s)://host:port) or unix socket path (unix:///path or /path)")
                .env("GENESIS_OPENBAO_URL")
                .required(true),
        )
        .arg(
            Arg::new("openbao-role-id")
                .long("openbao-role-id")
                .help("OpenBao role id (Required for TCP mode)")
                .env("GENESIS_OPENBAO_ROLE_ID"),
        )
        .arg(
            Arg::new("openbao-secret-id")
                .long("openbao-secret-id")
                .help("OpenBao secret id (Required for TCP mode unless using wrapped token)")
                .env("GENESIS_OPENBAO_SECRET_ID")
                .conflicts_with("openbao-wrapped-token"),
        )
        .arg(
            Arg::new("openbao-wrapped-token")
                .long("openbao-wrapped-token")
                .help("OpenBao wrapped token (TCP mode only)")
                .env("GENESIS_OPENBAO_WRAPPED_TOKEN")
        )
        .arg(
            Arg::new("openbao-transit-mount")
                .long("openbao-transit-mount")
                .help("OpenBao Transit secrets engine mount path")
                .env("GENESIS_TRANSIT_MOUNT")
                .default_value("transit/genesis"),
        )
        .group(
            ArgGroup::new("openbao-auth")
                .args(["openbao-role-id", "openbao-secret-id", "openbao-wrapped-token"])
                .multiple(true),
        )
}
