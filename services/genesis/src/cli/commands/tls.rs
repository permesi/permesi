use clap::{Arg, Command};

pub fn with_args(command: Command) -> Command {
    command.arg(
        Arg::new("tls-pem-bundle")
            .long("tls-pem-bundle")
            .help("Path to TLS bundle (Key + Cert + CA) (PEM)")
            .env("GENESIS_TLS_PEM_BUNDLE")
            .required_unless_present("socket-path"),
    )
}
