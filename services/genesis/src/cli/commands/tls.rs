use clap::{Arg, Command};

pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("tls-cert-path")
                .long("tls-cert-path")
                .help("Path to TLS certificate (PEM)")
                .env("GENESIS_TLS_CERT_PATH")
                .required(true),
        )
        .arg(
            Arg::new("tls-key-path")
                .long("tls-key-path")
                .help("Path to TLS private key (PEM)")
                .env("GENESIS_TLS_KEY_PATH")
                .required(true),
        )
        .arg(
            Arg::new("tls-ca-path")
                .long("tls-ca-path")
                .help("Path to TLS CA bundle (PEM)")
                .env("GENESIS_TLS_CA_PATH")
                .required(true),
        )
}
