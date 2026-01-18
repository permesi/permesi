use clap::{Arg, Command};

pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("tls-cert-path")
                .long("tls-cert-path")
                .help("Path to TLS certificate (PEM)")
                .env("PERMESI_TLS_CERT_PATH")
                .required(true),
        )
        .arg(
            Arg::new("tls-key-path")
                .long("tls-key-path")
                .help("Path to TLS private key (PEM)")
                .env("PERMESI_TLS_KEY_PATH")
                .required(true),
        )
        .arg(
            Arg::new("tls-ca-path")
                .long("tls-ca-path")
                .help("Path to TLS CA bundle (PEM)")
                .env("PERMESI_TLS_CA_PATH")
                .required(true),
        )
        .arg(
            Arg::new("admission-paserk-ca-path")
                .long("admission-paserk-ca-path")
                .help("Path to CA bundle for the PASERK URL (PEM)")
                .env("PERMESI_ADMISSION_PASERK_CA_PATH"),
        )
}
