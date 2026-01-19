use clap::{Arg, ArgMatches, Command};

pub const ARG_TLS_CERT_PATH: &str = "tls-cert-path";
pub const ARG_TLS_KEY_PATH: &str = "tls-key-path";
pub const ARG_TLS_CA_PATH: &str = "tls-ca-path";

#[derive(Debug, Clone)]
pub struct Options {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

impl Options {
    /// Parse TLS arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Self> {
        let read_required = |id: &str| -> anyhow::Result<String> {
            matches
                .get_one::<String>(id)
                .cloned()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("missing required argument: --{id}"))
        };

        Ok(Self {
            cert_path: read_required(ARG_TLS_CERT_PATH)?,
            key_path: read_required(ARG_TLS_KEY_PATH)?,
            ca_path: read_required(ARG_TLS_CA_PATH)?,
        })
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_TLS_CERT_PATH)
                .long(ARG_TLS_CERT_PATH)
                .help("Path to TLS certificate (PEM)")
                .env("PERMESI_TLS_CERT_PATH")
                .required(true),
        )
        .arg(
            Arg::new(ARG_TLS_KEY_PATH)
                .long(ARG_TLS_KEY_PATH)
                .help("Path to TLS private key (PEM)")
                .env("PERMESI_TLS_KEY_PATH")
                .required(true),
        )
        .arg(
            Arg::new(ARG_TLS_CA_PATH)
                .long(ARG_TLS_CA_PATH)
                .help("Path to TLS CA bundle (PEM)")
                .env("PERMESI_TLS_CA_PATH")
                .required(true),
        )
}
