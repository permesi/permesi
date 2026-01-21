use clap::{Arg, ArgMatches, Command};

pub const ARG_TLS_PEM_BUNDLE: &str = "tls-pem-bundle";

#[derive(Debug, Clone)]
pub struct Options {
    pub pem_bundle: String,
}

impl Options {
    /// Parse TLS arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing and not in socket mode.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Option<Self>> {
        if matches.contains_id("socket-path") {
            return Ok(None);
        }

        let read_required = |id: &str| -> anyhow::Result<String> {
            matches
                .get_one::<String>(id)
                .cloned()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("missing required argument: --{id}"))
        };

        Ok(Some(Self {
            pem_bundle: read_required(ARG_TLS_PEM_BUNDLE)?,
        }))
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command.arg(
        Arg::new(ARG_TLS_PEM_BUNDLE)
            .long(ARG_TLS_PEM_BUNDLE)
            .help("Path to TLS bundle (Key + Cert + CA) (PEM)")
            .env("PERMESI_TLS_PEM_BUNDLE")
            .required_unless_present("socket-path"),
    )
}
