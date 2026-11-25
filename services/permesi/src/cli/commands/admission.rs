use clap::{Arg, ArgMatches, Command};

pub const ARG_ADMISSION_ISSUER: &str = "admission-issuer";
pub const ARG_ADMISSION_AUDIENCE: &str = "admission-audience";

#[derive(Debug, Clone)]
pub struct Options {
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl Options {
    /// Parse admission arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Self> {
        // Helper to filter empty strings which clap might pass through if env vars are set to ""
        let get_non_empty = |id: &str| {
            matches
                .get_one::<String>(id)
                .cloned()
                .filter(|v| !v.trim().is_empty())
        };

        Ok(Self {
            issuer: get_non_empty(ARG_ADMISSION_ISSUER),
            audience: get_non_empty(ARG_ADMISSION_AUDIENCE),
        })
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_ADMISSION_ISSUER)
                .long(ARG_ADMISSION_ISSUER)
                .help("Expected Admission Token issuer (iss)")
                .env("PERMESI_ADMISSION_ISS"),
        )
        .arg(
            Arg::new(ARG_ADMISSION_AUDIENCE)
                .long(ARG_ADMISSION_AUDIENCE)
                .help("Expected Admission Token audience (aud)")
                .env("PERMESI_ADMISSION_AUD"),
        )
        .arg(
            Arg::new("admission-iat-leeway-seconds")
                .long("admission-iat-leeway-seconds")
                .help("Clock skew tolerated on an Admission Token's issue time (iat), never on its expiry")
                .env("PERMESI_ADMISSION_IAT_LEEWAY_SECONDS")
                .default_value("5")
                .value_parser(clap::value_parser!(i64).range(0..=30)),
        )
}
