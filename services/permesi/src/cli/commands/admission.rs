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
}
