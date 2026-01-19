use clap::{Arg, ArgMatches, Command};

pub const ARG_ADMISSION_PASERK_URL: &str = "admission-paserk-url";
pub const ARG_ADMISSION_ISSUER: &str = "admission-issuer";
pub const ARG_ADMISSION_AUDIENCE: &str = "admission-audience";
pub const ARG_ADMISSION_PASERK_CA_PATH: &str = "admission-paserk-ca-path";

#[derive(Debug, Clone)]
pub struct Options {
    pub url: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub paserk_ca_path: Option<String>,
}

impl Options {
    /// Parse admission arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Self> {
        let url = matches.get_one::<String>(ARG_ADMISSION_PASERK_URL).cloned();
        let url = match url {
            Some(value) if !value.trim().is_empty() => value,
            _ => anyhow::bail!("missing required argument: --{ARG_ADMISSION_PASERK_URL}"),
        };

        // Helper to filter empty strings which clap might pass through if env vars are set to ""
        let get_non_empty = |id: &str| {
            matches
                .get_one::<String>(id)
                .cloned()
                .filter(|v| !v.trim().is_empty())
        };

        Ok(Self {
            url,
            issuer: get_non_empty(ARG_ADMISSION_ISSUER),
            audience: get_non_empty(ARG_ADMISSION_AUDIENCE),
            paserk_ca_path: get_non_empty(ARG_ADMISSION_PASERK_CA_PATH),
        })
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_ADMISSION_PASERK_URL)
                .long(ARG_ADMISSION_PASERK_URL)
                .help("PASERK keyset URL used to verify Admission Tokens")
                .long_help(
                    "PASERK keyset URL (typically genesis `/paserk.json`) used to verify Admission Tokens.\n\nThe keyset is cached (TTL ~5 minutes) and refreshed on unknown `kid` with a cooldown. Verification\nitself is local and does not call genesis per request.",
                )
                .env("PERMESI_ADMISSION_PASERK_URL"),
        )
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
            Arg::new(ARG_ADMISSION_PASERK_CA_PATH)
                .long(ARG_ADMISSION_PASERK_CA_PATH)
                .help("Path to CA bundle for the PASERK URL (PEM)")
                .env("PERMESI_ADMISSION_PASERK_CA_PATH"),
        )
}
