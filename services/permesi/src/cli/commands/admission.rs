use clap::{Arg, ArgMatches, Command};

pub const ARG_ADMISSION_ISSUER: &str = "admission-issuer";
pub const ARG_ADMISSION_AUDIENCE: &str = "admission-audience";

#[derive(Debug, Clone)]
pub struct Options {
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

/// Parse an issuer or audience written into or expected in admission tokens: not empty,
/// not padded with whitespace, and without control characters, which would also forge a
/// line in the startup log that shows the value.
///
/// # Errors
/// Returns a message saying which rule the value breaks; the value is not repeated.
pub fn token_identifier(value: &str) -> Result<String, String> {
    if value.is_empty() || value.trim() != value {
        return Err("must not be empty or padded with whitespace".to_string());
    }
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters".to_string());
    }
    Ok(value.to_string())
}

/// As [`token_identifier`], except that an empty or blank value is kept: it means the
/// setting is not set, as it always has.
fn blank_or_token_identifier(value: &str) -> Result<String, String> {
    // Controls first: a tab is whitespace, and would otherwise pass as blank.
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters".to_string());
    }
    if value.trim().is_empty() {
        Ok(value.to_string())
    } else {
        token_identifier(value)
    }
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

        // Rechecked after clap: the values are compared with every admission token and
        // shown at startup, where a control character would forge a log line.
        let checked = |id: &str| -> anyhow::Result<Option<String>> {
            get_non_empty(id)
                .map(|value| {
                    token_identifier(&value).map_err(|problem| anyhow::anyhow!("--{id} {problem}"))
                })
                .transpose()
        };
        Ok(Self {
            issuer: checked(ARG_ADMISSION_ISSUER)?,
            audience: checked(ARG_ADMISSION_AUDIENCE)?,
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
                .env("PERMESI_ADMISSION_ISS")
                .value_parser(blank_or_token_identifier),
        )
        .arg(
            Arg::new(ARG_ADMISSION_AUDIENCE)
                .long(ARG_ADMISSION_AUDIENCE)
                .help("Expected Admission Token audience (aud)")
                .env("PERMESI_ADMISSION_AUD")
                .value_parser(blank_or_token_identifier),
        )
        .arg(
            Arg::new("admission-iat-leeway-seconds")
                .long("admission-iat-leeway-seconds")
                .help("Clock skew tolerated on an Admission Token's issue time (iat), never on its expiry")
                .env("PERMESI_ADMISSION_IAT_LEEWAY_SECONDS")
                .default_value("5")
                .value_parser(
                    clap::value_parser!(i64).range(0..=admission_token::MAX_IAT_LEEWAY_SECONDS),
                ),
        )
}

#[cfg(test)]
mod tests {
    use super::{ARG_ADMISSION_AUDIENCE, ARG_ADMISSION_ISSUER, Options, with_args};

    fn parse(issuer: &str, audience: &str) -> Result<Options, String> {
        temp_env::with_vars_unset(["PERMESI_ADMISSION_ISS", "PERMESI_ADMISSION_AUD"], || {
            with_args(clap::Command::new("permesi"))
                .try_get_matches_from([
                    "permesi",
                    &format!("--{ARG_ADMISSION_ISSUER}={issuer}"),
                    &format!("--{ARG_ADMISSION_AUDIENCE}={audience}"),
                ])
                .map_err(|error| error.kind().to_string())
                .and_then(|matches| Options::parse(&matches).map_err(|e| format!("{e:#}")))
        })
    }

    /// The expected issuer and audience are compared with every admission token and
    /// shown at startup; a control character in them would forge a log line. An empty
    /// value still means the setting is not set.
    #[test]
    fn admission_identifiers_refuse_control_characters_and_padding() {
        for (issuer, audience) in [
            ("https://genesis.test\nforged", "permesi"),
            ("https://genesis.test", "permesi\u{7}"),
            (" https://genesis.test", "permesi"),
            // Whitespace that is a control character is not read as "not set".
            ("\t", "permesi"),
            ("https://genesis.test", "\n"),
        ] {
            assert!(parse(issuer, audience).is_err(), "{issuer:?} {audience:?}");
        }
        let accepted = parse("https://genesis.test", "permesi");
        assert!(accepted.is_ok_and(|options| {
            options.issuer.as_deref() == Some("https://genesis.test")
                && options.audience.as_deref() == Some("permesi")
        }));
        assert!(
            parse("", " ")
                .is_ok_and(|options| { options.issuer.is_none() && options.audience.is_none() })
        );
    }
}
