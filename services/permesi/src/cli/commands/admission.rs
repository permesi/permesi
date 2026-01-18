use clap::{Arg, Command};

pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("admission-paserk-url")
                .long("admission-paserk-url")
                .help("PASERK keyset URL used to verify Admission Tokens")
                .long_help(
                    "PASERK keyset URL (typically genesis `/paserk.json`) used to verify Admission Tokens.\n\nThe keyset is cached (TTL ~5 minutes) and refreshed on unknown `kid` with a cooldown. Verification\nitself is local and does not call genesis per request.",
                )
                .env("PERMESI_ADMISSION_PASERK_URL"),
        )
        .arg(
            Arg::new("admission-issuer")
                .long("admission-issuer")
                .help("Expected Admission Token issuer (iss)")
                .env("PERMESI_ADMISSION_ISS"),
        )
        .arg(
            Arg::new("admission-audience")
                .long("admission-audience")
                .help("Expected Admission Token audience (aud)")
                .env("PERMESI_ADMISSION_AUD"),
        )
}
