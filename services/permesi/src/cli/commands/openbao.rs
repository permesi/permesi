use clap::{Arg, ArgGroup, ArgMatches, Command};

pub const ARG_OPENBAO_URL: &str = "openbao-url";
pub const ARG_OPENBAO_ROLE_ID: &str = "openbao-role-id";
pub const ARG_OPENBAO_SECRET_ID: &str = "openbao-secret-id";
pub const ARG_OPENBAO_WRAPPED_TOKEN: &str = "openbao-wrapped-token";
pub const ARG_OPENBAO_KV_MOUNT: &str = "openbao-kv-mount";
pub const ARG_OPENBAO_KV_PATH: &str = "openbao-kv-path";
pub const ARG_OPENBAO_TRANSIT_MOUNT: &str = "openbao-transit-mount";

#[derive(Clone)]
pub struct Options {
    pub url: String,
    pub role_id: Option<String>,
    pub secret_id: Option<String>,
    pub wrapped_token: Option<String>,
    pub kv_mount: String,
    pub kv_path: String,
    pub transit_mount: String,
}

/// Formats the address without userinfo or query string and the three credentials only as
/// present or absent, so parsed arguments can appear in a diagnostic without leaking.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("url", &openbao_client::loggable_url(&self.url))
            .field("role_id_set", &self.role_id.is_some())
            .field("secret_id_set", &self.secret_id.is_some())
            .field("wrapped_token_set", &self.wrapped_token.is_some())
            .field("kv_mount", &self.kv_mount)
            .field("kv_path", &self.kv_path)
            .field("transit_mount", &self.transit_mount)
            .finish()
    }
}

impl Options {
    /// Parse openbao arguments from matches.
    ///
    /// # Errors
    /// Returns an error if required arguments are missing.
    pub fn parse(matches: &ArgMatches) -> anyhow::Result<Self> {
        let url = matches
            .get_one::<String>(ARG_OPENBAO_URL)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing required argument: --{ARG_OPENBAO_URL}"))?;

        Ok(Self {
            url,
            role_id: matches.get_one::<String>(ARG_OPENBAO_ROLE_ID).cloned(),
            secret_id: matches.get_one::<String>(ARG_OPENBAO_SECRET_ID).cloned(),
            wrapped_token: matches
                .get_one::<String>(ARG_OPENBAO_WRAPPED_TOKEN)
                .cloned(),
            kv_mount: matches
                .get_one::<String>(ARG_OPENBAO_KV_MOUNT)
                .cloned()
                .unwrap_or_else(|| "secret/permesi".to_string()),
            kv_path: matches
                .get_one::<String>(ARG_OPENBAO_KV_PATH)
                .cloned()
                .unwrap_or_else(|| "config".to_string()),
            transit_mount: matches
                .get_one::<String>(ARG_OPENBAO_TRANSIT_MOUNT)
                .cloned()
                .unwrap_or_else(|| "transit/permesi".to_string()),
        })
    }
}

#[must_use]
pub fn with_args(command: Command) -> Command {
    command
        .arg(
            Arg::new(ARG_OPENBAO_URL)
                .long(ARG_OPENBAO_URL)
                .help("OpenBao URL: an origin (http(s)://host[:port]) is completed to the standard AppRole login path; any other URL is used as-is. Also accepts a unix socket path (unix:///path or /path)")
                .env("PERMESI_OPENBAO_URL")
                .hide_env_values(true)
                .required(true),
        )
        .arg(
            Arg::new(ARG_OPENBAO_ROLE_ID)
                .long(ARG_OPENBAO_ROLE_ID)
                .help("OpenBao role id (Required for TCP mode)")
                .env("PERMESI_OPENBAO_ROLE_ID")
                .hide_env_values(true),
        )
        .arg(
            Arg::new(ARG_OPENBAO_SECRET_ID)
                .long(ARG_OPENBAO_SECRET_ID)
                .help("OpenBao secret id (Required for TCP mode unless using wrapped token)")
                .env("PERMESI_OPENBAO_SECRET_ID")
                .hide_env_values(true)
                .conflicts_with(ARG_OPENBAO_WRAPPED_TOKEN),
        )
        .arg(
            Arg::new(ARG_OPENBAO_WRAPPED_TOKEN)
                .long(ARG_OPENBAO_WRAPPED_TOKEN)
                .help("OpenBao wrapped token (TCP mode only)")
                .env("PERMESI_OPENBAO_WRAPPED_TOKEN")
                .hide_env_values(true),
        )
        .arg(
            Arg::new(ARG_OPENBAO_KV_MOUNT)
                .long(ARG_OPENBAO_KV_MOUNT)
                .help("OpenBao KV-v2 mount path for configuration secrets")
                .env("PERMESI_OPENBAO_KV_MOUNT")
                .default_value("secret/permesi"),
        )
        .arg(
            Arg::new(ARG_OPENBAO_KV_PATH)
                .long(ARG_OPENBAO_KV_PATH)
                .help("OpenBao KV-v2 secret path for configuration secrets")
                .env("PERMESI_OPENBAO_KV_PATH")
                .default_value("config"),
        )
        .arg(
            Arg::new(ARG_OPENBAO_TRANSIT_MOUNT)
                .long(ARG_OPENBAO_TRANSIT_MOUNT)
                .help("OpenBao Transit secrets engine mount path")
                .env("PERMESI_OPENBAO_TRANSIT_MOUNT")
                .default_value("transit/permesi"),
        )
        .arg(
            Arg::new("openbao-allow-insecure-http")
                .long("openbao-allow-insecure-http")
                .help("Accept a plain http OpenBao address to a host that is not loopback; tokens and secrets then cross the network in clear text")
                .env("PERMESI_OPENBAO_ALLOW_INSECURE_HTTP")
                .action(clap::ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("openbao-auth")
                .args([ARG_OPENBAO_ROLE_ID, ARG_OPENBAO_SECRET_ID, ARG_OPENBAO_WRAPPED_TOKEN])
                .multiple(true),
        )
}

#[cfg(test)]
mod tests {
    use super::Options;

    #[test]
    fn options_debug_output_names_no_credential() {
        let options = Options {
            url: "https://proxy-user:proxy-password@openbao.internal:8200/?proxy_token=query-token-value"
                .to_string(),
            role_id: Some("role-id-value".to_string()),
            secret_id: Some("secret-id-value".to_string()),
            wrapped_token: Some("wrapped-token-value".to_string()),
            kv_mount: "secret/permesi".to_string(),
            kv_path: "config".to_string(),
            transit_mount: "transit/permesi".to_string(),
        };
        let shown = format!("{options:?} {options:#?}");
        assert!(
            shown.contains("https://openbao.internal:8200/")
                && shown.contains("secret_id_set: true")
        );
        for secret in [
            "proxy-user",
            "proxy-password",
            "query-token-value",
            "proxy_token",
            "role-id-value",
            "secret-id-value",
            "wrapped-token-value",
        ] {
            assert!(!shown.contains(secret), "{secret}");
        }
    }
}
