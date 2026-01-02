//! Build-time configuration for API and token endpoints. Values are compiled
//! into the wasm bundle to keep runtime logic simple, so changes require a
//! rebuild. Configuration values are public; do not store secrets here.

/// Frontend configuration derived from build-time environment variables.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_base_url: String,
    pub token_base_url: String,
    pub client_id: String,
    pub opaque_server_id: String,
}

impl AppConfig {
    /// Loads config from build-time environment variables.
    pub fn load() -> Self {
        let api_base_url = option_env!("PERMESI_API_BASE_URL")
            .or(option_env!("PERMESI_API_HOST"))
            .unwrap_or("");
        let token_base_url = option_env!("PERMESI_TOKEN_BASE_URL")
            .or(option_env!("PERMESI_TOKEN_HOST"))
            .or(option_env!("PERMESI_API_TOKEN_HOST"))
            .unwrap_or("");
        let client_id = option_env!("PERMESI_CLIENT_ID").unwrap_or("");
        let opaque_server_id = option_env!("PERMESI_OPAQUE_SERVER_ID").unwrap_or("api.permesi.dev");

        Self {
            api_base_url: api_base_url.to_string(),
            token_base_url: token_base_url.to_string(),
            client_id: client_id.to_string(),
            opaque_server_id: opaque_server_id.to_string(),
        }
    }
}
