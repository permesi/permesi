//! Build-time configuration for API and token endpoints with an optional
//! runtime override. The runtime config is read from `window.PERMESI_CONFIG`
//! (if present) so static deployments can change endpoints without rebuilding.
//! Configuration values are public; do not store secrets here.

/// Frontend configuration derived from build-time environment variables.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_base_url: String,
    pub token_base_url: String,
    pub client_id: String,
    pub opaque_server_id: String,
}

impl AppConfig {
    /// Loads config from build-time environment variables and applies runtime overrides.
    pub fn load() -> Self {
        let api_base_url = option_env!("PERMESI_API_BASE_URL")
            .or(option_env!("PERMESI_API_HOST"))
            .unwrap_or("");
        let token_base_url = option_env!("PERMESI_TOKEN_BASE_URL").unwrap_or("");
        let client_id = option_env!("PERMESI_CLIENT_ID").unwrap_or("");
        let opaque_server_id = option_env!("PERMESI_OPAQUE_SERVER_ID").unwrap_or("api.permesi.dev");

        let mut config = Self {
            api_base_url: api_base_url.to_string(),
            token_base_url: token_base_url.to_string(),
            client_id: client_id.to_string(),
            opaque_server_id: opaque_server_id.to_string(),
        };

        if let Some(runtime) = runtime_config() {
            apply_runtime_overrides(&mut config, runtime);
        }

        config
    }
}

#[derive(Default)]
struct RuntimeConfig {
    api_base_url: Option<String>,
    token_base_url: Option<String>,
    client_id: Option<String>,
    opaque_server_id: Option<String>,
}

fn apply_runtime_overrides(config: &mut AppConfig, runtime: RuntimeConfig) {
    if let Some(value) = runtime.api_base_url {
        config.api_base_url = value;
    }
    if let Some(value) = runtime.token_base_url {
        config.token_base_url = value;
    }
    if let Some(value) = runtime.client_id {
        config.client_id = value;
    }
    if let Some(value) = runtime.opaque_server_id {
        config.opaque_server_id = value;
    }
}

#[cfg(target_arch = "wasm32")]
fn runtime_config() -> Option<RuntimeConfig> {
    use js_sys::{Object, Reflect};
    use wasm_bindgen::JsValue;

    let window = web_sys::window()?;
    let config = Reflect::get(&window, &JsValue::from_str("PERMESI_CONFIG")).ok()?;
    if config.is_null() || config.is_undefined() {
        return None;
    }
    let object = Object::from(config);

    Some(RuntimeConfig {
        api_base_url: read_runtime_value(&object, "api_base_url"),
        token_base_url: read_runtime_value(&object, "token_base_url"),
        client_id: read_runtime_value(&object, "client_id"),
        opaque_server_id: read_runtime_value(&object, "opaque_server_id"),
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn runtime_config() -> Option<RuntimeConfig> {
    None
}

#[cfg(target_arch = "wasm32")]
fn read_runtime_value(object: &js_sys::Object, key: &str) -> Option<String> {
    let value = js_sys::Reflect::get(object, &wasm_bindgen::JsValue::from_str(key))
        .ok()?
        .as_string()?;
    normalize_runtime_value(&value)
}

fn normalize_runtime_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, RuntimeConfig, apply_runtime_overrides, normalize_runtime_value};

    #[test]
    fn normalize_runtime_value_trims_and_rejects_empty() {
        assert_eq!(normalize_runtime_value(""), None);
        assert_eq!(normalize_runtime_value("   "), None);
        assert_eq!(
            normalize_runtime_value("  https://api.permesi.dev "),
            Some("https://api.permesi.dev".to_string())
        );
    }

    #[test]
    fn apply_runtime_overrides_ignores_empty_values() {
        let mut config = AppConfig {
            api_base_url: "https://api.default".to_string(),
            token_base_url: "https://token.default".to_string(),
            client_id: "default-client".to_string(),
            opaque_server_id: "default-server".to_string(),
        };
        let runtime = RuntimeConfig {
            api_base_url: normalize_runtime_value(""),
            token_base_url: normalize_runtime_value("  "),
            client_id: normalize_runtime_value(""),
            opaque_server_id: normalize_runtime_value("  "),
        };

        apply_runtime_overrides(&mut config, runtime);

        assert_eq!(config.api_base_url, "https://api.default");
        assert_eq!(config.token_base_url, "https://token.default");
        assert_eq!(config.client_id, "default-client");
        assert_eq!(config.opaque_server_id, "default-server");
    }

    #[test]
    fn apply_runtime_overrides_overwrites_when_present() {
        let mut config = AppConfig {
            api_base_url: "https://api.default".to_string(),
            token_base_url: "https://token.default".to_string(),
            client_id: "default-client".to_string(),
            opaque_server_id: "default-server".to_string(),
        };
        let runtime = RuntimeConfig {
            api_base_url: normalize_runtime_value("https://api.override"),
            token_base_url: normalize_runtime_value("https://token.override"),
            client_id: normalize_runtime_value("override-client"),
            opaque_server_id: normalize_runtime_value("override-server"),
        };

        apply_runtime_overrides(&mut config, runtime);

        assert_eq!(config.api_base_url, "https://api.override");
        assert_eq!(config.token_base_url, "https://token.override");
        assert_eq!(config.client_id, "override-client");
        assert_eq!(config.opaque_server_id, "override-server");
    }
}
