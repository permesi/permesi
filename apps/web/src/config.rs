#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_host: String,
    pub token_host: Option<String>,
    pub client_id: Option<String>,
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        let api_host = resolve_required_value(
            option_env!("PERMESI_API_HOST").or(option_env!("PERMESI_API_BASE_URL")),
            Self::from_window_value("API_HOST").or_else(|| Self::from_window_value("API_BASE_URL")),
            "API host",
        )?;
        let token_host = resolve_optional_value(
            option_env!("PERMESI_API_TOKEN_HOST"),
            Self::from_window_value("API_TOKEN_HOST"),
        );
        let client_id = resolve_optional_value(
            option_env!("PERMESI_CLIENT_ID"),
            Self::from_window_value("CLIENT_ID"),
        );

        Ok(Self {
            api_host,
            token_host,
            client_id,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn from_window_value(key: &str) -> Option<String> {
        let window = web_sys::window()?;
        let config = Reflect::get(&window, &JsValue::from_str("__PERMESI_CONFIG__")).ok()?;
        if config.is_null() || config.is_undefined() {
            return None;
        }
        let value = Reflect::get(&config, &JsValue::from_str(key)).ok()?;
        value.as_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_window_value(_key: &str) -> Option<String> {
        None
    }
}

fn resolve_required_value(
    env_value: Option<&str>,
    window_value: Option<String>,
    label: &str,
) -> Result<String, String> {
    resolve_optional_value(env_value, window_value)
        .ok_or_else(|| format!("{label} is not configured."))
}

fn resolve_optional_value(env_value: Option<&str>, window_value: Option<String>) -> Option<String> {
    if let Some(value) = env_value {
        return Some(value.to_string());
    }

    window_value
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, resolve_optional_value, resolve_required_value};

    #[test]
    fn config_resolve_prefers_env() {
        let result = resolve_required_value(
            Some("https://env.example"),
            Some("https://window.example".to_string()),
            "API host",
        );

        assert!(matches!(
            result,
            Ok(value) if value == "https://env.example"
        ));
    }

    #[test]
    fn config_resolve_uses_window() {
        let result =
            resolve_required_value(None, Some("https://window.example".to_string()), "API host");

        assert!(matches!(
            result,
            Ok(value) if value == "https://window.example"
        ));
    }

    #[test]
    fn config_resolve_errors_without_value() {
        let result = resolve_required_value(None, None, "API host");

        assert!(result.is_err());
    }

    #[test]
    fn config_load_matches_env_or_errors() {
        let result = AppConfig::load();

        match option_env!("PERMESI_API_HOST").or(option_env!("PERMESI_API_BASE_URL")) {
            Some(value) => {
                assert!(matches!(result, Ok(config) if config.api_host == value));
            }
            None => assert!(result.is_err()),
        }
    }

    #[test]
    fn config_optional_prefers_env() {
        let result = resolve_optional_value(
            Some("https://env.example"),
            Some("https://window.example".to_string()),
        );

        assert!(matches!(
            result,
            Some(value) if value == "https://env.example"
        ));
    }

    #[test]
    fn config_optional_uses_window() {
        let result = resolve_optional_value(None, Some("https://window.example".to_string()));

        assert!(matches!(
            result,
            Some(value) if value == "https://window.example"
        ));
    }

    #[test]
    fn config_fields_are_readable() {
        let config = AppConfig {
            api_host: "https://api.example".to_string(),
            token_host: Some("https://genesis.example".to_string()),
            client_id: Some("client-id".to_string()),
        };

        assert!(matches!(
            config.token_host,
            Some(value) if value == "https://genesis.example"
        ));
        assert!(matches!(
            config.client_id,
            Some(value) if value == "client-id"
        ));
    }
}
