#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_base_url: String,
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        let api_base_url =
            resolve_api_base_url(option_env!("PERMESI_API_BASE_URL"), Self::from_window())?;

        Ok(Self { api_base_url })
    }

    #[cfg(target_arch = "wasm32")]
    fn from_window() -> Option<String> {
        let window = web_sys::window()?;
        let config = Reflect::get(&window, &JsValue::from_str("__PERMESI_CONFIG__")).ok()?;
        if config.is_null() || config.is_undefined() {
            return None;
        }
        let value = Reflect::get(&config, &JsValue::from_str("API_BASE_URL")).ok()?;
        value.as_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_window() -> Option<String> {
        None
    }
}

fn resolve_api_base_url(
    env_value: Option<&str>,
    window_value: Option<String>,
) -> Result<String, String> {
    if let Some(value) = env_value {
        return Ok(value.to_string());
    }

    if let Some(value) = window_value {
        return Ok(value);
    }

    Err("API base URL is not configured.".to_string())
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, resolve_api_base_url};

    #[test]
    fn config_resolve_prefers_env() {
        let result = resolve_api_base_url(
            Some("https://env.example"),
            Some("https://window.example".to_string()),
        );

        assert!(matches!(
            result,
            Ok(value) if value == "https://env.example"
        ));
    }

    #[test]
    fn config_resolve_uses_window() {
        let result = resolve_api_base_url(None, Some("https://window.example".to_string()));

        assert!(matches!(
            result,
            Ok(value) if value == "https://window.example"
        ));
    }

    #[test]
    fn config_resolve_errors_without_value() {
        let result = resolve_api_base_url(None, None);

        assert!(result.is_err());
    }

    #[test]
    fn config_load_matches_env_or_errors() {
        let result = AppConfig::load();

        match option_env!("PERMESI_API_BASE_URL") {
            Some(value) => {
                assert!(matches!(result, Ok(config) if config.api_base_url == value));
            }
            None => assert!(result.is_err()),
        }
    }
}
