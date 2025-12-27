use js_sys::Reflect;
use wasm_bindgen::JsValue;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_base_url: String,
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        if let Some(url) = option_env!("PERMESI_API_BASE_URL") {
            return Ok(Self {
                api_base_url: url.to_string(),
            });
        }

        if let Some(url) = Self::from_window() {
            return Ok(Self { api_base_url: url });
        }

        Err("API base URL is not configured.".to_string())
    }

    fn from_window() -> Option<String> {
        let window = web_sys::window()?;
        let config = Reflect::get(&window, &JsValue::from_str("__PERMESI_CONFIG__")).ok()?;
        if config.is_null() || config.is_undefined() {
            return None;
        }
        let value = Reflect::get(&config, &JsValue::from_str("API_BASE_URL")).ok()?;
        value.as_string()
    }
}
