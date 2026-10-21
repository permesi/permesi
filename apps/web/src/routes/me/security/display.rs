//! Credential timestamp presentation shared by the security sections.

use js_sys::Date;
use wasm_bindgen::JsValue;

/// Formats a server timestamp without discarding invalid presentation input.
pub(super) fn format_rfc3339(value: &str) -> String {
    let date = Date::new(&JsValue::from_str(value));
    if date.get_time().is_nan() {
        value.to_string()
    } else {
        date.to_iso_string().into()
    }
}

/// Presents recent credential usage with a bounded relative-time window.
pub(super) fn format_relative(value: &str) -> String {
    let date = Date::new(&JsValue::from_str(value));
    if date.get_time().is_nan() {
        return value.to_string();
    }
    let now_ms = Date::now();
    let then_ms = date.get_time();
    let diff_ms = (now_ms - then_ms).max(0.0);
    let Ok(elapsed) = std::time::Duration::try_from_secs_f64(diff_ms / 1000.0) else {
        return format_rfc3339(value);
    };
    let total_minutes = elapsed.as_secs() / 60;
    let cutoff_minutes = 30 * 24 * 60;
    if total_minutes >= cutoff_minutes {
        return format_rfc3339(value);
    }
    if total_minutes == 0 {
        return "Just now".to_string();
    }
    let days = total_minutes / (60 * 24);
    let hours = (total_minutes % (60 * 24)) / 60;
    let mins = total_minutes % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{} day{}", days, if days == 1 { "" } else { "s" }));
        if hours > 0 {
            parts.push(format!(
                "{} hour{}",
                hours,
                if hours == 1 { "" } else { "s" }
            ));
        } else if mins > 0 {
            parts.push(format!("{} min{}", mins, if mins == 1 { "" } else { "s" }));
        }
    } else if hours > 0 {
        parts.push(format!(
            "{} hour{}",
            hours,
            if hours == 1 { "" } else { "s" }
        ));
        if mins > 0 {
            parts.push(format!("{} min{}", mins, if mins == 1 { "" } else { "s" }));
        }
    } else {
        parts.push(format!("{} min{}", mins, if mins == 1 { "" } else { "s" }));
    }

    format!("{} ago", parts.join(", "))
}
