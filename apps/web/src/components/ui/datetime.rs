//! Readable UTC timestamps for metadata rows.
//!
//! Server timestamps arrive as RFC 3339 strings. They are shown as short UTC dates so
//! the same instant reads identically for every operator, while the exact ISO value
//! stays available in the `datetime` attribute and the tooltip. Unparseable input is
//! rendered unchanged rather than hidden.

use js_sys::Date;
use leptos::prelude::*;
use wasm_bindgen::JsValue;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Returns `(display, exact)` for a valid timestamp, `None` otherwise.
///
/// Dates are always UTC; the time variant says so explicitly because the browser's
/// local zone would otherwise be assumed.
fn format_utc(value: &str, with_time: bool) -> Option<(String, String)> {
    let date = Date::new(&JsValue::from_str(value));
    if date.get_time().is_nan() {
        return None;
    }
    let month = usize::try_from(date.get_utc_month()).ok()?;
    let day = format!(
        "{} {}, {}",
        MONTHS.get(month)?,
        date.get_utc_date(),
        date.get_utc_full_year()
    );
    let exact = String::from(date.to_iso_string());
    let display = if with_time {
        format!(
            "{day} · {:02}:{:02} UTC",
            date.get_utc_hours(),
            date.get_utc_minutes()
        )
    } else {
        day
    };
    Some((display, exact))
}

/// Renders a `<time>` element with a readable UTC label and the exact ISO value in its title.
#[component]
pub fn DateTime(
    #[prop(into)] value: String,
    #[prop(default = true)] with_time: bool,
) -> impl IntoView {
    match format_utc(&value, with_time) {
        Some((text, exact)) => view! { <time datetime=value title=exact>{text}</time> }.into_any(),
        None => view! { <span>{value}</span> }.into_any(),
    }
}
