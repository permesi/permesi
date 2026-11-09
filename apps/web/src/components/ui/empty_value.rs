//! Neutral read-only missing values, distinct from errors and effective defaults.

use leptos::prelude::*;

/// Displays an unset, empty or unavailable value without implying a warning.
#[component]
pub fn EmptyValue(#[prop(default = "Not set")] text: &'static str) -> impl IntoView {
    view! { <span class="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500 dark:bg-gray-800 dark:text-gray-400">{text}</span> }
}
