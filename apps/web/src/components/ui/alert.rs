//! Alert banners for success and error messages. Messages must be safe to render
//! and should never include secrets or tokens.

use leptos::prelude::*;

#[derive(Clone, Copy)]
/// Supported alert styles.
pub enum AlertKind {
    Error,
    Success,
    Info,
}

/// Renders a styled alert banner.
#[component]
pub fn Alert(kind: AlertKind, message: String) -> impl IntoView {
    let class = match kind {
        AlertKind::Error => {
            "rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-400 dark:bg-red-900/30 dark:text-red-200"
        }
        AlertKind::Success => {
            "rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700 dark:border-emerald-400 dark:bg-emerald-900/30 dark:text-emerald-200"
        }
        AlertKind::Info => {
            "rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-700 dark:border-blue-400 dark:bg-blue-900/30 dark:text-blue-200"
        }
    };

    view! { <div class=class role="alert">{message}</div> }
}
