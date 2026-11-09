//! Alert banners for success and error messages. Messages must be safe to render
//! and should never include secrets or tokens.

use super::{Icon, IconName, icon_size};
use leptos::prelude::*;

#[derive(Clone, Copy)]
/// Supported alert styles.
pub enum AlertKind {
    Error,
    Success,
    Info,
}

/// Renders a styled alert banner. The leading icon is decorative and reinforces
/// the colour so the state is not conveyed by colour alone; the message text is
/// the accessible content.
#[component]
pub fn Alert(kind: AlertKind, message: String) -> impl IntoView {
    let (class, icon) = match kind {
        AlertKind::Error => (
            "flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-400 dark:bg-red-900/30 dark:text-red-200",
            IconName::Error,
        ),
        AlertKind::Success => (
            "flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700 dark:border-emerald-400 dark:bg-emerald-900/30 dark:text-emerald-200",
            IconName::Success,
        ),
        AlertKind::Info => (
            "flex items-start gap-2 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-700 dark:border-blue-400 dark:bg-blue-900/30 dark:text-blue-200",
            IconName::Info,
        ),
    };

    view! {
        <div class=class role="alert">
            <Icon name=icon size=icon_size::CONTROL class="mt-0.5" />
            <span class="min-w-0 break-words">{message}</span>
        </div>
    }
}
