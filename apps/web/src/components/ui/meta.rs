//! Compact metadata rows for entity cards and detail headers.
//!
//! Visible labels and aligned icon/label columns make fields recognizable without
//! tooltips. Values wrap rather than truncate, preserving complete identifiers.

use super::{Icon, IconName, icon_size};
use leptos::prelude::*;

/// One `<dt>`/`<dd>` metadata pair; render inside a `<dl>`.
#[component]
pub fn MetaItem(
    icon: IconName,
    label: &'static str,
    #[prop(optional)] mono: bool,
    children: Children,
) -> impl IntoView {
    let value_class = if mono {
        "min-w-0 break-words font-mono text-sm text-gray-900 dark:text-gray-100"
    } else {
        "min-w-0 break-words text-sm text-gray-900 dark:text-gray-100"
    };
    view! {
        <div class="metadata-row text-xs">
            <Icon name=icon size=icon_size::INLINE class="mt-0.5 text-gray-400 dark:text-gray-500" />
            <dt class="pt-0.5 text-gray-500 dark:text-gray-400">{label}</dt>
            <dd class=value_class>{children()}</dd>
        </div>
    }
}
