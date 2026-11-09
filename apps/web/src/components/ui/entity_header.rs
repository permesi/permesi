//! Quiet, recognizable card headers shared by tenant and identity resources.
//! The chevron is reserved for cards whose entire surface navigates; action cards
//! remain plain headings so decorative cues do not imply a nonexistent link.

use super::{Icon, IconName, icon_size};
use leptos::prelude::*;

/// Renders an entity title with a muted icon and a structural divider.
#[component]
pub fn EntityHeader(
    icon: IconName,
    #[prop(optional)] navigable: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="flex min-w-0 items-start gap-2 border-b border-gray-100 pb-3 dark:border-gray-700">
            <Icon name=icon size=icon_size::CARD class="mt-0.5 text-gray-400 dark:text-gray-500" />
            <h3 class="min-w-0 flex-1 break-words text-lg font-semibold text-gray-900 dark:text-white">{children()}</h3>
            {navigable.then(|| view! { <Icon name=IconName::ChevronRight size=icon_size::CONTROL class="mt-1 text-gray-400 dark:text-gray-500" /> })}
        </div>
    }
}
