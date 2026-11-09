//! Component shown when platform operator elevation is required.

use super::{Icon, IconName, icon_size};
use crate::routes::paths;
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders a prompt for operators to elevate their session.
#[component]
pub fn ElevationPrompt() -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center min-h-[50vh] text-center px-4">
            <div class="p-8 bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 max-w-md w-full">
                <Icon name=IconName::LockedKey size=icon_size::EMPTY class="mb-4 text-gray-400 dark:text-gray-500" />
                <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-2">"Elevation Required"</h2>
                <p class="text-gray-500 dark:text-gray-400 mb-6 text-sm">
                    "You are a platform operator, but this section requires an active admin token. Please elevate your session to continue."
                </p>
                <A
                    href={paths::ADMIN_CLAIM}
                    {..}
                    class="inline-flex cursor-pointer items-center px-4 py-2 text-sm font-medium text-white bg-blue-700 rounded-lg hover:bg-blue-800 focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                    <Icon name=IconName::KeyRound size=icon_size::CONTROL class="mr-2" />
                    "Elevate Session"
                </A>
            </div>
        </div>
    }
}
