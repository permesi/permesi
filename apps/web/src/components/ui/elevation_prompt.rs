//! Component shown when platform operator elevation is required.

use crate::routes::paths;
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders a prompt for operators to elevate their session.
#[component]
pub fn ElevationPrompt() -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center min-h-[50vh] text-center px-4">
            <div class="p-8 bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 max-w-md w-full">
                <span class="material-symbols-outlined text-6xl text-blue-600 mb-4 animate-pulse">"lock"</span>
                <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-2">"Elevation Required"</h2>
                <p class="text-gray-500 dark:text-gray-400 mb-6 text-sm">
                    "You are a platform operator, but this section requires an active admin token. Please elevate your session to continue."
                </p>
                <A
                    href={paths::ADMIN_CLAIM}
                    {..}
                    class="inline-flex items-center px-6 py-3 text-base font-medium text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-all shadow-md hover:shadow-lg active:scale-95"
                >
                    <span class="material-symbols-outlined mr-2 text-xl">"key"</span>
                    "Elevate Session"
                </A>
            </div>
        </div>
    }
}
