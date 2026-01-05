//! Minimalistic and clean 404 page for unknown or unauthorized routes.

use crate::components::AppShell;
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders a polished, minimalistic not-found page with AppShell wrapper.
/// Use this for top-level route fallbacks.
#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <AppShell>
            <NotFoundContent />
        </AppShell>
    }
}

/// Inner 404 content without AppShell. Use inside guards where the page
/// component already provides the shell.
#[component]
pub fn NotFoundContent() -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center min-h-[50vh] text-center px-4">
            <div class="relative">
                <h1 class="text-9xl font-black text-gray-100 dark:text-gray-800 select-none">
                    "404"
                </h1>
                <p class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-2xl font-bold text-gray-900 dark:text-white whitespace-nowrap">
                    "Page not found"
                </p>
            </div>

            <div class="mt-4 space-y-6">
                <p class="text-gray-500 dark:text-gray-400 max-w-sm mx-auto">
                    "The resource you requested is missing or you don't have permission to view it."
                </p>

                <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
                    <A
                        href="/"
                        {..}
                        class="inline-flex items-center px-5 py-2.5 text-sm font-medium text-white bg-blue-700 rounded-lg hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800 transition-all"
                    >
                        <span class="material-symbols-outlined mr-2 text-base">"home"</span>
                        "Go Home"
                    </A>
                    <button
                        on:click=move |_| {
                            let window = web_sys::window().expect("no window");
                            let history = window.history().expect("no history");
                            let _ = history.back();
                        }
                        class="inline-flex items-center px-5 py-2.5 text-sm font-medium text-gray-900 bg-white border border-gray-200 rounded-lg hover:bg-gray-100 hover:text-blue-700 focus:z-10 focus:ring-4 focus:ring-gray-100 dark:focus:ring-gray-700 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600 dark:hover:text-white dark:hover:bg-gray-700 transition-all"
                    >
                        <span class="material-symbols-outlined mr-2 text-base">"arrow_back"</span>
                        "Go Back"
                    </button>
                </div>
            </div>
        </div>
    }
}
