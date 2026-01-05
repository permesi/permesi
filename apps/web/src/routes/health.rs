//! Health route that displays build metadata for quick diagnostics. It shows the
//! git commit locally without a backend call and exposes only non-sensitive data.

use crate::app_lib::build_info;
use leptos::prelude::*;

/// Renders the build version card.
#[component]
pub fn HealthPage() -> impl IntoView {
    let commit = build_info::git_commit_hash();

    view! {
        <div class="flex justify-center">
            <div class="block max-w-[38rem] rounded-lg border border-neutral-200 bg-white dark:border-neutral-300 dark:bg-neutral-600">
                <div class="border-b-2 border-[#0000002d] px-6 py-3 text-neutral-600 dark:text-neutral-50 font-semibold">
                    "Build Version"
                </div>
                <div class="p-6">
                    <div class="text-base text-black dark:text-neutral-50">
                        <pre class="text-center">{commit}</pre>
                    </div>
                </div>
            </div>
        </div>
    }
}
