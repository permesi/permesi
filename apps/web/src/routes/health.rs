//! Health route that displays build metadata and system status for quick diagnostics.
//! It exposes only non-sensitive data like frontend/backend versions, commit hashes,
//! and component health.

use crate::{
    app_lib::GIT_COMMIT_HASH,
    features::auth::{client, types::HealthResponse},
};
use leptos::{prelude::*, task::spawn_local};

const FRONTEND_VERSION: &str = env!("CARGO_PKG_VERSION");
const FRONTEND_COMMIT: &str = GIT_COMMIT_HASH;

/// Renders the build version and system health card.
#[component]
pub fn HealthPage() -> impl IntoView {
    let (health, set_health) = signal::<Option<Result<HealthResponse, String>>>(None);

    Effect::new(move |_| {
        spawn_local(async move {
            match client::fetch_health().await {
                Ok(response) => set_health.set(Some(Ok(response))),
                Err(e) => set_health.set(Some(Err(e.to_string()))),
            }
        });
    });

    view! {
        <div class="flex justify-center py-10 px-4">
            <div class="w-full max-w-lg rounded-xl border border-gray-200 bg-white shadow-sm dark:border-gray-700 dark:bg-gray-800">
                <div class="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
                    <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
                        "System Status"
                    </h2>
                </div>
                <div class="p-6">
                    {move || match health.get() {
                        None => view! {
                            <div class="flex flex-col items-center justify-center py-8 gap-3 text-gray-500">
                                <span class="material-symbols-outlined animate-spin text-3xl">"sync"</span>
                                <p>"Checking system health..."</p>
                            </div>
                        }.into_any(),
                        Some(Ok(info)) => view! {
                            <div class="space-y-4">
                                <HealthItem label="Frontend Version" value=FRONTEND_VERSION.to_string() />
                                <HealthItem label="Frontend Commit" value=FRONTEND_COMMIT.to_string() monospace=true />
                                <div class="my-4 border-t border-gray-100 dark:border-gray-700"></div>
                                <HealthItem label="Backend Service" value=info.name />
                                <HealthItem label="Backend Version" value=info.version />
                                <HealthItem label="Backend Commit" value=info.commit monospace=true />
                                <div class="my-4 border-t border-gray-100 dark:border-gray-700"></div>
                                <StatusItem label="Database" status=info.database />
                                <StatusItem label="Admission Keyset" status=info.admission_keyset />
                            </div>
                        }.into_any(),
                        Some(Err(err)) => view! {
                            <div class="flex w-full flex-col items-center justify-center py-6 text-center text-red-600 dark:text-red-400">
                                <span class="material-symbols-outlined text-4xl mb-2">"error"</span>
                                <p class="font-medium">"System Unreachable"</p>
                                <p class="mt-1 w-full max-w-full break-words text-sm opacity-80">{err}</p>
                            </div>
                        }.into_any(),
                    }}
                </div>
            </div>
        </div>
    }
}

#[component]
fn HealthItem(
    label: &'static str,
    value: String,
    #[prop(optional)] monospace: bool,
) -> impl IntoView {
    view! {
        <div class="flex justify-between items-center text-sm">
            <span class="text-gray-500 dark:text-gray-400">{label}</span>
            <span class={if monospace { "font-mono text-gray-700 dark:text-gray-300" } else { "font-medium text-gray-900 dark:text-white" }}>
                {value}
            </span>
        </div>
    }
}

#[component]
fn StatusItem(label: &'static str, status: String) -> impl IntoView {
    let is_ok = is_status_ok(&status);
    view! {
        <div class="flex justify-between items-center text-sm">
            <span class="text-gray-500 dark:text-gray-400">{label}</span>
            <div class="flex items-center gap-2">
                <span class={if is_ok { "text-green-600 dark:text-green-400 capitalize" } else { "text-red-600 dark:text-red-400 capitalize" }}>
                    {status}
                </span>
                <span class={if is_ok { "text-green-500 text-[10px]" } else { "text-red-500 text-[10px]" }}>
                    "●"
                </span>
            </div>
        </div>
    }
}

fn is_status_ok(status: &str) -> bool {
    status.eq_ignore_ascii_case("ok") || status.eq_ignore_ascii_case("healthy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_status_ok() {
        assert!(is_status_ok("ok"));
        assert!(is_status_ok("OK"));
        assert!(is_status_ok("healthy"));
        assert!(is_status_ok("HEALTHY"));
        assert!(!is_status_ok("error"));
        assert!(!is_status_ok("unhealthy"));
        assert!(!is_status_ok(""));
    }
}
