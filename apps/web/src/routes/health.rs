//! Health route that displays build metadata and system status for quick diagnostics.
//! It exposes only non-sensitive data like frontend/backend versions, commit hashes,
//! and component health.

use crate::{
    app_lib::GIT_COMMIT_HASH,
    components::{Icon, IconName, Spinner, icon_size},
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
            <div class="min-w-0 w-full max-w-lg rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800">
                <div class="border-b border-gray-200 px-6 py-4 dark:border-gray-700">
                    <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
                        "System Status"
                    </h2>
                </div>
                <div class="p-6">
                    {move || match health.get() {
                        None => view! {
                            <div class="flex flex-col items-center justify-center py-8 gap-3 text-gray-500 dark:text-gray-400">
                                <Spinner />
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
                                <Icon name=IconName::Error size=icon_size::EMPTY class="mb-2" />
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

/// Displays a build field with a wrapping value so full commit hashes remain readable.
#[component]
fn HealthItem(
    label: &'static str,
    value: String,
    #[prop(optional)] monospace: bool,
) -> impl IntoView {
    view! {
        <div class="grid min-w-0 grid-cols-1 gap-1 text-sm sm:grid-cols-2 sm:gap-4">
            <span class="text-gray-500 dark:text-gray-400">{label}</span>
            <span class={if monospace { "min-w-0 break-words font-mono text-gray-700 dark:text-gray-300 sm:text-right" } else { "min-w-0 break-words font-medium text-gray-900 dark:text-white sm:text-right" }}>
                {value}
            </span>
        </div>
    }
}

/// Shows the server-reported component status with semantic text rather than a badge.
#[component]
fn StatusItem(label: &'static str, status: String) -> impl IntoView {
    let is_ok = is_status_ok(&status);
    view! {
        <div class="flex min-w-0 flex-wrap justify-between items-start gap-2 text-sm">
            <span class="text-gray-500 dark:text-gray-400">{label}</span>
            <span class={if is_ok { "min-w-0 break-words text-green-600 dark:text-green-400 capitalize" } else { "min-w-0 break-words text-red-600 dark:text-red-400 capitalize" }}>
                {status}
            </span>
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
