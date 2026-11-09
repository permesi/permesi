//! Admin overview showing neutral navigation cards and semantic system-health status.

use crate::{
    components::{Icon, IconName, icon_size},
    features::auth::{client, state::use_auth, types::AdminInfraResponse},
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders the admin dashboard with real-time system stats.
#[component]
pub fn AdminPage() -> impl IntoView {
    let auth = use_auth();

    let infra = LocalResource::new(move || {
        let token = auth.admin_token.get();
        async move { client::admin_infra(token.as_ref().map(|t| t.admin_token.as_str())).await }
    });

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <div class="space-y-1">
                    <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                        "Admin Dashboard"
                    </h1>
                    <p class="text-sm text-gray-500 dark:text-gray-400">
                        "System health and platform metrics."
                    </p>
                </div>
                <button
                    on:click=move |_| infra.refetch()
                    class="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800"
                    aria-label="Refresh system status"
                    title="Refresh system status"
                >
                    <Icon name=IconName::Refresh size=icon_size::INLINE />
                    "Refresh"
                </button>
            </div>

            <Suspense fallback=move || view! { <crate::components::ui::Spinner /> }.into_any()>
                {move || match infra.get() {
                    Some(Ok(data)) => render_infra_grid(data).into_any(),
                    Some(Err(err)) => {
                        view! { <crate::components::ui::Alert kind=crate::components::ui::AlertKind::Error message=err.to_string() /> }
                            .into_any()
                    }
                    None => view! { <crate::components::ui::Spinner /> }.into_any(),
                }}
            </Suspense>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
                <A href={paths::USERS} {..} class="cursor-pointer min-w-0 p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-gray-400 dark:hover:border-gray-500 focus-visible:ring-2 focus-visible:ring-blue-500 transition-colors">
                    <div class="flex items-start gap-3">
                        <Icon name=IconName::Users size=icon_size::CONTROL class="mt-1 shrink-0 text-gray-400 dark:text-gray-500" />
                        <div class="min-w-0">
                            <h2 class="break-words text-lg font-medium text-gray-900 dark:text-white">"Users"</h2>
                            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">"Manage platform users and permissions."</p>
                        </div>
                    </div>
                </A>
                <A href={paths::ADMIN_ORGS} {..} class="cursor-pointer min-w-0 p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-gray-400 dark:hover:border-gray-500 focus-visible:ring-2 focus-visible:ring-blue-500 transition-colors">
                    <div class="flex items-start gap-3">
                        <Icon name=IconName::Organizations size=icon_size::CONTROL class="mt-1 shrink-0 text-gray-400 dark:text-gray-500" />
                        <div class="min-w-0">
                            <h2 class="break-words text-lg font-medium text-gray-900 dark:text-white">"Organizations"</h2>
                            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">"Inspect all active tenants and their resources."</p>
                        </div>
                    </div>
                </A>
            </div>
        </div>
    }
}

/// Displays infrastructure metrics without changing the server-reported health state.
fn render_infra_grid(data: AdminInfraResponse) -> impl IntoView {
    let db_color = if data.database.status == "ok" {
        "text-green-500"
    } else {
        "text-red-500"
    };
    let vault_color = if data.vault.status == "ok" && !data.vault.sealed {
        "text-green-500"
    } else {
        "text-red-500"
    };

    view! {
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            // Database Card
            <div class="min-w-0 p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between gap-3 mb-4">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-white">"Database"</h3>
                    <Icon name=IconName::Database size=icon_size::CONTROL class="text-gray-400 dark:text-gray-500" />
                </div>
                <div class="space-y-2">
                    <div class="flex flex-wrap justify-between gap-x-3 gap-y-1 text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Status"</span>
                        <span class=db_color>{data.database.status}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Pool Size"</span>
                        <span class="font-medium dark:text-white">{data.database.pool_size}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Active / Idle"</span>
                        <span class="font-medium dark:text-white">{data.database.active_connections} " / " {data.database.idle_connections}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Permesi Size"</span>
                        <span class="font-medium dark:text-white">{format_bytes(data.database.permesi_size_bytes)}</span>
                    </div>
                </div>
            </div>

            // Vault Card
            <div class="min-w-0 p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between gap-3 mb-4">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-white">"Vault"</h3>
                    <Icon name=IconName::LockedKey size=icon_size::CONTROL class="text-gray-400 dark:text-gray-500" />
                </div>
                <div class="space-y-2">
                    <div class="flex min-w-0 justify-between gap-3 text-sm">
                        <span class="shrink-0 text-gray-500 dark:text-gray-400">"Version"</span>
                        <span class="min-w-0 break-words text-right font-medium dark:text-white">{data.vault.version}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Sealed"</span>
                        <span class="font-medium dark:text-white">{data.vault.sealed.to_string()}</span>
                    </div>
                    <div class="flex flex-wrap justify-between gap-x-3 gap-y-1 text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Status"</span>
                        <span class=vault_color>{data.vault.status}</span>
                    </div>
                </div>
            </div>

            // Platform Card
            <div class="min-w-0 p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between gap-3 mb-4">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-white">"Platform"</h3>
                    <Icon name=IconName::Health size=icon_size::CONTROL class="text-gray-400 dark:text-gray-500" />
                </div>
                <div class="space-y-2">
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Operators"</span>
                        <span class="font-medium dark:text-white">{data.platform.operator_count}</span>
                    </div>
                    <div class="flex flex-wrap justify-between gap-x-3 gap-y-1 text-sm">
                        <span class="text-gray-500 dark:text-gray-400">"Recent Elevation Attempts"</span>
                        <span class="font-medium dark:text-white">{data.platform.recent_attempts_count}</span>
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-2">"Attempts tracked in the last hour"</p>
                </div>
            </div>
        </div>
    }
}

fn format_bytes(value: Option<i64>) -> String {
    let Some(bytes) = value.filter(|bytes| *bytes >= 0) else {
        return "unavailable".to_string();
    };
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let value = u128::try_from(bytes).unwrap_or_default();
    let mut divisor = 1_u128;
    let mut unit_index = 0;
    while value / divisor >= 1024 && unit_index < units.len() - 1 {
        divisor *= 1024;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{bytes} B")
    } else {
        let hundredths = (value * 100 + divisor / 2) / divisor;
        let whole = hundredths / 100;
        let fraction = hundredths % 100;
        let unit = units.get(unit_index).copied().unwrap_or("B");
        format!("{whole}.{fraction:02} {unit}")
    }
}
