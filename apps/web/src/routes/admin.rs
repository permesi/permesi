//! Admin overview page showing system infrastructure health and platform stats.

use crate::{
    components::AppShell,
    features::auth::{RequireAdmin, client, state::use_auth, types::AdminInfraResponse},
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
        <AppShell>
            <RequireAdmin children=move || view! {
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
                            class="p-2 text-gray-500 hover:text-blue-600 transition-colors"
                        >
                            <span class="material-symbols-outlined">"refresh"</span>
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
                        <A href="/users" {..} class="group p-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm hover:border-blue-500 transition-all">
                            <div class="flex items-center gap-4">
                                <div class="p-3 bg-blue-50 dark:bg-blue-900/30 rounded-lg text-blue-600 dark:text-blue-400 group-hover:scale-110 transition-transform">
                                    <span class="material-symbols-outlined">"group"</span>
                                </div>
                                <div>
                                    <h2 class="font-semibold text-gray-900 dark:text-white">"Users"</h2>
                                    <p class="text-sm text-gray-500">"Manage platform users and permissions."</p>
                                </div>
                            </div>
                        </A>
                        <A href="/orgs" {..} class="group p-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm hover:border-blue-500 transition-all">
                            <div class="flex items-center gap-4">
                                <div class="p-3 bg-green-50 dark:bg-green-900/30 rounded-lg text-green-600 dark:text-green-400 group-hover:scale-110 transition-transform">
                                    <span class="material-symbols-outlined">"corporate_fare"</span>
                                </div>
                                <div>
                                    <h2 class="font-semibold text-gray-900 dark:text-white">"Organizations"</h2>
                                    <p class="text-sm text-gray-500">"Manage tenants and projects."</p>
                                </div>
                            </div>
                        </A>
                    </div>
                </div>
            } />
        </AppShell>
    }
}

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
            <div class="p-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wider">"Database"</h3>
                    <span class=format!("material-symbols-outlined {}", db_color)>"database"</span>
                </div>
                <div class="space-y-2">
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Status"</span>
                        <span class="font-medium dark:text-white">{data.database.status}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Pool Size"</span>
                        <span class="font-medium dark:text-white">{data.database.pool_size}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Active / Idle"</span>
                        <span class="font-medium dark:text-white">{data.database.active_connections} " / " {data.database.idle_connections}</span>
                    </div>
                </div>
            </div>

            // Vault Card
            <div class="p-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wider">"Vault"</h3>
                    <span class=format!("material-symbols-outlined {}", vault_color)>"lock"</span>
                </div>
                <div class="space-y-2">
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Version"</span>
                        <span class="font-medium dark:text-white">{data.vault.version}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Sealed"</span>
                        <span class="font-medium dark:text-white">{data.vault.sealed.to_string()}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Status"</span>
                        <span class="font-medium dark:text-white">{data.vault.status}</span>
                    </div>
                </div>
            </div>

            // Platform Card
            <div class="p-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wider">"Platform"</h3>
                    <span class="material-symbols-outlined text-blue-500">"monitoring"</span>
                </div>
                <div class="space-y-2">
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Operators"</span>
                        <span class="font-medium dark:text-white">{data.platform.operator_count}</span>
                    </div>
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-500">"Recent Elevation Attempts"</span>
                        <span class="font-medium dark:text-white">{data.platform.recent_attempts_count}</span>
                    </div>
                    <p class="text-[10px] text-gray-400 mt-2 italic">"Attempts tracked in the last hour"</p>
                </div>
            </div>
        </div>
    }
}
