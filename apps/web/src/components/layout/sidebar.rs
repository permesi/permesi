//! Side navigation for authenticated users.
//!
//! Organized by domain hierarchy:
//! 1. Personal (Dashboard, Profile)
//! 2. Tenancy (Organizations, Projects)
//! 3. Platform Admin (Users, Global Settings - Operator only)

use crate::features::auth::state::use_auth;
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location};

#[component]
pub fn Sidebar() -> impl IntoView {
    let auth = use_auth();
    let location = use_location();
    let pathname = move || location.pathname.get();

    view! {
        <aside class="w-64 flex-shrink-0 hidden md:flex flex-col border-r border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-y-auto">
            <nav class="flex-1 px-4 py-6 space-y-8">
                // --- Section: Personal ---
                <div>
                    <h3 class="px-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        "Personal"
                    </h3>
                    <div class="mt-2 space-y-1">
                        <SidebarLink
                            target="/"
                            icon="dashboard"
                            label="Dashboard"
                            active=move || pathname() == "/"
                        />
                        <SidebarLink
                            target="/me"
                            icon="person"
                            label="My Profile"
                            active=move || pathname() == "/me"
                        />
                    </div>
                </div>

                // --- Section: Tenancy ---
                <div>
                    <h3 class="px-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        "Tenancy"
                    </h3>
                    <div class="mt-2 space-y-1">
                        <SidebarLink
                            target="/orgs"
                            icon="corporate_fare"
                            label="Organizations"
                            active=move || pathname().starts_with("/orgs")
                        />
                    </div>
                </div>

                // --- Section: Platform Admin (Role-Gated) ---
                <Show when=move || auth.is_operator.get()>
                    <div>
                        <h3 class="px-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            "Platform Admin"
                        </h3>
                        <div class="mt-2 space-y-1">
                            <SidebarLink
                                target="/admin"
                                icon="admin_panel_settings"
                                label="Admin Overview"
                                active=move || pathname() == "/admin"
                            />
                            <SidebarLink
                                target="/users"
                                icon="group"
                                label="Global Users"
                                active=move || pathname().starts_with("/users")
                            />
                            <SidebarLink
                                target="/admin/claim"
                                icon="key"
                                label="Admin Elevation"
                                active=move || pathname() == "/admin/claim"
                            />
                        </div>
                    </div>
                </Show>
            </nav>

            // Footer / Build Info
            <div class="p-4 border-t border-gray-100 dark:border-gray-800">
                <p class="text-[10px] text-gray-400 font-mono text-center uppercase tracking-tighter">
                    "Permesi Identity Engine"
                </p>
            </div>
        </aside>
    }
}

#[component]
fn SidebarLink<F>(
    target: &'static str,
    icon: &'static str,
    label: &'static str,
    active: F,
) -> impl IntoView
where
    F: Fn() -> bool + Clone + Send + Sync + 'static,
{
    let active_1 = active.clone();
    let active_2 = active.clone();
    let active_3 = active.clone();
    let active_4 = active.clone();
    let active_5 = active.clone();
    let active_6 = active.clone();
    let active_7 = active.clone();
    let active_8 = active.clone();
    let active_9 = active.clone();
    let active_10 = active.clone();
    let active_11 = active.clone();
    let active_12 = active.clone();
    let active_13 = active.clone();
    let active_14 = active.clone();

    view! {
        <A
            href=move || target.to_string()
            {..}
            attr:class="group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors"
            class:text-blue-600=move || active_1()
            class:bg-blue-50=move || active_2()
            class:dark:bg-blue-900=move || active_3()
            class:dark:text-blue-400=move || active_4()
            class:text-gray-600=move || !active_5()
            class:dark:text-gray-300=move || !active_6()
            class:hover:bg-gray-50=move || !active_7()
            class:dark:hover:bg-gray-800=move || !active_8()
            class:hover:text-gray-900=move || !active_9()
            class:dark:hover:text-white=move || !active_10()
        >
            <span
                class="material-symbols-outlined mr-3 text-xl transition-colors"
                class:text-blue-600=move || active_11()
                class:dark:text-blue-400=move || active_12()
                class:text-gray-400=move || !active_13()
                class:group-hover:text-gray-900=move || !active_14()
                class:dark:group-hover:text-white=move || {
                    let active = active.clone();
                    !active()
                }
            >
                {icon}
            </span>
            {label}
        </A>
    }
}
