//! Side navigation for authenticated users.
//!
//! Organized by domain hierarchy:
//! 1. Personal (Dashboard, Profile)
//! 2. Workspace (Organizations, Projects)
//! 3. Platform Admin (Users, Global Settings - Operator only)

use crate::app_lib::theme::Theme;
use crate::features::auth::state::use_auth;
use crate::routes::paths;
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location};

#[component]
pub fn Sidebar() -> impl IntoView {
    let auth = use_auth();
    let location = use_location();
    let pathname = move || location.pathname.get();

    let (is_profile_open, set_profile_open) = signal(false);

    // Auto-expand if navigating to any profile sub-route
    Effect::new(move |_| {
        if pathname().starts_with("/console/me") {
            set_profile_open.set(true);
        }
    });

    let toggle_profile = move |_| {
        set_profile_open.update(|open| *open = !*open);
    };

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
                            target={paths::DASHBOARD}
                            icon="dashboard"
                            label="Dashboard"
                            active=move || pathname() == paths::DASHBOARD
                        />

                        // My Profile Parent (Collapsible)
                        <div>
                            <button
                                on:click=toggle_profile
                                class="w-full group flex items-center justify-between px-2 py-2 text-sm font-medium rounded-md transition-colors text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white"
                                class:text-gray-900=move || is_profile_open.get()
                                class:dark:text-white=move || is_profile_open.get()
                                aria-expanded=move || if is_profile_open.get() { "true" } else { "false" }
                            >
                                <div class="flex items-center">
                                    <span class=Theme::ICON>
                                        "person"
                                    </span>
                                    "My Profile"
                                </div>
                                <span
                                    class="material-symbols-outlined text-base text-gray-400 transition-transform duration-200"
                                    class:rotate-180=move || is_profile_open.get()
                                >
                                    "expand_more"
                                </span>
                            </button>

                            // Nested Children
                            <div
                                class="mt-1 space-y-1 overflow-hidden transition-all duration-300 ease-in-out"
                                class:max-h-0=move || !is_profile_open.get()
                                class:max-h-40=move || is_profile_open.get()
                                class:opacity-0=move || !is_profile_open.get()
                                class:opacity-100=move || is_profile_open.get()
                            >
                                // Overview Child
                                <A
                                    href=move || paths::ME.to_string()
                                    {..}
                                    attr:class="group flex items-center pl-10 pr-2 py-2 text-sm font-medium rounded-md transition-colors"
                                    class:text-blue-600=move || pathname() == paths::ME
                                    class:bg-blue-50=move || pathname() == paths::ME
                                    class:dark:bg-blue-900=move || pathname() == paths::ME
                                    class:dark:text-blue-400=move || pathname() == paths::ME
                                    class:text-gray-500=move || pathname() != paths::ME
                                    class:dark:text-gray-400=move || pathname() != paths::ME
                                    class:hover:bg-gray-50=move || pathname() != paths::ME
                                    class:dark:hover:bg-gray-800=move || pathname() != paths::ME
                                    class:hover:text-gray-900=move || pathname() != paths::ME
                                    class:dark:hover:text-white=move || pathname() != paths::ME
                                >
                                    <span
                                        class="material-symbols-outlined mr-3 text-lg transition-colors"
                                        class:text-blue-600=move || pathname() == paths::ME
                                        class:dark:text-blue-400=move || pathname() == paths::ME
                                        class:text-gray-400=move || pathname() != paths::ME
                                        class:group-hover:text-gray-900=move || pathname() != paths::ME
                                        class:dark:group-hover:text-white=move || pathname() != paths::ME
                                    >
                                        "badge"
                                    </span>
                                    "Overview"
                                </A>

                                // Security Child
                                <A
                                    href=move || paths::ME_SECURITY.to_string()
                                    {..}
                                    attr:class="group flex items-center pl-10 pr-2 py-2 text-sm font-medium rounded-md transition-colors"
                                    class:text-blue-600=move || pathname() == paths::ME_SECURITY
                                    class:bg-blue-50=move || pathname() == paths::ME_SECURITY
                                    class:dark:bg-blue-900=move || pathname() == paths::ME_SECURITY
                                    class:dark:text-blue-400=move || pathname() == paths::ME_SECURITY
                                    class:text-gray-500=move || pathname() != paths::ME_SECURITY
                                    class:dark:text-gray-400=move || pathname() != paths::ME_SECURITY
                                    class:hover:bg-gray-50=move || pathname() != paths::ME_SECURITY
                                    class:dark:hover:bg-gray-800=move || pathname() != paths::ME_SECURITY
                                    class:hover:text-gray-900=move || pathname() != paths::ME_SECURITY
                                    class:dark:hover:text-white=move || pathname() != paths::ME_SECURITY
                                >
                                    <span
                                        class="material-symbols-outlined mr-3 text-lg transition-colors"
                                        class:text-blue-600=move || pathname() == paths::ME_SECURITY
                                        class:dark:text-blue-400=move || pathname() == paths::ME_SECURITY
                                        class:text-gray-400=move || pathname() != paths::ME_SECURITY
                                        class:group-hover:text-gray-900=move || pathname() != paths::ME_SECURITY
                                        class:dark:group-hover:text-white=move || pathname() != paths::ME_SECURITY
                                    >
                                        "encrypted"
                                    </span>
                                    "Security"
                                </A>
                            </div>
                        </div>
                    </div>
                </div>

                // --- Section: Workspace ---
                <div>
                    <h3 class="px-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        "Workspace"
                    </h3>
                    <div class="mt-2 space-y-1">
                        <SidebarLink
                            target={paths::ORGS}
                            icon="corporate_fare"
                            label="Organizations"
                            active=move || pathname().starts_with(paths::ORGS)
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
                                target={paths::ADMIN}
                                icon="admin_panel_settings"
                                label="Admin Overview"
                                active=move || pathname() == paths::ADMIN
                            />
                            <SidebarLink
                                target={paths::USERS}
                                icon="group"
                                label="Global Users"
                                active=move || pathname().starts_with(paths::USERS)
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
