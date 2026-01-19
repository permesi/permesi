//! Side navigation for authenticated users.
//!
//! Organized by domain hierarchy:
//! 1. Personal (Dashboard, Profile)
//! 2. Workspace (Organizations, Projects)
//! 3. Platform Admin (Users, Global Settings - Operator only)

use crate::app_lib::theme::Theme;
use crate::features::auth::{client, state::use_auth};
use crate::routes::paths;
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{components::A, hooks::use_location};

#[component]
pub fn Sidebar() -> impl IntoView {
    let auth = use_auth();
    let location = use_location();
    let pathname = move || location.pathname.get();

    let (is_profile_open, set_profile_open) = signal(false);

    // True = Operational (Green), False = Offline (Red)
    let (is_healthy, set_is_healthy) = signal(false);

    Effect::new(move |_| {
        spawn_local(async move {
            if client::fetch_health().await.is_ok() {
                set_is_healthy.set(true);
            }
        });
    });

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
                            href={paths::DASHBOARD}
                            icon="dashboard"
                            label="Dashboard"
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
                                class="mt-1 space-y-1 transition-all duration-300 ease-in-out"
                                class:max-h-0=move || !is_profile_open.get()
                                class:max-h-40=move || is_profile_open.get()
                                class:opacity-0=move || !is_profile_open.get()
                                class:opacity-100=move || is_profile_open.get()
                                class:overflow-hidden=move || !is_profile_open.get()
                                class:overflow-visible=move || is_profile_open.get()
                            >
                                // Overview Child
                                <A
                                    href=move || paths::ME.to_string()
                                    {..}
                                    attr:class="group relative flex items-center gap-3 rounded-lg pl-10 pr-3 py-1 text-sm transition"
                                    class:bg-slate-200=move || pathname() == paths::ME
                                    class:text-slate-900=move || pathname() == paths::ME
                                    class:font-medium=move || pathname() == paths::ME
                                    class:text-slate-600=move || pathname() != paths::ME
                                    class:hover:bg-slate-100=move || pathname() != paths::ME
                                    class:hover:text-slate-900=move || pathname() != paths::ME
                                    aria-current=move || {
                                        if pathname() == paths::ME { Some("page") } else { None }
                                    }
                                >
                                    <Show when=move || pathname() == paths::ME>
                                        <span class="absolute -left-3 top-0.5 bottom-0.5 w-1 rounded bg-blue-600"></span>
                                    </Show>
                                    <span
                                        class=move || format!("{} text-lg", Theme::ICON)
                                        class:text-slate-700=move || pathname() == paths::ME
                                        class:text-slate-400=move || pathname() != paths::ME
                                    >
                                        "badge"
                                    </span>
                                    "Overview"
                                </A>

                                // Security Child
                                <A
                                    href=move || paths::ME_SECURITY.to_string()
                                    {..}
                                    attr:class="group relative flex items-center gap-3 rounded-lg pl-10 pr-3 py-1 text-sm transition"
                                    class:bg-slate-200=move || pathname() == paths::ME_SECURITY
                                    class:text-slate-900=move || pathname() == paths::ME_SECURITY
                                    class:font-medium=move || pathname() == paths::ME_SECURITY
                                    class:text-slate-600=move || pathname() != paths::ME_SECURITY
                                    class:hover:bg-slate-100=move || pathname() != paths::ME_SECURITY
                                    class:hover:text-slate-900=move || pathname() != paths::ME_SECURITY
                                    aria-current=move || {
                                        if pathname() == paths::ME_SECURITY {
                                            Some("page")
                                        } else {
                                            None
                                        }
                                    }
                                >
                                    <Show when=move || pathname() == paths::ME_SECURITY>
                                        <span class="absolute -left-3 top-0.5 bottom-0.5 w-1 rounded bg-blue-600"></span>
                                    </Show>
                                    <span
                                        class=move || format!("{} text-lg", Theme::ICON)
                                        class:text-slate-700=move || pathname() == paths::ME_SECURITY
                                        class:text-slate-400=move || pathname() != paths::ME_SECURITY
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
                            href={paths::ORGS}
                            icon="corporate_fare"
                            label="Organizations"
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
                                href={paths::ADMIN}
                                icon="admin_panel_settings"
                                label="Admin Overview"
                            />
                            <SidebarLink
                                href={paths::USERS}
                                icon="group"
                                label="Global Users"
                            />
                        </div>
                    </div>
                </Show>
            </nav>

            // Footer / Build Info
            <div class="border-t border-gray-100 dark:border-gray-800">
                <div class="mx-auto flex items-center justify-center px-4 py-2 font-mono text-gray-400">
                    <A
                        href=paths::HEALTH
                        attr:class="flex items-center gap-2 hover:text-gray-800 dark:hover:text-gray-300 transition-colors"
                    >
                        <span class="text-[10px]">{concat!("v", env!("CARGO_PKG_VERSION"))}</span>
                        <span class="text-[10px] mx-1">"|"</span>
                        <span
                            class="text-[10px]"
                            class:text-green-500=move || is_healthy.get()
                            class:text-red-500=move || !is_healthy.get()
                        >
                            "●"
                        </span>
                    </A>
                </div>
            </div>
        </aside>
    }
}

#[component]
fn SidebarLink(href: &'static str, icon: &'static str, label: &'static str) -> impl IntoView {
    let location = use_location();
    let is_active = move || location.pathname.get().starts_with(href);
    let active_1 = is_active.clone();
    let active_4 = is_active.clone();

    view! {
        <A
            href=move || href.to_string()
            {..}
            attr:class="group relative flex items-center gap-3 rounded-lg px-3 py-1 text-sm transition"
            class:bg-slate-200=move || active_1()
            class:text-slate-900=move || active_4()
            class:text-slate-700=move || !is_active()
            class:hover:bg-slate-50=move || !is_active()
            aria-current=move || if is_active() { Some("page") } else { None }
        >
            <Show when=move || is_active()>
                <span class="absolute -left-3 top-0.5 bottom-0.5 w-1 rounded bg-blue-600"></span>
            </Show>
            <span
                class=move || format!("{} text-xl", Theme::ICON)
                class:text-slate-700=move || is_active()
                class:text-slate-400=move || !is_active()
            >
                {icon}
            </span>
            {label}
        </A>
    }
}
