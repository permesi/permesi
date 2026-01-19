//! Shared layout wrapper with navigation and content container. It centralizes
//! header markup and the mobile menu toggle so routes can focus on content.
//! Navigation remains client-side; backend routes must enforce access control.

use crate::components::layout::Sidebar;
use crate::features::auth::{client, state::use_auth};
use crate::routes::paths;
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{components::A, hooks::use_location};

fn breadcrumbs(path: &str) -> Vec<String> {
    // Strip the /console prefix for breadcrumb matching
    let path = path.strip_prefix("/console").unwrap_or(path);

    if path == "/" || path.is_empty() || path == "/dashboard" {
        return vec!["Dashboard".to_string()];
    }

    match path {
        "/me" => return vec!["Me".to_string()],
        "/orgs" => return vec!["Organizations".to_string()],
        "/users" => return vec!["Users".to_string()],
        "/admin" => return vec!["Admin".to_string()],
        "/admin/claim" => return vec!["Admin".to_string(), "Claim".to_string()],
        // Public routes usually don't have AppShell, but for completeness:
        "/login" => return vec!["Sign In".to_string()],
        "/signup" => return vec!["Sign Up".to_string()],
        "/verify-email" => return vec!["Verify Email".to_string()],
        "/health" => return vec!["Health".to_string()],
        _ => {}
    }

    if let Some(rest) = path.strip_prefix("/orgs/") {
        if !rest.is_empty() {
            let mut segments = vec!["Organizations".to_string()];
            let parts: Vec<&str> = rest.split('/').collect();
            if let Some(org_slug) = parts.get(0) {
                segments.push(org_slug.to_string());
            }
            if parts.get(1) == Some(&"projects") {
                segments.push("Projects".to_string());
                if let Some(project_slug) = parts.get(2) {
                    segments.push(project_slug.to_string());
                }
            }
            return segments;
        }
    }

    if let Some(rest) = path.strip_prefix("/users/") {
        if !rest.is_empty() {
            return vec!["Users".to_string(), "User".to_string()];
        }
    }

    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|segment| {
            segment
                .split('-')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let mut chars = s.chars();
                    match chars.next() {
                        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// Wraps routes with a header and main content container.
#[component]
pub fn AppShell(children: Children) -> impl IntoView {
    let (menu_open, set_menu_open) = signal(false);
    let toggle_menu = move |_| {
        set_menu_open.update(|open| *open = !*open);
    };
    let auth = use_auth();
    let is_authenticated = auth.is_authenticated;
    let is_full_session = auth.is_full_session;
    let location = use_location();
    let on_login = move || location.pathname.get() == paths::LOGIN;
    let breadcrumb_segments = Memo::new(move |_| breadcrumbs(&location.pathname.get()));
    let user_info = Signal::derive(move || {
        auth.session
            .get()
            .map(|session| (session.user_id.clone(), session.email.clone()))
    });

    view! {
        <div class="min-h-screen flex flex-col bg-white dark:bg-gray-900">
            <header class="border-b border-gray-200 bg-[#f6f8fa] dark:bg-gray-900 z-30">
                <div class="w-full flex flex-wrap items-center gap-4 px-4 py-3">
                    {move || {
                        let target = if is_authenticated.get() { paths::DASHBOARD } else { paths::LANDING };
                        view! {
                            <A
                                href=target.to_string()
                                attr:class="flex items-center space-x-2 rtl:space-x-reverse"
                                on:click=move |_| set_menu_open.set(false)
                            >
                                <img src="/logo.svg" class="h-8 dark:invert" alt="permesi" />
                                <span class="font-semibold whitespace-nowrap text-gray-900 dark:text-white">
                                    "Permesi"
                                </span>
                                <Show when=move || is_full_session.get()>
                                    <For
                                        each=move || breadcrumb_segments.get().into_iter().enumerate()
                                        key=|(_, segment)| segment.clone()
                                        children=move |(_, segment)| {
                                            view! {
                                                <span class="text-sm text-gray-400 dark:text-gray-500">"/"</span>
                                                <span class="text-sm font-medium text-gray-700 dark:text-gray-200">
                                                    {segment}
                                                </span>
                                            }
                                        }
                                    />
                                </Show>
                            </A>
                        }
                    }}
                    <button
                        type="button"
                        class="ml-auto inline-flex items-center p-2 w-10 h-10 justify-center text-sm text-gray-500 rounded-lg md:hidden hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-gray-200 dark:text-gray-400 dark:hover:bg-gray-700 dark:focus:ring-gray-600"
                        data-collapse-toggle="navbar-default"
                        aria-controls="navbar-default"
                        aria-expanded=move || menu_open.get().to_string()
                        on:click=toggle_menu
                    >
                        <span class="sr-only">"Open main menu"</span>
                        <svg
                            class="w-5 h-5"
                            aria-hidden="true"
                            xmlns="http://www.w3.org/2000/svg"
                            fill="none"
                            viewBox="0 0 17 14"
                        >
                            <path
                                stroke="currentColor"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                stroke-width="2"
                                d="M1 1h15M1 7h15M1 13h15"
                            ></path>
                        </svg>
                    </button>
                    <div
                        id="navbar-default"
                        class="w-full md:ml-auto md:block md:w-auto"
                        class:hidden=move || !menu_open.get()
                    >
                        <ul class="flex flex-col gap-2 p-4 md:flex-row md:items-center md:gap-6 md:p-0">
                            <li>
                                <Show
                                    when=move || is_authenticated.get()
                                    fallback=move || {
                                        view! {
                                            <Show
                                                when=on_login
                                                fallback=move || {
                                                    view! {
                                                        <A
                                                            href={paths::LOGIN}
                                                            {..}
                                                            class="block py-2 text-sm font-medium text-gray-700 hover:text-black md:p-0 dark:text-gray-200 dark:hover:text-white cursor-pointer"
                                                            on:click=move |_| set_menu_open.set(false)
                                                        >
                                                            "Sign In"
                                                        </A>
                                                    }
                                                }
                                            >
                                                <A
                                                    href={paths::SIGNUP}
                                                    {..}
                                                    class="block py-2 text-sm font-medium text-gray-700 hover:text-black md:p-0 dark:text-gray-200 dark:hover:text-white cursor-pointer"
                                                    on:click=move |_| set_menu_open.set(false)
                                                >
                                                    "Sign Up"
                                                </A>
                                            </Show>
                                        }
                                    }
                                >
                                    <div class="flex flex-col gap-2 md:flex-row md:items-center md:gap-3">
                                        {move || {
                                            if is_full_session.get() {
                                                user_info.get().map(|(_user_id, email)| {
                                                    view! {
                                                        <A
                                                            href={paths::ME}
                                                            {..}
                                                            class="text-sm font-medium text-gray-700 hover:text-black dark:text-gray-200 dark:hover:text-white cursor-pointer"
                                                            on:click=move |_| set_menu_open.set(false)
                                                        >
                                                            {email}
                                                        </A>
                                                        <span class="hidden md:inline text-gray-300 dark:text-gray-600">
                                                            "|"
                                                        </span>
                                                    }
                                                })
                                            } else {
                                                None
                                            }
                                        }}
                                        <button
                                            type="button"
                                            class="inline-flex items-center gap-1 text-sm font-medium text-gray-700 hover:text-black dark:text-gray-200 dark:hover:text-white cursor-pointer"
                                            on:click=move |_| {
                                                spawn_local(async move {
                                                    let _ = client::logout().await;
                                                    auth.clear_session();
                                                    if let Some(window) = web_sys::window() {
                                                        let _ = window.location().set_href("/");
                                                    }
                                                });
                                                set_menu_open.set(false);
                                            }
                                        >
                                            "Sign Out"
                                            <span class="material-symbols-outlined text-base">
                                                "logout"
                                            </span>
                                        </button>
                                    </div>
                                </Show>
                            </li>
                        </ul>
                    </div>
                </div>
            </header>

            <div class="flex flex-1 overflow-hidden">
                <Show when=move || is_full_session.get()>
                    <Sidebar />
                </Show>

                <main class="flex-1 overflow-y-auto">
                    <div class="max-w-screen-xl mx-auto px-4 py-6">
                        {children()}
                    </div>
                </main>
            </div>
        </div>
    }
}
