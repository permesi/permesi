//! Shared layout wrapper with navigation and content container. It centralizes
//! header markup and the mobile menu toggle so routes can focus on content.
//! Navigation remains client-side; backend routes must enforce access control.

use crate::features::auth::{client, state::use_auth};
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{components::A, hooks::use_location};

fn breadcrumb_label(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return "Dashboard".to_string();
    }

    match path {
        "/login" => return "Sign In".to_string(),
        "/signup" => return "Sign Up".to_string(),
        "/verify-email" => return "Verify Email".to_string(),
        "/health" => return "Health".to_string(),
        "/me" => return "Me".to_string(),
        "/users" => return "Users".to_string(),
        _ => {}
    }

    if let Some(rest) = path.strip_prefix("/users/") {
        if !rest.is_empty() {
            return "User".to_string();
        }
    }

    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return "Dashboard".to_string();
    }

    trimmed
        .split('/')
        .last()
        .unwrap_or("Page")
        .split('-')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
    let location = use_location();
    let on_login = move || location.pathname.get() == "/login";
    let breadcrumb = Signal::derive(move || breadcrumb_label(&location.pathname.get()));
    let user_info = Signal::derive(move || {
        auth.session
            .get()
            .map(|session| (session.user_id.clone(), session.email.clone()))
    });

    view! {
        <div class="min-h-screen flex flex-col">
            <header class="border-b border-gray-200 bg-[#f6f8fa] dark:bg-gray-900">
                <div class="w-full flex flex-wrap items-center gap-4 px-4 py-3">
                    <A
                        href="/"
                        {..}
                        class="flex items-center space-x-2 rtl:space-x-reverse"
                        on:click=move |_| set_menu_open.set(false)
                    >
                        <img src="/logo.svg" class="h-8" alt="permesi" />
                        <span class="font-semibold whitespace-nowrap text-gray-900 dark:text-white">
                            "Permesi"
                        </span>
                        <Show when=move || is_authenticated.get()>
                            <span class="text-sm text-gray-400 dark:text-gray-500">"/"</span>
                            <span class="text-sm font-medium text-gray-700 dark:text-gray-200">
                                {move || breadcrumb.get()}
                            </span>
                        </Show>
                    </A>
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
                                                            href="/login"
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
                                                    href="/signup"
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
                                            user_info
                                                .get()
                                                .map(|(_user_id, email)| {
                                                    view! {
                                                        <A
                                                            href="/me"
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
                                        }}
                                        <button
                                            type="button"
                                            class="inline-flex items-center gap-1 text-sm font-medium text-gray-700 hover:text-black dark:text-gray-200 dark:hover:text-white cursor-pointer"
                                            on:click=move |_| {
                                                spawn_local(async move {
                                                    let _ = client::logout().await;
                                                    auth.clear_session();
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
            <main class="flex-1">
                <div class="w-full">
                    <div class="max-w-screen-xl mx-auto px-4 py-6">
                        {children()}
                    </div>
                </div>
            </main>
        </div>
    }
}
