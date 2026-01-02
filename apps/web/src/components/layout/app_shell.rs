//! Shared layout wrapper with navigation and content container. It centralizes
//! header markup and the mobile menu toggle so routes can focus on content.
//! Navigation remains client-side; backend routes must enforce access control.

use crate::features::auth::{client, state::use_auth};
use leptos::{prelude::*, task::spawn_local};
use leptos_router::{components::A, hooks::use_location};

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

    view! {
        <div class="min-h-screen flex flex-col">
            <header class="border-gray-200 dark:bg-gray-900">
                <div class="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
                    <A
                        href="/"
                        {..}
                        class="flex items-center space-x-3 rtl:space-x-reverse"
                        on:click=move |_| set_menu_open.set(false)
                    >
                        <img src="/logo.svg" class="h-8" alt="permesi" />
                        <span class="font-semibold whitespace-nowrap dark:text-white">
                            "Permesi"
                        </span>
                    </A>
                    <button
                        type="button"
                        class="inline-flex items-center p-2 w-10 h-10 justify-center text-sm text-gray-500 rounded-lg md:hidden hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-gray-200 dark:text-gray-400 dark:hover:bg-gray-700 dark:focus:ring-gray-600"
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
                        class="w-full md:block md:w-auto"
                        class:hidden=move || !menu_open.get()
                    >
                        <ul class="font-medium flex flex-col p-4 md:p-0 mt-4 border border-gray-100 rounded-lg bg-gray-50 md:flex-row md:space-x-8 rtl:space-x-reverse md:mt-0 md:border-0 md:bg-white dark:bg-gray-800 md:dark:bg-gray-900 dark:border-gray-700">
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
                                                            class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:border-0 md:hover:text-blue-700 md:p-0 dark:text-white md:dark:hover:text-blue-500 dark:hover:bg-gray-700 dark:hover:text-white md:dark:hover:bg-transparent"
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
                                                    class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:border-0 md:hover:text-blue-700 md:p-0 dark:text-white md:dark:hover:text-blue-500 dark:hover:bg-gray-700 dark:hover:text-white md:dark:hover:bg-transparent"
                                                    on:click=move |_| set_menu_open.set(false)
                                                >
                                                    "Sign Up"
                                                </A>
                                            </Show>
                                        }
                                    }
                                >
                                    <button
                                        type="button"
                                        class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:border-0 md:hover:text-blue-700 md:p-0 dark:text-white md:dark:hover:text-blue-500 dark:hover:bg-gray-700 dark:hover:text-white md:dark:hover:bg-transparent"
                                        on:click=move |_| {
                                            spawn_local(async move {
                                                let _ = client::logout().await;
                                                auth.clear_session();
                                            });
                                            set_menu_open.set(false);
                                        }
                                    >
                                        "Sign Out"
                                    </button>
                                </Show>
                            </li>
                        </ul>
                    </div>
                </div>
            </header>
            <main class="flex-1">
                <div class="container mx-auto p-4 mt-6">
                    {children()}
                </div>
            </main>
        </div>
    }
}
