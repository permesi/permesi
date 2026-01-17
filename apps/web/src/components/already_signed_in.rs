use crate::{
    features::auth::{client, state::use_auth},
    routes::paths,
};
use leptos::{prelude::*, task::spawn_local};
use leptos_router::components::A;

/// Renders the signed-in state for auth routes (login/signup).
#[component]
pub fn AlreadySignedInPanel() -> impl IntoView {
    let auth = use_auth();
    let user_email =
        Signal::derive(move || auth.session.get().map(|s| s.email).unwrap_or_default());

    view! {
        <div class="max-w-sm mx-auto text-center space-y-6 py-8">
            <div class="flex justify-center">
                <div class="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-full">
                    <span class="material-symbols-outlined text-4xl text-blue-600 dark:text-blue-400">
                        "account_circle"
                    </span>
                </div>
            </div>
            <div class="space-y-2">
                <h2 class="text-xl font-bold text-gray-900 dark:text-white">
                    "Already Signed In"
                </h2>
                <p class="text-gray-500 dark:text-gray-400">
                    "You are currently signed in as "
                    <span class="font-medium text-gray-900 dark:text-gray-200">
                        {move || user_email.get()}
                    </span> "."
                </p>
            </div>
            <div class="flex flex-col gap-3">
                <A
                    href={paths::DASHBOARD}
                    {..}
                    class="w-full inline-flex justify-center items-center px-5 py-2.5 text-sm font-medium text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-all shadow-sm"
                >
                    "Go to Dashboard"
                </A>
                <button
                    on:click=move |_| {
                        let auth = auth.clone();
                        spawn_local(async move {
                            let _ = client::logout().await;
                            auth.clear_session();
                            if let Some(storage) = web_sys::window()
                                .and_then(|w| w.local_storage().ok())
                                .flatten()
                            {
                                let _ = storage.remove_item("permesi_logged_in");
                            }
                            if let Some(window) = web_sys::window() {
                                let _ = window.location().set_href("/");
                            }
                        });
                    }
                    class="w-full inline-flex justify-center items-center px-5 py-2.5 text-sm font-medium text-gray-900 bg-white border border-gray-200 rounded-lg hover:bg-gray-100 hover:text-blue-700 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600 dark:hover:text-white dark:hover:bg-gray-700 transition-all"
                >
                    "Sign Out"
                </button>
            </div>
        </div>
    }
}
