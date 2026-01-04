//! Account route for the authenticated user's profile.

use crate::{
    components::{Alert, AlertKind, AppShell, Spinner},
    features::{auth::guards::RequireAuth, me::client},
};
use leptos::prelude::*;

/// Renders the current user's profile.
#[component]
pub fn MePage() -> impl IntoView {
    let profile = LocalResource::new(move || async move { client::fetch_me().await });

    view! {
        <AppShell>
            <RequireAuth>
                <div class="block rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-300 dark:bg-neutral-600 space-y-4">
                    <h1 class="text-lg font-semibold text-gray-900 dark:text-white">
                        "Me"
                    </h1>
                    <Suspense fallback=move || view! { <Spinner /> }>
                        {move || match profile.get() {
                            Some(Ok(me)) => {
                                let display_name = me
                                    .display_name
                                    .clone()
                                    .unwrap_or_else(|| "Not set".to_string());
                                let role_list = if me.roles.is_empty() {
                                    "user".to_string()
                                } else {
                                    me.roles.join(", ")
                                };
                                view! {
                                    <div class="space-y-4">
                                        <div>
                                            <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                                "Email"
                                            </span>
                                            <div class="text-gray-900 dark:text-white">
                                                {me.email}
                                            </div>
                                        </div>
                                        <div>
                                            <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                                "Display name"
                                            </span>
                                            <div class="text-gray-900 dark:text-white">
                                                {display_name}
                                            </div>
                                        </div>
                                        <div>
                                            <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                                "Roles"
                                            </span>
                                            <div class="text-gray-900 dark:text-white">
                                                {role_list}
                                            </div>
                                        </div>
                                    </div>
                                }
                                .into_any()
                            }
                            Some(Err(err)) => {
                                view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                                    .into_any()
                            }
                            None => view! { <Spinner /> }.into_any(),
                        }}
                    </Suspense>
                </div>
            </RequireAuth>
        </AppShell>
    }
}
