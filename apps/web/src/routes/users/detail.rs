//! User detail route guarded by the auth gate. It fetches a single user record
//! by id and relies on the backend for authorization.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, AppShell, Button, Spinner},
    features::{auth::RequireAdmin, users::client},
};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params, params::Params};

/// Typed route params for `/users/:id`.
#[derive(Params, PartialEq, Clone)]
struct UserParams {
    id: Option<String>,
}

/// Renders the user detail view and fetches data by id.
#[component]
pub fn UserDetailPage() -> impl IntoView {
    let params = use_params::<UserParams>();
    let params_for_fetch = params;
    let user = LocalResource::new(move || {
        let id = params_for_fetch
            .get()
            .ok()
            .and_then(|params| params.id)
            .unwrap_or_default();
        async move {
            if id.trim().is_empty() {
                return Err(AppError::Config("User id is required.".to_string()));
            }

            client::get_user(&id).await
        }
    });

    let params_for_effect = params;
    Effect::new(move |_| {
        let _ = params_for_effect.get();
        user.refetch();
    });

    view! {
        <AppShell>
            <RequireAdmin children=move || view! {
                <div class="space-y-6">
                    <div class="flex items-center gap-4">
                        <A
                            href="/users"
                            {..}
                            class="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                        >
                            <span class="material-symbols-outlined text-2xl">"arrow_back"</span>
                        </A>
                        <div class="space-y-1">
                            <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                                "User Detail"
                            </h1>
                            <p class="text-sm text-gray-500 dark:text-gray-400">
                                "Viewing detailed profile and metadata for this user."
                            </p>
                        </div>
                    </div>

                    <Suspense fallback=move || view! { <Spinner /> }.into_any()>
                        {move || match user.get() {
                            Some(Ok(detail)) => {
                                let display_name = detail.display_name.clone().unwrap_or_else(|| "Not set".to_string());
                                                                let locale = detail.locale.clone().unwrap_or_else(|| "Default".to_string());
                                                                let role = detail.role.clone().unwrap_or_else(|| "none".to_string());

                                                                view! {
                                                                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                                                                        <div class="lg:col-span-2 space-y-6">
                                                                            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
                                                                                <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-900/20">
                                                                                    <h2 class="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">
                                                                                        "Profile Information"
                                                                                    </h2>
                                                                                </div>
                                                                                <div class="p-6 space-y-6">
                                                                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-6">
                                                                                        <div>
                                                                                            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">"Email Address"</label>
                                                                                            <div class="mt-1 text-sm font-medium text-gray-900 dark:text-white">{detail.email}</div>
                                                                                        </div>
                                                                                        <div>
                                                                                            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">"Display Name"</label>
                                                                                            <div class="mt-1 text-sm text-gray-900 dark:text-white">{display_name}</div>
                                                                                        </div>
                                                                                        <div>
                                                                                            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">"Locale"</label>
                                                                                            <div class="mt-1 text-sm text-gray-900 dark:text-white">{locale}</div>
                                                                                        </div>
                                                                                                                                                <div>
                                                                                                                                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">"Internal ID"</label>
                                                                                                                                                    <div class="mt-1 text-xs font-mono text-gray-500 dark:text-gray-400">{detail.id.clone()}</div>
                                                                                                                                                </div>                                                                                    </div>
                                                                                </div>
                                                                            </div>

                                                                            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
                                                                                <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-900/20">
                                                                                    <h2 class="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">
                                                                                        "Platform Role"
                                                                                    </h2>
                                                                                </div>
                                                                                <div class="p-6">
                                                                                    <RoleManager
                                                                                        user_id=detail.id.clone()
                                                                                        current_role=role
                                                                                        on_success=Callback::new(move |_| user.refetch())
                                                                                    />
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                        <div class="space-y-6">
                                            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
                                                <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-900/20">
                                                    <h2 class="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">
                                                        "Metadata"
                                                    </h2>
                                                </div>
                                                <div class="p-6 space-y-4">
                                                    <div>
                                                        <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">"Joined"</label>
                                                        <div class="mt-1 text-xs text-gray-900 dark:text-white">{detail.created_at}</div>
                                                    </div>
                                                    <div>
                                                        <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">"Last Updated"</label>
                                                        <div class="mt-1 text-xs text-gray-900 dark:text-white">{detail.updated_at}</div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                }.into_any()
                            }
                            Some(Err(err)) => {
                                view! { <Alert kind=AlertKind::Error message=err.to_string() /> }.into_any()
                            }
                            None => view! { <Spinner /> }.into_any(),
                        }}
                    </Suspense>
                </div>
            } />
        </AppShell>
    }
}

#[component]
fn RoleManager(user_id: String, current_role: String, on_success: Callback<()>) -> impl IntoView {
    let (selected_role, set_selected_role) = signal(current_role.clone());
    let (error, set_error) = signal::<Option<AppError>>(None);

    let update_action = Action::new_local(move |(id, role): &(String, String)| {
        let id = id.clone();
        let role = role.clone();
        async move { client::set_user_role(&id, &role).await }
    });

    Effect::new(move |_| {
        if let Some(result) = update_action.value().get() {
            match result {
                Ok(()) => {
                    set_error.set(None);
                    on_success.run(());
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let roles = vec!["owner", "admin", "editor", "member"];

    view! {
        <div class="space-y-4">
            <div class="flex flex-col sm:flex-row sm:items-center gap-4">
                <select
                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full sm:w-64 p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                    on:change=move |ev| set_selected_role.set(event_target_value(&ev))
                >
                    <option value="none" selected=move || selected_role.get() == "none" disabled=true>
                        "Select a role..."
                    </option>
                    {roles.into_iter().map(|r| {
                        let r_val = r.to_string();
                        view! {
                            <option value=r_val.clone() selected=move || selected_role.get() == r_val>
                                {r.to_uppercase()}
                            </option>
                        }
                    }).collect_view()}
                </select>

                <Button
                    disabled=move || update_action.pending().get() || selected_role.get() == current_role || selected_role.get() == "none"
                    on_click=move |_| {
                        update_action.dispatch((user_id.clone(), selected_role.get_untracked()));
                    }
                >
                    {move || if update_action.pending().get() { "Updating..." } else { "Update Role" }}
                </Button>
            </div>

            <Show when=move || error.get().is_some()>
                <Alert kind=AlertKind::Error message=error.get().unwrap().to_string() />
            </Show>

            <p class="text-xs text-gray-500">
                "Warning: Changing platform roles affects global permissions for this user."
            </p>
        </div>
    }
}
