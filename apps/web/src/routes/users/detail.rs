use crate::app_lib::AppError;
use crate::components::{Alert, AlertKind, AppShell, Spinner};
use crate::features::auth::guards::RequireAuth;
use crate::features::users::client;
use leptos::prelude::*;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;

#[derive(Params, PartialEq, Clone)]
struct UserParams {
    id: Option<String>,
}

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
            <RequireAuth>
                <div class="block rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-300 dark:bg-neutral-600 space-y-4">
                    <h1 class="text-lg font-semibold text-gray-900 dark:text-white">
                        "User detail"
                    </h1>
                    <Suspense fallback=move || view! { <Spinner /> }>
                        {move || match user.get() {
                            Some(Ok(detail)) => {
                                let display_name = detail
                                    .display_name
                                    .clone()
                                    .unwrap_or_else(|| "Unknown".to_string());
                                view! {
                                    <div class="space-y-4">
                                        <div>
                                            <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                                "ID"
                                            </span>
                                            <div class="text-gray-900 dark:text-white">
                                                {detail.id}
                                            </div>
                                        </div>
                                        <div>
                                            <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                                "Email"
                                            </span>
                                            <div class="text-gray-900 dark:text-white">
                                                {detail.email}
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
