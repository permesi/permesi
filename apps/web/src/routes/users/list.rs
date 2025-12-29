use crate::components::{Alert, AlertKind, AppShell, Spinner};
use crate::features::auth::guards::RequireAuth;
use crate::features::users::client;
use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn UsersListPage() -> impl IntoView {
    let users = LocalResource::new(move || async move { client::list_users().await });

    view! {
        <AppShell>
            <RequireAuth>
                <div class="block rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-300 dark:bg-neutral-600 space-y-4">
                    <h1 class="text-lg font-semibold text-gray-900 dark:text-white">"Users"</h1>
                    <Suspense fallback=move || view! { <Spinner /> }>
                        {move || match users.get() {
                            Some(Ok(list)) if list.is_empty() => {
                                view! {
                                    <p class="text-sm text-gray-500 dark:text-gray-200">
                                        "No users found."
                                    </p>
                                }
                                .into_any()
                            }
                            Some(Ok(list)) => {
                                let rows = list
                                    .into_iter()
                                    .map(|user| {
                                        view! {
                                            <li>
                                                <A
                                                    href=format!("/users/{}", user.id)
                                                    {..}
                                                    class="text-blue-700 hover:text-blue-800 dark:text-blue-200"
                                                >
                                                    {user.email}
                                                </A>
                                            </li>
                                        }
                                    })
                                    .collect_view();

                                view! { <ul class="space-y-2">{rows}</ul> }.into_any()
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
