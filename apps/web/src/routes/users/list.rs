//! Users list route guarded by the auth gate. It keeps the list view minimal
//! and relies on the backend for authorization.

use crate::{
    components::{Alert, AlertKind, Spinner},
    features::{auth::RequireAdmin, users::client},
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders the users list view and fetches data on mount.
#[component]
pub fn UsersListPage() -> impl IntoView {
    let users = LocalResource::new(move || async move { client::list_users().await });

    view! {
        <RequireAdmin children=move || view! {
            <div class="space-y-6">
                <div class="flex items-center justify-between">
                    <div class="space-y-1">
                        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                            "Users"
                        </h1>
                        <p class="text-sm text-gray-500 dark:text-gray-400">
                            "View and manage all registered platform users."
                        </p>
                    </div>
                </div>

                <div class="overflow-hidden bg-white dark:bg-gray-800 shadow-sm border border-gray-200 dark:border-gray-700 rounded-lg">
                    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead class="bg-gray-50 dark:bg-gray-900/50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                    "Email"
                                </th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                    "Display Name"
                                </th>
                                <th scope="col" class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                    "Actions"
                                </th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                            <Suspense fallback=move || view! {
                                <tr>
                                    <td colspan="3" class="px-6 py-12 text-center">
                                        <Spinner />
                                    </td>
                                </tr>
                            }>
                                {move || match users.get() {
                                    Some(Ok(list)) if list.is_empty() => {
                                        view! {
                                            <tr>
                                                <td colspan="3" class="px-6 py-12 text-center text-sm text-gray-500 dark:text-gray-400">
                                                    "No users found."
                                                </td>
                                            </tr>
                                        }.into_any()
                                    }
                                    Some(Ok(list)) => {
                                        view! {
                                            <For
                                                each=move || list.clone()
                                                key=|user| user.id.clone()
                                                children=|user| {
                                                    let display_name = user.display_name.clone().unwrap_or_else(|| "-".to_string());
                                                    view! {
                                                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                                                                <A
                                                                    href={paths::user_detail(&user.id)}
                                                                    {..}
                                                                    class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                                                >
                                                                    {user.email}
                                                                </A>
                                                            </td>
                                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                                                {display_name}
                                                            </td>
                                                            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                                <A
                                                                    href={paths::user_detail(&user.id)}
                                                                    {..}
                                                                    class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                                                >
                                                                    "View"
                                                                </A>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        }.into_any()
                                    }
                                    Some(Err(err)) => {
                                        view! {
                                            <tr>
                                                <td colspan="3" class="px-6 py-4">
                                                    <Alert kind=AlertKind::Error message=err.to_string() />
                                                </td>
                                            </tr>
                                        }.into_any()
                                    }
                                    None => view! {
                                        <tr>
                                            <td colspan="3" class="px-6 py-12 text-center">
                                                <Spinner />
                                            </td>
                                        </tr>
                                    }.into_any(),
                                }}
                            </Suspense>
                        </tbody>
                    </table>
                </div>
            </div>
        } />
    }
}
