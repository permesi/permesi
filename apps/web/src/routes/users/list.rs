//! Users list route guarded by the auth gate. Wrapping rows keep account names
//! readable on narrow screens; authorization remains enforced by the backend.

use crate::{
    components::{Alert, AlertKind, EmptyValue, Icon, IconName, Spinner, icon_size},
    features::{auth::RequireAdmin, users::client},
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders the users list view and fetches data on mount.
#[component]
pub fn UsersListPage() -> impl IntoView {
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

                <UsersTable />
            </div>
        } />
    }
}

/// Loads the platform user table inside the existing administrator gate.
#[component]
fn UsersTable() -> impl IntoView {
    let users = LocalResource::new(move || async move { client::list_users().await });
    view! {
                <div class="flex justify-end">
                    <button type="button" on:click=move |_| users.refetch()
                        class="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-800">
                        <Icon name=IconName::Refresh size=icon_size::INLINE />
                        "Refresh"
                    </button>
                </div>
                <div class="overflow-x-auto bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                    <table class="w-full table-fixed divide-y divide-gray-200 dark:divide-gray-700">
                        <thead class="bg-gray-50 dark:bg-gray-900/50">
                            <tr>
                                <th scope="col" class="w-1/2 px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 sm:px-6">
                                    "Email"
                                </th>
                                <th scope="col" class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 sm:px-6">
                                    "Display Name"
                                </th>
                                <th scope="col" class="w-20 px-3 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 sm:w-24 sm:px-6">
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
                                                    let display_name = user.display_name.clone();
                                                    view! {
                                                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                                                            <td class="min-w-0 break-words px-3 py-4 text-sm font-medium text-gray-900 dark:text-white sm:px-6">
                                                                <A
                                                                    href={paths::user_detail(&user.id)}
                                                                    {..}
                                                                    class="inline-flex min-w-0 cursor-pointer items-start gap-2 rounded hover:text-blue-600 focus-visible:ring-2 focus-visible:ring-blue-500 dark:hover:text-blue-400"
                                                                >
                                                                    <Icon name=IconName::Person size=icon_size::INLINE class="mt-0.5 text-gray-400 dark:text-gray-500" />
                                                                    <span class="min-w-0 break-words">{user.email}</span>
                                                                </A>
                                                            </td>
                                                            <td class="min-w-0 break-words px-3 py-4 text-sm text-gray-500 dark:text-gray-400 sm:px-6">
                                                                {display_name.map_or_else(|| view! { <EmptyValue /> }.into_any(), IntoAny::into_any)}
                                                            </td>
                                                            <td class="px-3 py-4 text-right text-sm font-medium sm:px-6">
                                                                <A
                                                                    href={paths::user_detail(&user.id)}
                                                                    {..}
                                                                    class="cursor-pointer rounded text-gray-600 hover:text-gray-900 focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-gray-400 dark:hover:text-white"
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
    }
}
