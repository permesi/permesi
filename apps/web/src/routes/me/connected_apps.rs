//! Self-service view of OAuth consent granted by the current user.
//!
//! Flow Overview: Fetch server-filtered, tenant-bound grants in bounded pages.
//! Revocation uses a dedicated confirmation dialog and the server rechecks
//! session identity before permanently changing the grant. Browser state never
//! selects a user, organization or additional delegated scope.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Spinner, ui::Dialog},
    features::me::{
        client,
        types::{SavedGrant, SavedGrantPage},
    },
};
use leptos::prelude::*;

/// Shows active saved grants and lets the current user revoke one at a time.
#[component]
pub fn ConnectedAppsPage() -> impl IntoView {
    let cursor = RwSignal::new(None::<String>);
    let history = RwSignal::new(Vec::<Option<String>>::new());
    let grants: LocalResource<Result<SavedGrantPage, AppError>> = LocalResource::new(move || {
        let after = cursor.get();
        async move { client::list_oauth_grants(after.as_deref()).await }
    });

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">"Connected apps"</h1>
                <p class="mt-2 text-sm text-gray-600 dark:text-gray-300">
                    "Review the OAuth access you granted to applications in each organization."
                </p>
            </div>
            <Suspense fallback=|| view! { <Spinner /> }>
                {move || match grants.get() {
                    Some(Ok(page)) => {
                        let next_cursor = page.next_cursor.clone();
                        let empty = page.grants.is_empty();
                        view! {
                            <div class="space-y-4">
                                {empty.then(|| view! {
                                    <p class="rounded-lg border border-gray-200 bg-white p-5 text-sm text-gray-600 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300">
                                        "No saved application access on this page."
                                    </p>
                                })}
                                {page.grants.into_iter().map(|grant| view! {
                                    <GrantCard grant refresh=grants />
                                }).collect_view()}
                                <nav aria-label="Connected apps pages" class="flex items-center gap-3">
                                    <button type="button"
                                        class="cursor-pointer rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-800"
                                        disabled=move || history.get().is_empty()
                                        on:click=move |_| {
                                            if let Some(previous) = history.get_untracked().last().cloned() {
                                                history.update(|items| { items.pop(); });
                                                cursor.set(previous);
                                            }
                                        }>"Previous"</button>
                                    {next_cursor.map(|next| view! {
                                        <button type="button"
                                            class="cursor-pointer rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-800"
                                            on:click=move |_| {
                                                history.update(|items| items.push(cursor.get_untracked()));
                                                cursor.set(Some(next.clone()));
                                            }>"Next"</button>
                                    })}
                                </nav>
                            </div>
                        }.into_any()
                    }
                    Some(Err(err)) => view! {
                        <Alert kind=AlertKind::Error message=err.to_string() />
                    }.into_any(),
                    None => view! { <Spinner /> }.into_any(),
                }}
            </Suspense>
        </div>
    }
}

/// Displays one exact client/organization grant and owns its revoke confirmation.
#[component]
fn GrantCard(
    grant: SavedGrant,
    refresh: LocalResource<Result<SavedGrantPage, AppError>>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let id = StoredValue::new(grant.id.clone());
    let client_name = grant.client_name.clone();
    let revoke = Action::new_local(move |(): &()| {
        let id = id.get_value();
        async move { client::revoke_oauth_grant(&id).await }
    });
    Effect::new(move |_| {
        if let Some(result) = revoke.value().get() {
            match result {
                Ok(()) => {
                    open.set(false);
                    refresh.refetch();
                }
                Err(err) => error.set(err.to_string()),
            }
        }
    });
    view! {
        <article class="rounded-xl border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <div class="flex flex-wrap items-start justify-between gap-4">
                <div class="min-w-0 space-y-1">
                    <h2 class="break-words text-base font-semibold text-gray-900 dark:text-white">{grant.client_name}</h2>
                    <p class="text-sm text-gray-600 dark:text-gray-300">{grant.application_name}</p>
                    <p class="text-sm text-gray-600 dark:text-gray-300">
                        {format!("Organization: {} ({})", grant.organization_name, grant.organization_slug)}
                    </p>
                    <p class="break-all font-mono text-xs text-gray-500 dark:text-gray-400">
                        {format!("Client ID: {}", grant.client_id)}
                    </p>
                    <p class="text-xs text-gray-500 dark:text-gray-400">
                        {format!("Granted: {}", grant.created_at)}
                    </p>
                </div>
                <button type="button"
                    class="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-red-300 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50 focus:ring-2 focus:ring-red-500 dark:border-red-800 dark:text-red-300 dark:hover:bg-red-900/20"
                    on:click=move |_| { error.set(String::new()); open.set(true); }>
                    <span class="material-symbols-outlined text-base" aria-hidden="true">"link_off"</span>
                    "Revoke access"
                </button>
            </div>
            <div class="mt-4">
                <p class="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">"Granted OAuth scopes"</p>
                <div class="mt-2 flex flex-wrap gap-2">
                    {grant.scopes.into_iter().map(|scope| view! {
                        <span class="rounded-full bg-blue-50 px-2.5 py-1 font-mono text-xs text-blue-800 dark:bg-blue-900/30 dark:text-blue-200">{scope}</span>
                    }).collect_view()}
                </div>
            </div>
            <Dialog id=format!("revoke-oauth-grant-{}", grant.id) title="Revoke application access" icon="link_off" open=open busy=revoke.pending()>
                <form class="space-y-4" on:submit=move |event| {
                    event.prevent_default();
                    if !revoke.pending().get_untracked() { revoke.dispatch(()); }
                }>
                    <p class="text-sm text-gray-700 dark:text-gray-200">
                        {format!("Revoke saved access for {client_name}?")}
                    </p>
                    <p class="text-sm text-gray-600 dark:text-gray-300">
                        "This stops new code redemptions and refreshes under this consent. Already-issued access tokens remain valid until they expire."
                    </p>
                    {move || (!error.get().is_empty()).then(|| view! {
                        <Alert kind=AlertKind::Error message=error.get() />
                    })}
                    <div class="flex justify-end gap-3">
                        <button type="button" disabled=move || revoke.pending().get()
                            class="cursor-pointer rounded-lg border border-gray-300 px-4 py-2 text-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:hover:bg-gray-700"
                            on:click=move |_| open.set(false)>"Cancel"</button>
                        <button type="submit" disabled=move || revoke.pending().get()
                            class="cursor-pointer rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50">
                            {move || if revoke.pending().get() { "Revoking…" } else { "Revoke access" }}
                        </button>
                    </div>
                </form>
            </Dialog>
        </article>
    }
}
