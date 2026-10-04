//! Application delegated scope registry and immutable system entries.
//!
//! Only server-classified application scopes receive edit/delete controls. Names
//! remain immutable; descriptions can change. Deletion removes client/grant edges,
//! so it requires explicit typed confirmation rather than a browser confirm call.

use super::common::{
    CARD, EmptyState, FormError, INPUT, LABEL, Loading, OAuthNav, SECONDARY, application_context,
    error_message,
};
use crate::{
    components::{Alert, AlertKind, Button, ui::Dialog},
    features::oauth::{
        client,
        model::{NO_APPLICATION_SCOPES, application_scopes_empty},
        paths::ApplicationPaths,
        scope::{ApplicationScopeParts, compose_application_scope},
        types::{CreateScopeRequest, ScopeResponse},
    },
};
use leptos::prelude::*;

/// Displays the registry without confusing delegated scopes with platform capabilities.
#[component]
pub fn ScopesPage() -> impl IntoView {
    let Some(context) = application_context() else {
        return view! { <Alert kind=AlertKind::Error message="Application unavailable.".to_owned() /> }.into_any();
    };
    let paths = context.paths;
    let fetch_path = paths.clone();
    let scopes = LocalResource::new(move || {
        let path = fetch_path.clone();
        async move { client::list_scopes(&path).await }
    });
    let changed = Callback::new(move |()| scopes.refetch());
    view! { <div class="space-y-6"><OAuthNav paths=paths.clone() />
        <div class="flex flex-wrap items-center justify-between gap-4"><h2 class="text-xl font-semibold">"OAuth Scopes"</h2><CreateScopeDialog paths=paths.clone() changed=changed /></div>
        <p class="text-sm text-gray-500 dark:text-gray-400">"Delegated scopes describe what clients may request for this application. They are separate from Permesi administrator permissions. System OIDC scopes are read-only. Organization owners and admins can manage application scopes."</p>
        <Suspense fallback=|| view! { <Loading message="Loading OAuth scopes…" /> }>
            {move || match scopes.get() {
                Some(Ok(items)) => {
                    let no_application_scopes = application_scopes_empty(&items);
                    view! { <div class="space-y-4">
                        <Show when=move || no_application_scopes><EmptyState title=NO_APPLICATION_SCOPES message="Create delegated API scopes such as jobs:read. OIDC protocol scopes are provided by the server." /></Show>
                        {items.into_iter().map(|scope| view! { <ScopeRow paths=paths.clone() scope=scope changed=changed /> }).collect_view()}
                    </div> }.into_any()
                },
                Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
                None => view! { <Loading message="Loading OAuth scopes…" /> }.into_any(),
            }}
        </Suspense>
    </div> }.into_any()
}

/// Shows system entries as immutable metadata; only application entries have controls.
#[component]
fn ScopeRow(paths: ApplicationPaths, scope: ScopeResponse, changed: Callback<()>) -> impl IntoView {
    let editable = scope.editable();
    let semantics = ApplicationScopeParts::from_scope(&scope).map(|parts| {
        let resource = parts.resource.to_owned();
        let action = parts.action.to_owned();
        view! { <dl class="mt-3 grid gap-3 text-sm sm:grid-cols-2">
            <div><dt class="text-xs text-gray-500 dark:text-gray-400">"Resource"</dt><dd class="break-all">{resource}</dd></div>
            <div><dt class="text-xs text-gray-500 dark:text-gray-400">"Action"</dt><dd class="break-all">{action}</dd></div>
        </dl> }
    });
    view! { <div class=CARD><div class="flex flex-wrap items-start justify-between gap-4"><div class="min-w-0"><h3 class="break-all font-mono font-medium">{scope.name.clone()}</h3><p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{scope.kind_label()}</p><p class="mt-3 break-words text-sm text-gray-600 dark:text-gray-300">{scope.description.clone()}</p></div>
        {if editable { view! { <ScopeControls paths=paths scope=scope changed=changed /> }.into_any() } else { view! { <span class="text-xs text-gray-500 dark:text-gray-400">"Read-only"</span> }.into_any() }}
    </div>{semantics}</div> }
}

/// Creates only backend-supported name/description fields and retains invalid drafts.
#[component]
fn CreateScopeDialog(paths: ApplicationPaths, changed: Callback<()>) -> impl IntoView {
    let paths = StoredValue::new(paths);
    let open = RwSignal::new(false);
    let resource = RwSignal::new(String::new());
    let action = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let create = Action::new_local(move |request: &CreateScopeRequest| {
        let paths = paths.get_value();
        let request = request.clone();
        async move { client::create_scope(&paths, &request).await }
    });
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(_) => {
                    open.set(false);
                    resource.set(String::new());
                    action.set(String::new());
                    description.set(String::new());
                    error.set(String::new());
                    changed.run(());
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    view! { <Button on_click=move |_| { error.set(String::new()); open.set(true); }>"+ Create Scope"</Button>
        <Dialog id="create-oauth-scope" title="Create OAuth Scope" open=open busy=create.pending()>
            <form class="space-y-4" on:submit=move |ev| { ev.prevent_default(); if create.pending().get_untracked() { return; } error.set(String::new()); match compose_application_scope(&resource.get_untracked(), &action.get_untracked()) { Ok(name) => { create.dispatch(CreateScopeRequest { name, description: description.get_untracked() }); }, Err(message) => error.set(message.to_owned()) } }>
                <div><label for="scope-resource" class=LABEL>"Resource"</label><input id="scope-resource" class=INPUT required maxlength="126" autofocus spellcheck="false" prop:value=move || resource.get() disabled=move || create.pending().get() aria-describedby="scope-resource-help create-scope-help create-scope-error" on:input=move |ev| { resource.set(event_target_value(&ev)); error.set(String::new()); } placeholder="jobs" /><p id="scope-resource-help" class="mt-1 text-xs text-gray-500 dark:text-gray-400">"The thing being protected, such as jobs or runs."</p></div>
                <div><label for="scope-action" class=LABEL>"Action"</label><input id="scope-action" class=INPUT required maxlength="126" spellcheck="false" prop:value=move || action.get() disabled=move || create.pending().get() aria-describedby="scope-action-help create-scope-help create-scope-error" on:input=move |ev| { action.set(event_target_value(&ev)); error.set(String::new()); } placeholder="read" /><p id="scope-action-help" class="mt-1 text-xs text-gray-500 dark:text-gray-400">"The operation being delegated. Use any application-specific action, such as cancel or approve."</p></div>
                <p id="scope-preview" class="break-all text-sm" aria-live="polite">"OAuth scope: "<code>{move || format!("{}:{}", resource.get(), action.get())}</code></p>
                <p id="create-scope-help" class="text-xs text-gray-500 dark:text-gray-400">"Use one resource and one action without colons. Names are case-sensitive and cannot be renamed. The users and platform namespaces are reserved for internal permissions."</p>
                <div><label for="scope-description" class=LABEL>"Description"</label><textarea id="scope-description" class=INPUT rows="3" maxlength="2048" prop:value=move || description.get() disabled=move || create.pending().get() aria-describedby="create-scope-error" on:input=move |ev| description.set(event_target_value(&ev)) /></div>
                <FormError id="create-scope-error" error=error />
                <div class="flex justify-end gap-3"><button type="button" class=SECONDARY disabled=move || create.pending().get() on:click=move |_| open.set(false)>"Cancel"</button><Button button_type="submit" disabled=create.pending()>{move || if create.pending().get() { "Creating…" } else { "Create Scope" }}</Button></div>
            </form>
        </Dialog>
    }
}

/// Edits descriptions and confirms irreversible removal of delegated authority edges.
#[component]
fn ScopeControls(
    paths: ApplicationPaths,
    scope: ScopeResponse,
    changed: Callback<()>,
) -> impl IntoView {
    let paths = StoredValue::new(paths);
    let id = StoredValue::new(scope.id.clone());
    let name = StoredValue::new(scope.name);
    let edit_open = RwSignal::new(false);
    let delete_open = RwSignal::new(false);
    let description = RwSignal::new(scope.description);
    let confirmation = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let delete_error = RwSignal::new(String::new());
    let edit = Action::new_local(move |description: &String| {
        let path = paths.get_value();
        let id = id.get_value();
        let description = description.clone();
        async move { client::patch_scope(&path, &id, description).await }
    });
    let delete = Action::new_local(move |(): &()| {
        let path = paths.get_value();
        let id = id.get_value();
        async move { client::delete_scope(&path, &id).await }
    });
    Effect::new(move |_| {
        if let Some(result) = edit.value().get() {
            match result {
                Ok(_) => {
                    edit_open.set(false);
                    changed.run(());
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => {
                    delete_open.set(false);
                    changed.run(());
                }
                Err(err) => delete_error.set(error_message(&err)),
            }
        }
    });
    let description_id = format!("scope-description-{}", scope.id);
    let confirmation_id = format!("scope-confirmation-{}", scope.id);
    let edit_error_id = format!("scope-error-{}", scope.id);
    let delete_error_id = format!("scope-delete-error-{}", scope.id);
    view! { <div class="flex gap-2">
        <button type="button" class=SECONDARY on:click=move |_| { error.set(String::new()); edit_open.set(true); }>"Edit"</button><button type="button" class=SECONDARY on:click=move |_| { confirmation.set(String::new()); delete_error.set(String::new()); delete_open.set(true); }>"Delete"</button>
        <Dialog id=format!("edit-scope-{}", scope.id) title="Edit Scope Description" open=edit_open busy=edit.pending()>
            <form class="space-y-4" on:submit=move |ev| { ev.prevent_default(); if !edit.pending().get_untracked() { error.set(String::new()); edit.dispatch(description.get_untracked()); } }>
                <code class="block break-all text-sm">{name.get_value()}</code><label for=description_id.clone() class=LABEL>"Description"</label>
                <textarea id=description_id class=INPUT rows="3" maxlength="2048" prop:value=move || description.get() disabled=move || edit.pending().get() aria-describedby=edit_error_id.clone() on:input=move |ev| description.set(event_target_value(&ev)) />
                <div id=edit_error_id aria-live="polite">{move || if error.get().is_empty() { ().into_any() } else { view! { <Alert kind=AlertKind::Error message=error.get() /> }.into_any() }}</div>
                <div class="flex justify-end gap-3"><button type="button" class=SECONDARY disabled=move || edit.pending().get() on:click=move |_| edit_open.set(false)>"Cancel"</button><Button button_type="submit" disabled=edit.pending()>{move || if edit.pending().get() { "Saving…" } else { "Save Description" }}</Button></div>
            </form>
        </Dialog>
        <Dialog id=format!("delete-scope-{}", scope.id) title="Delete OAuth Scope" open=delete_open busy=delete.pending()>
            <form class="space-y-4" on:submit=move |ev| { ev.prevent_default(); if confirmation.get_untracked() == name.get_value() && !delete.pending().get_untracked() { delete.dispatch(()); } }>
                <p class="text-sm">"Deleting this scope removes it from client allow-lists and saved grants. Creating the same name later will not restore those assignments."</p>
                <label for=confirmation_id.clone() class=LABEL>"Type the scope name to confirm"</label><code class="block break-all">{name.get_value()}</code>
                <input id=confirmation_id class=INPUT autocomplete="off" spellcheck="false" aria-describedby=delete_error_id.clone() prop:value=move || confirmation.get() disabled=move || delete.pending().get() on:input=move |ev| confirmation.set(event_target_value(&ev)) />
                <div id=delete_error_id aria-live="polite">{move || if delete_error.get().is_empty() { ().into_any() } else { view! { <Alert kind=AlertKind::Error message=delete_error.get() /> }.into_any() }}</div>
                <div class="flex justify-end gap-3"><button type="button" class=SECONDARY disabled=move || delete.pending().get() on:click=move |_| delete_open.set(false)>"Cancel"</button><Button button_type="submit" disabled=Signal::derive(move || delete.pending().get() || confirmation.get() != name.get_value())>{move || if delete.pending().get() { "Deleting…" } else { "Delete Scope" }}</Button></div>
            </form>
        </Dialog>
    </div> }
}
