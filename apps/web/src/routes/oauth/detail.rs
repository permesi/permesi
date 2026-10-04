//! Public client detail and configuration editors.
//!
//! Flow Overview: load registration, redirect/scopes allow-lists and registry via
//! existing GETs; retain drafts on failure; replace one allow-list per explicit save.
//! Disabling/deleting are confirmed because they revoke stored authority permanently.

use super::common::{
    CARD, FormError, INPUT, LABEL, LINK, Loading, OAuthNav, ResourceParams, SECONDARY,
    application_context, error_message,
};
use crate::{
    app_lib::AppError,
    components::{
        Alert, AlertKind, Button,
        ui::{CopyValue, Dialog},
    },
    features::oauth::{
        client,
        model::{add_redirect, redirect_selection_matches, scope_selection_matches, toggle_scope},
        paths::ApplicationPaths,
        scope::{ApplicationScopeParts, scope_assignment_groups, unavailable_scopes},
        types::{ClientResponse, PatchClientRequest, ScopeResponse},
    },
};
use leptos::prelude::*;
use leptos_router::{
    components::A,
    hooks::{use_navigate, use_params},
};

/// Loads all editable client configuration scoped by the public route identifier.
#[component]
pub fn ClientDetailPage() -> impl IntoView {
    let Some(context) = application_context() else {
        return view! { <Alert kind=AlertKind::Error message="Application unavailable.".to_owned() /> }.into_any();
    };
    let path = context.paths;
    let fetch_path = path.clone();
    let params = use_params::<ResourceParams>();
    let data = LocalResource::new(move || {
        let path = fetch_path.clone();
        let id = params
            .get()
            .ok()
            .and_then(|value| value.client_id)
            .unwrap_or_default();
        async move {
            if id.is_empty() {
                return Err(AppError::Config("Missing client ID.".to_owned()));
            }
            let registration = client::get_client(&path, &id).await?;
            let redirects = client::get_redirects(&path, &id).await?;
            let allowed = client::get_client_scopes(&path, &id).await?;
            let registry = client::list_scopes(&path).await?;
            Ok((registration, redirects, allowed, registry))
        }
    });
    view! { <div class="space-y-6"><OAuthNav paths=path.clone() /><A href=path.clients() attr:class=LINK>"← OAuth clients"</A>
        <Suspense fallback=|| view! { <Loading message="Loading OAuth client…" /> }>
            {move || match data.get() {
                Some(Ok((registration, redirects, allowed, registry))) => view! { <ClientConfiguration paths=path.clone() registration=registration redirects=redirects allowed=allowed registry=registry /> }.into_any(),
                Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
                None => view! { <Loading message="Loading OAuth client…" /> }.into_any(),
            }}
        </Suspense>
    </div> }.into_any()
}

/// Mounts independent configuration drafts; lifecycle/name saves preserve sibling drafts.
#[component]
fn ClientConfiguration(
    paths: ApplicationPaths,
    registration: ClientResponse,
    redirects: Vec<String>,
    allowed: Vec<String>,
    registry: Vec<ScopeResponse>,
) -> impl IntoView {
    let id = registration.client_id.clone();
    let client = RwSignal::new(registration);
    view! { <div class="space-y-6">
        <div class=CARD><h2 class="mb-4 break-words text-xl font-semibold">{move || client.get().name}</h2>
            <dl class="grid gap-4 sm:grid-cols-2"><div class="min-w-0 sm:col-span-2"><dt class=LABEL>"Client ID"</dt><dd><CopyValue value=id.clone() /></dd></div>
                <div><dt class=LABEL>"Type"</dt><dd>{move || client.get().client_type.label()}</dd></div>
                <div><dt class=LABEL>"Status"</dt><dd>{move || client.get().status()}</dd></div>
                <div><dt class=LABEL>"Created"</dt><dd class="break-words text-sm">{move || client.get().created_at}</dd></div>
            </dl>
        </div>
        <ClientSettings paths=paths.clone() client=client />
        <RedirectEditor paths=paths.clone() id=id.clone() initial=redirects />
        <ScopeAssignment paths=paths.clone() id=id initial=allowed registry=registry />
        <ClientLifecycle paths=paths client=client />
    </div> }
}

/// Updates the display name without changing immutable identifiers or client type.
#[component]
fn ClientSettings(paths: ApplicationPaths, client: RwSignal<ClientResponse>) -> impl IntoView {
    let paths = StoredValue::new(paths);
    let id = StoredValue::new(client.get_untracked().client_id);
    let name = RwSignal::new(client.get_untracked().name);
    let error = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let save = Action::new_local(move |name: &String| {
        let path = paths.get_value();
        let id = id.get_value();
        let name = name.clone();
        async move {
            client::patch_client(
                &path,
                &id,
                &PatchClientRequest {
                    name: Some(name),
                    disabled: None,
                },
            )
            .await
        }
    });
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(value) => {
                    client.set(value);
                    message.set("Client name saved.".to_owned());
                    error.set(String::new());
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    view! { <section class=CARD aria-labelledby="client-settings-heading"><h3 id="client-settings-heading" class="mb-4 text-lg font-medium">"Client name"</h3>
        <form class="space-y-4" on:submit=move |ev| { ev.prevent_default(); if save.pending().get_untracked() { return; } error.set(String::new()); message.set(String::new()); save.dispatch(name.get_untracked().trim().to_owned()); }>
            <label for="client-edit-name" class=LABEL>"Name"</label><input id="client-edit-name" required maxlength="255" class=INPUT prop:value=move || name.get() disabled=move || save.pending().get() aria-describedby="client-settings-error" on:input=move |ev| { name.set(event_target_value(&ev)); message.set(String::new()); } />
            <FormError id="client-settings-error" error=error /><p aria-live="polite" class="text-sm text-green-700 dark:text-green-400">{move || message.get()}</p>
            <Button button_type="submit" disabled=save.pending()>{move || if save.pending().get() { "Saving…" } else { "Save Name" }}</Button>
        </form>
    </section> }
}

/// Stages additions/removals and saves a whole URI list; failures preserve every draft byte.
#[component]
fn RedirectEditor(paths: ApplicationPaths, id: String, initial: Vec<String>) -> impl IntoView {
    let path = StoredValue::new(paths);
    let id = StoredValue::new(id);
    let saved = RwSignal::new(initial.clone());
    let values = RwSignal::new(initial);
    let candidate = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let save = Action::new_local(move |values: &Vec<String>| {
        let path = path.get_value();
        let id = id.get_value();
        let values = values.clone();
        async move { client::replace_redirects(&path, &id, values).await }
    });
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(result) => {
                    saved.set(result.clone());
                    values.set(result);
                    error.set(String::new());
                    message.set("Redirect URIs saved.".to_owned());
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    view! { <section class=CARD aria-labelledby="redirect-heading"><h3 id="redirect-heading" class="text-lg font-medium">"Redirect URIs"</h3>
        <p class="my-3 text-sm text-gray-500 dark:text-gray-400">"Exact matching applies. Use HTTPS; public clients may use HTTP with 127.0.0.1 or [::1]. Wildcards and fragments are rejected. Save to apply additions or removals."</p>
        <fieldset disabled=move || save.pending().get() class="space-y-4"><legend class="sr-only">"Registered redirect URIs"</legend>
            <Show when=move || values.get().is_empty()><p class="text-sm text-gray-500">"No redirect URIs configured."</p></Show>
            <ul class="space-y-2"><For each=move || values.get() key=|value| value.clone() children=move |value| {
                let remove = StoredValue::new(value.clone());
                view! { <li class="flex min-w-0 flex-wrap items-start justify-between gap-2 rounded border border-gray-200 p-3 dark:border-gray-700"><code class="min-w-0 break-all text-sm">{value.clone()}</code><button type="button" class=SECONDARY aria-label=format!("Remove redirect URI {value}") on:click=move |_| { values.update(|items| items.retain(|item| item != &remove.get_value())); message.set(String::new()); }>"Remove"</button></li> }
            } /></ul>
            <form class="space-y-3" on:submit=move |ev| { ev.prevent_default(); match add_redirect(&values.get_untracked(), &candidate.get_untracked()) { Ok(result) => { values.set(result); candidate.set(String::new()); error.set(String::new()); message.set(String::new()); }, Err(err) => error.set(err.to_owned()) } }>
                <label for="redirect-uri-input" class=LABEL>"Add redirect URI"</label><input id="redirect-uri-input" class=INPUT type="text" required maxlength="2048" autocomplete="off" spellcheck="false" aria-describedby="redirect-error" prop:value=move || candidate.get() on:input=move |ev| candidate.set(event_target_value(&ev)) placeholder="https://example.com/oauth/callback" />
                <button type="submit" class=SECONDARY>"Add URI"</button>
            </form>
        </fieldset>
        <div class="mt-4 space-y-3"><FormError id="redirect-error" error=error /><p aria-live="polite" class="text-sm text-green-700 dark:text-green-400">{move || message.get()}</p><Button disabled=Signal::derive(move || save.pending().get() || redirect_selection_matches(&values.get(), &saved.get())) on_click=move |_| { error.set(String::new()); message.set(String::new()); save.dispatch(values.get_untracked()); }>{move || if save.pending().get() { "Saving…" } else { "Save Redirect URIs" }}</Button></div>
    </section> }
}

/// Configures maximum requested scopes from the server registry; no user grants are created.
#[component]
fn ScopeAssignment(
    paths: ApplicationPaths,
    id: String,
    initial: Vec<String>,
    registry: Vec<ScopeResponse>,
) -> impl IntoView {
    let paths = StoredValue::new(paths);
    let id = StoredValue::new(id);
    let registry = StoredValue::new(registry);
    let saved = RwSignal::new(initial.clone());
    let selected = RwSignal::new(initial);
    let error = RwSignal::new(String::new());
    let message = RwSignal::new(String::new());
    let save = Action::new_local(move |values: &Vec<String>| {
        let path = paths.get_value();
        let id = id.get_value();
        let values = values.clone();
        async move { client::replace_client_scopes(&path, &id, values).await }
    });
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(result) => {
                    saved.set(result.clone());
                    selected.set(result);
                    error.set(String::new());
                    message.set("Allowed scopes saved.".to_owned());
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    view! { <section class=CARD aria-labelledby="allowed-scopes-heading"><h3 id="allowed-scopes-heading" class="text-lg font-medium">"Allowed Scopes"</h3>
        <p class="my-3 text-sm text-gray-500 dark:text-gray-400">"These scopes define the maximum permissions this client may request. Actual authorization will be determined during the OAuth flow. Assigning scopes here does not grant permissions to users."</p>
        <form class="space-y-4" on:submit=move |ev| {
            ev.prevent_default();
            if save.pending().get_untracked() {
                return;
            }
            if !unavailable_scopes(&selected.get_untracked(), &registry.get_value()).is_empty() {
                error.set("Remove unavailable scopes before saving.".to_owned());
                return;
            }
            error.set(String::new());
            message.set(String::new());
            save.dispatch(selected.get_untracked());
        }>
            <fieldset disabled=move || save.pending().get() aria-describedby="allowed-scopes-error" class="space-y-3"><legend class="sr-only">"Application and system OAuth scopes"</legend>
                {scope_assignment_groups(registry.get_value()).into_iter().map(|group| {
                    let label = group.label().to_owned();
                    view! { <fieldset class="space-y-2"><legend class="mb-2 text-sm font-semibold">{label}</legend>
                        {group.scopes.into_iter().map(|scope| view! { <ScopeChoice scope=scope registry=registry selected=selected message=message /> }).collect_view()}
                    </fieldset> }
                }).collect_view()}
            </fieldset>
            <UnavailableScopes selected=selected registry=registry busy=save.pending() />
            <FormError id="allowed-scopes-error" error=error /><p aria-live="polite" class="text-sm text-green-700 dark:text-green-400">{move || message.get()}</p>
            <Button button_type="submit" disabled=Signal::derive(move || save.pending().get() || !unavailable_scopes(&selected.get(), &registry.get_value()).is_empty() || scope_selection_matches(&selected.get(), &saved.get()))>{move || if save.pending().get() { "Saving…" } else { "Save Allowed Scopes" }}</Button>
        </form>
    </section> }
}

/// Keeps unsupported configured values visible and removable without granting new choices.
/// Removal changes only the draft; the existing explicit Save performs revocation.
#[component]
fn UnavailableScopes(
    selected: RwSignal<Vec<String>>,
    registry: StoredValue<Vec<ScopeResponse>>,
    #[prop(into)] busy: Signal<bool>,
) -> impl IntoView {
    let values = Signal::derive(move || unavailable_scopes(&selected.get(), &registry.get_value()));
    view! { <Show when=move || !values.get().is_empty()>
        <div class="space-y-2 rounded-lg border border-gray-300 p-3 dark:border-gray-600">
            <p class="text-sm">"These configured scopes are unavailable. Remove them before saving. Removal takes effect only when you save."</p>
            {move || values.get().into_iter().map(|name| {
                let value = StoredValue::new(name.clone());
                view! { <div class="flex flex-wrap items-center justify-between gap-2"><code class="min-w-0 break-all text-xs">{name.clone()}</code>
                    <button type="button" class=SECONDARY aria-label=format!("Remove unavailable scope {name}") disabled=move || busy.get() on:click=move |_| selected.update(|values| values.retain(|name| name != &value.get_value()))>"Remove"</button>
                </div> }
            }).collect_view()}
        </div>
    </Show> }
}

/// Displays an action within its resource group while submitting the original token.
/// Selection remains bound to the fetched registry and grants no user authority.
#[component]
fn ScopeChoice(
    scope: ScopeResponse,
    registry: StoredValue<Vec<ScopeResponse>>,
    selected: RwSignal<Vec<String>>,
    message: RwSignal<String>,
) -> impl IntoView {
    let label = ApplicationScopeParts::from_scope(&scope)
        .map_or_else(|| scope.name.clone(), |parts| parts.action.to_owned());
    let kind = scope.kind_label();
    let name = StoredValue::new(scope.name);
    view! { <label class="flex cursor-pointer items-start gap-3 rounded border border-gray-200 p-3 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-700">
        <input type="checkbox" name="allowed-oauth-scope" value=name.get_value() prop:checked=move || selected.get().contains(&name.get_value()) on:change=move |ev| { selected.update(|values| toggle_scope(values, &registry.get_value(), &name.get_value(), event_target_checked(&ev))); message.set(String::new()); } />
        <span class="min-w-0"><span class="break-all text-sm font-medium">{label}</span><span class="ml-2 text-xs text-gray-500 dark:text-gray-400">{kind}</span><code class="block break-all text-xs">{name.get_value()}</code><span class="block break-words text-xs text-gray-500 dark:text-gray-400">{scope.description}</span></span>
    </label> }
}

/// Confirms lifecycle changes; deletion requires the full public client ID.
#[component]
fn ClientLifecycle(paths: ApplicationPaths, client: RwSignal<ClientResponse>) -> impl IntoView {
    let paths = StoredValue::new(paths);
    let id = StoredValue::new(client.get_untracked().client_id);
    let open = RwSignal::new(false);
    let delete_open = RwSignal::new(false);
    let confirmation = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let delete_error = RwSignal::new(String::new());
    let navigate = use_navigate();
    let change = Action::new_local(move |disabled: &bool| {
        let path = paths.get_value();
        let id = id.get_value();
        let disabled = *disabled;
        async move {
            client::patch_client(
                &path,
                &id,
                &PatchClientRequest {
                    name: None,
                    disabled: Some(disabled),
                },
            )
            .await
        }
    });
    let delete = Action::new_local(move |(): &()| {
        let path = paths.get_value();
        let id = id.get_value();
        async move { client::delete_client(&path, &id).await }
    });
    Effect::new(move |_| {
        if let Some(result) = change.value().get() {
            match result {
                Ok(value) => {
                    client.set(value);
                    open.set(false);
                    error.set(String::new());
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => navigate(
                    &paths.get_value().clients(),
                    leptos_router::NavigateOptions::default(),
                ),
                Err(err) => delete_error.set(error_message(&err)),
            }
        }
    });
    view! { <section class="rounded-lg border border-red-200 p-6 dark:border-red-900" aria-labelledby="danger-heading"><h3 id="danger-heading" class="text-lg font-medium">"Danger Zone"</h3>
        <p class="my-3 text-sm text-gray-500 dark:text-gray-400">"Disabling or deleting a client revokes its saved grants and credentials. Re-enabling does not restore revoked authority."</p>
        <div class="flex flex-wrap gap-3"><button type="button" class=SECONDARY disabled=Signal::derive(move || change.pending().get() || delete.pending().get()) on:click=move |_| { error.set(String::new()); open.set(true); }>{move || if client.get().disabled_at.is_some() { "Enable Client" } else { "Disable Client" }}</button><button type="button" class="cursor-pointer rounded-lg border border-red-300 px-4 py-2 text-sm text-red-700 hover:bg-red-50 focus:ring-2 focus:ring-red-500 dark:text-red-400 dark:hover:bg-red-950" disabled=move || change.pending().get() || delete.pending().get() on:click=move |_| { confirmation.set(String::new()); delete_error.set(String::new()); delete_open.set(true); }>"Delete Client"</button></div>
        <Dialog id="client-lifecycle" title="Change client status" open=open busy=change.pending()>
            <p class="mb-4 text-sm">{move || if client.get().disabled_at.is_some() { "Enable this client? Previously revoked grants and credentials will remain revoked." } else { "Disable this client? It becomes inactive and its saved grants and credentials are revoked." }}</p><FormError id="lifecycle-error" error=error />
            <div class="mt-4 flex justify-end gap-3"><button type="button" class=SECONDARY disabled=move || change.pending().get() on:click=move |_| open.set(false)>"Cancel"</button><Button disabled=change.pending() on_click=move |_| { change.dispatch(client.get_untracked().disabled_at.is_none()); }>{move || if change.pending().get() { "Saving…" } else { "Confirm" }}</Button></div>
        </Dialog>
        <Dialog id="client-delete" title="Delete OAuth Client" open=delete_open busy=delete.pending()>
            <form class="space-y-4" on:submit=move |ev| { ev.prevent_default(); if confirmation.get_untracked() == id.get_value() && !delete.pending().get_untracked() { delete.dispatch(()); } }>
                <p class="text-sm">"This permanently removes the client from management and revokes its saved authority. This cannot be undone."</p>
                <label for="delete-client-confirmation" class=LABEL>"Type the full client ID to confirm"</label><code class="block break-all text-sm">{id.get_value()}</code>
                <input id="delete-client-confirmation" class=INPUT autocomplete="off" spellcheck="false" aria-describedby="delete-client-error" prop:value=move || confirmation.get() disabled=move || delete.pending().get() on:input=move |ev| confirmation.set(event_target_value(&ev)) />
                <FormError id="delete-client-error" error=delete_error />
                <div class="flex justify-end gap-3"><button type="button" class=SECONDARY disabled=move || delete.pending().get() on:click=move |_| delete_open.set(false)>"Cancel"</button><Button button_type="submit" disabled=Signal::derive(move || delete.pending().get() || confirmation.get() != id.get_value())>{move || if delete.pending().get() { "Deleting…" } else { "Delete Client" }}</Button></div>
            </form>
        </Dialog>
    </section> }
}
