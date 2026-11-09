//! Client registration list and minimal creation form.
//!
//! Creation sends only name/type; independent redirect and scope APIs configure
//! the new registration. Cards link by public identifier; details expose copyable IDs.

use super::common::{
    EmptyState, FormError, INPUT, LABEL, Loading, OAuthNav, SECONDARY, application_context,
    error_message,
};
use crate::{
    components::{
        Alert, AlertKind, Button, DateTime, EntityHeader, Icon, IconName, MetaItem, icon_size,
        ui::Dialog,
    },
    features::oauth::{
        client,
        model::NO_CLIENTS,
        paths::ApplicationPaths,
        types::{ClientType, CreateClientRequest},
    },
};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_navigate};

/// Lists registrations and offers creation without inferring organization roles.
#[component]
pub fn ClientsPage() -> impl IntoView {
    let Some(context) = application_context() else {
        return view! { <Alert kind=AlertKind::Error message="Application unavailable.".to_owned() /> }.into_any();
    };
    let paths = context.paths;
    let fetch_path = paths.clone();
    let clients = LocalResource::new(move || {
        let path = fetch_path.clone();
        async move { client::list_clients(&path).await }
    });
    view! { <div class="space-y-6">
        <OAuthNav paths=paths.clone() />
        <div class="flex flex-wrap items-center justify-between gap-4"><h2 class="text-xl font-semibold">"OAuth Clients"</h2><div class="flex flex-wrap items-center gap-3"><button type="button" class=SECONDARY on:click=move |_| clients.refetch()><Icon name=IconName::Refresh size=icon_size::INLINE class="text-gray-400 dark:text-gray-500" />"Refresh"</button><CreateClientDialog paths=paths.clone() /></div></div>
        <p class="text-sm text-gray-500 dark:text-gray-400">"Organization owners and admins can manage clients. Client IDs are public identifiers; client types are fixed at creation."</p>
        <Suspense fallback=|| view! { <Loading message="Loading OAuth clients…" /> }>
            {move || match clients.get() {
                Some(Ok(items)) if items.is_empty() => view! { <EmptyState title=NO_CLIENTS message="Create a client to configure an integration for this application." /> }.into_any(),
                Some(Ok(items)) => view! { <div class="space-y-3">{items.into_iter().map(|item| {
                    let status = item.status();
                    let client_type = item.client_type.label();
                    view! {
                    <A href=paths.client(&item.client_id) attr:class="block min-w-0 cursor-pointer rounded-lg border border-gray-200 bg-white p-5 hover:border-gray-400 hover:bg-gray-50 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-gray-500 dark:hover:bg-gray-700/50">
                        <EntityHeader icon=IconName::Clients navigable=true>{item.name.clone()}</EntityHeader>
                        <dl class="mt-3">
                            <MetaItem icon=IconName::Clients label="Type">{client_type}</MetaItem>
                            <MetaItem icon=IconName::Info label="Status">{status}</MetaItem>
                            <MetaItem icon=IconName::Calendar label="Created"><DateTime value=item.created_at /></MetaItem>
                        </dl>
                    </A>
                }}).collect_view()}</div> }.into_any(),
                Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
                None => view! { <Loading message="Loading OAuth clients…" /> }.into_any(),
            }}
        </Suspense>
    </div> }.into_any()
}

/// Creates name/type only and navigates using the returned public client identifier.
#[component]
fn CreateClientDialog(paths: ApplicationPaths) -> impl IntoView {
    let path = StoredValue::new(paths);
    let open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let kind = RwSignal::new(ClientType::Public);
    let error = RwSignal::new(String::new());
    let navigate = use_navigate();
    let create = Action::new_local(move |request: &CreateClientRequest| {
        let request = request.clone();
        let path = path.get_value();
        async move { client::create_client(&path, &request).await }
    });
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(client) => {
                    open.set(false);
                    navigate(
                        &path.get_value().client(&client.client_id),
                        leptos_router::NavigateOptions::default(),
                    );
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    view! {
        <Button on_click=move |_| { error.set(String::new()); open.set(true); }>"+ Create OAuth Client"</Button>
        <Dialog id="create-oauth-client" title="Create OAuth Client" open=open busy=create.pending()>
            <form class="space-y-4" on:submit=move |ev| { ev.prevent_default(); if create.pending().get_untracked() { return; } error.set(String::new()); create.dispatch(CreateClientRequest { name: name.get_untracked().trim().to_owned(), client_type: kind.get_untracked() }); }>
                <div><label for="oauth-client-name" class=LABEL>"Name"</label><input id="oauth-client-name" required maxlength="255" autofocus class=INPUT prop:value=move || name.get() disabled=move || create.pending().get() aria-describedby="create-client-error" on:input=move |ev| name.set(event_target_value(&ev)) /></div>
                <fieldset disabled=move || create.pending().get() class="space-y-3"><legend class=LABEL>"Client type"</legend>
                    <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-gray-200 p-3 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-700"><input type="radio" name="client-type" value="public" prop:checked=move || kind.get() == ClientType::Public on:change=move |_| kind.set(ClientType::Public) /><span><strong>"Public"</strong><span class="mt-1 block text-sm text-gray-500 dark:text-gray-400">{ClientType::Public.description()}</span></span></label>
                    <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-gray-200 p-3 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-700"><input type="radio" name="client-type" value="confidential" prop:checked=move || kind.get() == ClientType::Confidential on:change=move |_| kind.set(ClientType::Confidential) /><span><strong>"Confidential"</strong><span class="mt-1 block text-sm text-gray-500 dark:text-gray-400">{ClientType::Confidential.description()}</span></span></label>
                </fieldset>
                <FormError id="create-client-error" error=error />
                <div class="flex flex-wrap justify-end gap-3"><button type="button" class=SECONDARY disabled=move || create.pending().get() on:click=move |_| open.set(false)>"Cancel"</button><Button button_type="submit" disabled=create.pending()>{move || if create.pending().get() { "Creating…" } else { "Create Client" }}</Button></div>
            </form>
        </Dialog>
    }
}
