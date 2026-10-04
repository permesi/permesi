//! Confidential credential management with ephemeral one-time disclosure.
//!
//! Flow Overview: load server metadata, confirm an explicit creation/rotation/revocation,
//! then refresh metadata. Plaintext lives only in the mounted reveal dialog; action
//! results contain no secret. Dismissal/navigation clears disclosure. Failed issuance
//! refreshes metadata and offers recovery without an automatic mutation retry.

use super::common::{CARD, FormError, SECONDARY, error_message};
use crate::{
    components::{Button, ui::Dialog},
    features::oauth::{
        client,
        paths::ApplicationPaths,
        types::{ClientResponse, IssuedSecret},
    },
};
use leptos::{prelude::*, task::spawn_local};
use wasm_bindgen_futures::JsFuture;

/// Renders secret metadata and explicit mutations; server tenant ACLs remain authoritative.
#[component]
pub(super) fn CredentialSection(
    paths: ApplicationPaths,
    registration: RwSignal<ClientResponse>,
) -> impl IntoView {
    let paths = StoredValue::new(paths);
    let client_id = StoredValue::new(registration.get_untracked().client_id);
    let refresh = RwSignal::new(0u64);
    let metadata = LocalResource::new(move || {
        refresh.get();
        let _ = registration.get();
        let paths = paths.get_value();
        let id = client_id.get_value();
        async move { client::list_secrets(&paths, &id).await }
    });
    let open = RwSignal::new(false);
    let secret = RwSignal::new(None::<IssuedSecret>);
    let error = RwSignal::new(String::new());
    // None creates; Some(current ID) rotates. Plaintext never enters an Action result.
    let expected = RwSignal::new(None::<String>);
    let issue = Action::new_local(move |current: &Option<String>| {
        let paths = paths.get_value();
        let id = client_id.get_value();
        let current = current.clone();
        async move { issue_once(paths, id, current, secret, error, refresh).await }
    });
    let revoke_open = RwSignal::new(false);
    let revoke_id = RwSignal::new(String::new());
    let revoke_error = RwSignal::new(String::new());
    let revoke = Action::new_local(move |id: &String| {
        let paths = paths.get_value();
        let client = client_id.get_value();
        let id = id.clone();
        async move { client::revoke_secret(&paths, &client, &id).await }
    });
    Effect::new(move |_| {
        if let Some(result) = revoke.value().get() {
            match result {
                Ok(()) => {
                    revoke_open.set(false);
                    refresh.update(|version| *version += 1);
                }
                Err(err) => {
                    revoke_error.set(error_message(&err));
                    refresh.update(|version| *version += 1);
                }
            }
        }
    });
    Effect::new(move |_| {
        if !open.get() {
            secret.set(None);
            issue.value().set(None);
        }
    });
    on_cleanup(move || {
        secret.try_set(None);
        issue.value().try_set(None);
    });
    let busy = Signal::derive(move || issue.pending().get() || revoke.pending().get());
    view! { <section class=CARD aria-labelledby="credential-heading">
        <h3 id="credential-heading" class="mb-3 text-lg font-medium">"Client secrets"</h3>
        <p class="mb-4 text-sm text-gray-500 dark:text-gray-400">"Secrets are shown once. Rotation temporarily keeps the previous secret valid until its displayed deadline. Revocation takes effect when the request succeeds."</p>
        <Suspense fallback=|| view! { <p>"Loading credential metadata…"</p> }>
        {move || match metadata.get() {
            Some(Ok(rows)) => {
                let current = rows.iter().find(|value| value.expires_at.is_none()).map(|value| value.id.clone());
                let rotating = rows.iter().any(|value| value.expires_at.is_some());
                let current = StoredValue::new(current);
                let empty = rows.is_empty();
                view! { <div class="space-y-3">
                    <Show when=move || empty><p>"No usable client secrets."</p></Show>
                    <ul class="space-y-3">{rows.iter().map(|value| {
                        let id = StoredValue::new(value.id.clone());
                        view! { <li class="rounded border border-gray-200 p-3 dark:border-gray-700">
                            <p class="font-medium">{if value.expires_at.is_some() { "Retiring" } else { "Current" }}</p>
                            <code class="block break-all text-sm">{value.id.clone()}</code>
                            <p class="text-sm">"Created: "{value.created_at.clone()}</p>
                            {value.expires_at.clone().map(|deadline| view! { <p class="text-sm">"Valid until: "{deadline}</p> })}
                            <button class=SECONDARY type="button" disabled=busy on:click=move |_| { revoke_id.set(id.get_value()); revoke_error.set(String::new()); revoke_open.set(true); }>"Revoke Secret"</button>
                        </li> }
                    }).collect_view()}</ul>
                    <Button disabled=Signal::derive(move || busy.get() || registration.get().disabled_at.is_some() || (current.get_value().is_some() && rotating)) on_click=move |_| {
                        expected.set(current.get_value()); error.set(String::new()); secret.set(None); issue.value().set(None); open.set(true);
                    }>{if current.get_value().is_some() { "Rotate Secret" } else { "Create Secret" }}</Button>
                    <Show when=move || rotating><p class="text-sm">"Another rotation is unavailable until the retiring secret expires or is revoked."</p></Show>
                </div> }.into_any()
            },
            Some(Err(err)) => view! { <p class="text-sm text-red-600">{error_message(&err)}</p> }.into_any(),
            None => view! { <p>"Loading credential metadata…"</p> }.into_any(),
        }}</Suspense>
        <button type="button" class=SECONDARY disabled=busy on:click=move |_| refresh.update(|version| *version += 1)>"Refresh Secret Metadata"</button>
        <Dialog id="client-secret-issue" title="Issue client secret" open=open busy=issue.pending()>
            <Show when=move || secret.get().is_some() fallback=move || view! {
                <p class="mb-4 text-sm">"Create a new secret? Save it securely when shown. A replacement retires the current secret using the configured overlap."</p>
                <FormError id="credential-error" error=error />
                <Button disabled=Signal::derive(move || issue.pending().get() || !error.get().is_empty()) on_click=move |_| { if !issue.pending().get_untracked() { issue.dispatch(expected.get_untracked()); } }>{move || if issue.pending().get() { "Issuing…" } else { "Confirm Issuance" }}</Button>
            }>
                {move || secret.get().map(|value| view! { <SecretReveal value=value.client_secret /> })}
                <p class="my-4 text-sm">"This secret cannot be retrieved again. Store it securely before closing."</p>
                <Button on_click=move |_| open.set(false)>"I saved the secret"</Button>
            </Show>
        </Dialog>
        <Dialog id="client-secret-revoke" title="Revoke client secret" open=revoke_open busy=revoke.pending()>
            <p class="mb-4 text-sm">"Revoke this secret? Applications using it will need another valid secret."</p>
            <code class="block break-all text-sm">{move || revoke_id.get()}</code>
            <FormError id="credential-revoke-error" error=revoke_error />
            <Button disabled=revoke.pending() on_click=move |_| { if !revoke.pending().get_untracked() { revoke.dispatch(revoke_id.get_untracked()); } }>"Confirm Revocation"</Button>
        </Dialog>
    </section> }
}

/// Mounted only during disclosure; closing destroys the plaintext text and clipboard closure.
#[component]
fn SecretReveal(value: String) -> impl IntoView {
    let value = StoredValue::new(value);
    let status = RwSignal::new(String::new());
    view! { <div><code id="one-time-client-secret" class="block break-all text-sm">{value.get_value()}</code>
        <button type="button" class=SECONDARY on:click=move |_| spawn_local(async move {
            let Some(window) = web_sys::window() else { return; };
            if !window.is_secure_context() { status.try_set("Select the secret to copy it.".to_owned()); return; }
            let copied = JsFuture::from(window.navigator().clipboard().write_text(&value.get_value())).await.is_ok();
            status.try_set(if copied { "Copied." } else { "Select the secret to copy it." }.to_owned());
        })>"Copy Secret"</button>
        <p class="text-sm" aria-live="polite">{move || status.get()}</p>
    </div> }
}

/// Handles one explicitly confirmed issuance; errors refresh metadata but never retry.
/// Disposed signal writes fail harmlessly, dropping plaintext after navigation.
async fn issue_once(
    paths: ApplicationPaths,
    id: String,
    current: Option<String>,
    secret: RwSignal<Option<IssuedSecret>>,
    error: RwSignal<String>,
    refresh: RwSignal<u64>,
) {
    let result = match current {
        Some(current) => client::rotate_secret(&paths, &id, current).await,
        None => client::create_secret(&paths, &id).await,
    };
    match result {
        Ok(value) => {
            secret.try_set(Some(value));
        }
        Err(err) => {
            error.try_set(format!("{} Refresh metadata before retrying. If a new current secret was created but not received, revoke it and create another; the retiring secret keeps its original deadline.", error_message(&err)));
        }
    }
    refresh.try_update(|version| *version += 1);
}
