//! Passkey (`WebAuthn`) UI for security settings. Registration preparation,
//! credential listing and deletion are separate components sharing only the
//! current resource and feedback state.
//!
//! Flow Overview: Prepare server options, complete the browser `WebAuthn` ceremony,
//! then submit the response. Deletion requires OPAQUE reauthentication before
//! its server mutation. Challenges and passwords stay transient in the browser;
//! the server enforces session recency and credential ownership.

mod list;
mod registration;

use self::{list::PasskeyList, registration::CreatePasskeyControl};
use crate::{
    app_lib::AppError,
    components::AlertKind,
    features::{
        auth::{opaque::reauthenticate, state::use_auth, token},
        passkeys::client,
    },
};
use js_sys::Reflect;
use leptos::{ev, prelude::*};
use leptos_dom::helpers::{WindowListenerHandle, window_event_listener};
use wasm_bindgen::{JsCast, JsValue};

/// Detects presentation support without granting credential authority.
fn webauthn_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    Reflect::has(window.as_ref(), &JsValue::from_str("PublicKeyCredential"))
        .ok()
        .unwrap_or(false)
}

#[component]
pub fn PasskeysSection() -> impl IntoView {
    let auth = use_auth();
    let passkeys = LocalResource::new(move || async move { client::list_credentials().await });
    let (feedback, set_feedback) = signal::<Option<(AlertKind, String)>>(None);
    let (show_delete_passkey_form, set_show_delete_passkey_form) = signal::<Option<String>>(None);
    let (delete_passkey_password, set_delete_passkey_password) = signal(String::new());
    let section_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    let click_listener: StoredValue<Option<WindowListenerHandle>> = StoredValue::new(None);

    Effect::new(move |_| {
        let has_feedback = feedback.get().is_some();
        if has_feedback {
            let has_listener = click_listener
                .try_read_value()
                .is_some_and(|handle| handle.is_some());
            if has_listener {
                return;
            }
            let section_ref = section_ref;
            let handle = window_event_listener(ev::click, move |event| {
                let Some(section) = section_ref.get() else {
                    return;
                };
                let Some(target) = event.target() else {
                    return;
                };
                let Ok(target) = target.dyn_into::<web_sys::Node>() else {
                    return;
                };
                if !section.contains(Some(&target)) {
                    set_feedback.set(None);
                }
            });
            if let Some(mut stored) = click_listener.try_write_value() {
                *stored = Some(handle);
            }
        } else if let Some(mut stored) = click_listener.try_write_value()
            && let Some(handle) = stored.take()
        {
            handle.remove();
        }
    });

    on_cleanup(move || {
        if let Some(mut stored) = click_listener.try_write_value()
            && let Some(handle) = stored.take()
        {
            handle.remove();
        }
    });

    let delete_action = Action::new_local(move |(credential_id, password): &(String, String)| {
        let credential_id = credential_id.clone();
        let password = password.clone();
        let email = auth.session.get_untracked().map(|session| session.email);
        async move { delete_passkey_with_reauth(email, credential_id, password).await }
    });
    let delete_action_value = delete_action;

    Effect::new(move |_| {
        if let Some(result) = delete_action_value.value().get() {
            match result {
                Ok(()) => {
                    set_feedback.set(Some((AlertKind::Success, "Passkey removed.".to_string())));
                    set_show_delete_passkey_form.set(None);
                    set_delete_passkey_password.set(String::new());
                    passkeys.refetch();
                }
                Err(err) => set_feedback.set(Some((AlertKind::Error, err.to_string()))),
            }
        }
    });

    view! {
        <div node_ref=section_ref>
            <CreatePasskeyControl passkeys feedback set_feedback />

            <PasskeyList
                supported=webauthn_supported()
                passkeys
                show_delete_passkey_form
                set_show_delete_passkey_form
                delete_passkey_password
                set_delete_passkey_password
                delete_action
            />
        </div>
    }
}

/// Reauthenticates the current account before deleting its passkey credential.
async fn delete_passkey_with_reauth(
    email: Option<String>,
    credential_id: String,
    password: String,
) -> Result<(), AppError> {
    let email = email
        .ok_or_else(|| AppError::Config("Sign in again before removing a passkey.".to_owned()))?;
    reauthenticate(&email, password).await?;
    let zero_token = token::fetch_zero_token().await?;
    client::delete_credential(&credential_id, &zero_token).await
}
