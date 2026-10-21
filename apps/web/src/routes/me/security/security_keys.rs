//! Hardware MFA key registration and removal; server policy and credential ownership remain authoritative.
//!
//! Flow Overview: The section collects browser-local input, completes the existing
//! authentication ceremony and calls its session-authenticated mutation API.

use super::{
    display::{format_relative, format_rfc3339},
    factor_mutation_error,
};
use crate::{
    app_lib::{AppError, theme::Theme},
    components::{Alert, AlertKind, Button, Spinner},
    features::{
        auth::{client as auth_client, opaque::reauthenticate, state::use_auth},
        me::client,
    },
};
use leptos::{ev::SubmitEvent, prelude::*};

/// Manages hardware MFA keys with per-mutation reauthentication and local feedback.
#[component]
pub(super) fn SecurityKeysSection() -> impl IntoView {
    let auth = use_auth();
    // Security keys signals
    let security_keys =
        LocalResource::new(move || async move { client::list_security_keys().await });
    let (show_add_key_form, set_show_add_key_form) = signal(false);
    let (new_key_label, set_new_key_label) = signal(String::new());
    let (show_delete_key_form, set_show_delete_key_form) = signal::<Option<String>>(None); // Credential ID
    let (delete_key_password, set_delete_key_password) = signal(String::new());

    let delete_key_action =
        Action::new_local(move |(credential_id, password): &(String, String)| {
            let credential_id = credential_id.clone();
            let password = password.clone();
            let auth = auth;
            async move {
                let email = auth
                    .session
                    .get_untracked()
                    .map(|s| s.email)
                    .unwrap_or_default();
                reauthenticate(&email, password).await?;

                // 2. Call delete
                client::delete_security_key(&credential_id).await
            }
        });

    Effect::new(move |_| {
        if let Some(Ok(())) = delete_key_action.value().get() {
            set_show_delete_key_form.set(None);
            set_delete_key_password.set(String::new());
            security_keys.refetch();
        }
    });

    let add_key_action = Action::new_local(move |label: &String| {
        let label = label.clone();
        async move {
            // 1. Start WebAuthn registration
            let start_response = auth_client::mfa_webauthn_register_start().await?;

            // 2. Browser interaction (YubiKey touch)
            let reg_response =
                crate::features::auth::webauthn::register_key(&start_response.challenge).await?;

            // 3. Finish registration
            auth_client::mfa_webauthn_register_finish(
                &crate::features::auth::types::WebauthnRegisterFinishRequest {
                    reg_id: start_response.reg_id,
                    label,
                    response: reg_response,
                },
            )
            .await
        }
    });

    Effect::new(move |_| {
        if let Some(Ok(())) = add_key_action.value().get() {
            set_show_add_key_form.set(false);
            set_new_key_label.set(String::new());
            security_keys.refetch();
        }
    });

    view! {
                                        // Security Keys Row
                                        <div class=Theme::ROW>
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class=Theme::ICON>
                                                        "usb"
                                                    </span>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                            "Security keys"
                                                        </p>
                                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                                            {move || match security_keys.get() {
                                                                Some(Ok(keys)) => format!("{} security keys configured", keys.len()),
                                                                _ => "0 security keys configured".to_string(),
                                                            }}
                                                        </p>
                                                    </div>
                                                </div>
                                                <button
                                                    on:click=move |_| {
                                                        set_show_add_key_form.update(|v| *v = !*v);
                                                        set_new_key_label.set(String::new());
                                                    }
                                                    class="text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                >
                                                    {move || if show_add_key_form.get() { "Cancel" } else { "Add" }}
                                                </button>
                                            </div>

                                            <Show when=move || show_add_key_form.get()>
                                                {add_key_form(AddKeyForm { new_key_label, set_new_key_label, add_key_action })}
                                            </Show>
                                        </div>

                                        {key_list(KeyRows { delete_key_password, set_delete_key_password, delete_key_action, set_show_delete_key_form, security_keys, show_delete_key_form })}

    }
}

#[derive(Clone, Copy)]
struct AddKeyForm {
    new_key_label: ReadSignal<String>,
    set_new_key_label: WriteSignal<String>,
    add_key_action: Action<String, Result<(), AppError>>,
}

/// Renders the confirmation form using only its owning section's state.
fn add_key_form(state: AddKeyForm) -> impl IntoView {
    let AddKeyForm {
        new_key_label,
        set_new_key_label,
        add_key_action,
    } = state;
    view! {
    <form
                                                        class="mt-6 space-y-4 max-w-md bg-gray-50 dark:bg-gray-900/50 p-4 rounded-lg border border-gray-100 dark:border-gray-700"
                                                        on:submit=move |event: SubmitEvent| {
                                                            event.prevent_default();
                                                            let label = new_key_label.get_untracked();
                                                            if label.trim().is_empty() {
                                                                return;
                                                            }
                                                            add_key_action.dispatch(label);
                                                        }
                                                    >
                                                        <p class="text-xs text-gray-600 dark:text-gray-400 mb-4">
                                                            "Security keys are hardware devices that can be used as a second factor. Give your key a nickname to help you identify it later."
                                                        </p>
                                                        <div>
                                                            <label class="block mb-1 text-xs font-medium text-gray-700 dark:text-gray-300" for="key_label">
                                                                "Key nickname"
                                                            </label>
                                                            <input
                                                                id="key_label"
                                                                type="text"
                                                                placeholder="e.g. Blue YubiKey"
                                                                class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                                                                required
                                                                on:input=move |event| set_new_key_label.set(event_target_value(&event))
                                                            />
                                                        </div>
                                                        <div class="pt-2 flex items-center gap-4">
                                                            <Button button_type="submit" disabled=add_key_action.pending()>
                                                                "Register hardware key"
                                                            </Button>
                                                            {move || {
                                                                add_key_action
                                                                    .pending()
                                                                    .get()
                                                                    .then_some(view! { <Spinner /> })
                                                            }}
                                                        </div>
                                                        <p class="text-[10px] text-gray-500 dark:text-gray-400 mt-2">
                                                            "After clicking register, follow your browser's instructions to touch or insert your hardware key."
                                                        </p>
                                                        {move || {
                                                            add_key_action
                                                                .value()
                                                                .get()
                                                                .and_then(std::result::Result::err)
                                                                .map(|err| {
                                                                    view! { <div class="mt-4"><Alert kind=AlertKind::Error message=factor_mutation_error(&err) /></div> }
                                                                })
                                                        }}
                                                    </form>
    }
}

#[derive(Clone)]
struct KeyRemoval {
    delete_key_password: ReadSignal<String>,
    set_delete_key_password: WriteSignal<String>,
    delete_key_action: Action<(String, String), Result<(), AppError>>,
    set_show_delete_key_form: WriteSignal<Option<String>>,
    credential_id_for_delete: String,
}

/// Renders the confirmation form using only its owning section's state.
fn delete_key_form(state: KeyRemoval) -> impl IntoView {
    let KeyRemoval {
        delete_key_password,
        set_delete_key_password,
        delete_key_action,
        set_show_delete_key_form,
        credential_id_for_delete,
    } = state;
    view! {
    <form
                                                                                    class="space-y-4 max-w-md bg-red-50 dark:bg-red-900/10 p-4 rounded-lg border border-red-100 dark:border-red-900/30"
                                                                                    on:submit={
                                                                                        let credential_id = credential_id_for_delete.clone();

                                                                                        move |event: SubmitEvent| {
                                                                                            event.prevent_default();
                                                                                            let password = delete_key_password.get_untracked();
                                                                                            if password.trim().is_empty() {
                                                                                                return;
                                                                                            }
                                                                                            delete_key_action.dispatch((credential_id.clone(), password));
                                                                                        }
                                                                                    }
                                                                                >
                                                                                    <p class="text-xs text-red-700 dark:text-red-300 mb-4">
                                                                                        "Deleting this hardware key will remove it as a sign-in method. Please enter your password to confirm."
                                                                                    </p>
                                                                                    <div>
                                                                                        <label class="block mb-1 text-xs font-medium text-red-900 dark:text-red-200" for="delete_key_password">
                                                                                            "Password"
                                                                                        </label>
                                                                                        <input
                                                                                            id="delete_key_password"
                                                                                            type="password"
                                                                                            class="bg-white border border-red-200 text-gray-900 text-sm rounded-lg focus:ring-red-500 focus:border-red-500 block w-full p-2 dark:bg-gray-800 dark:border-red-900/50 dark:text-white"
                                                                                            required
                                                                                            on:input=move |event| set_delete_key_password.set(event_target_value(&event))
                                                                                        />
                                                                                    </div>
                                                                                    <div class="pt-2 flex items-center gap-3">
                                                                                        <button
                                                                                            type="submit"
                                                                                            disabled=delete_key_action.pending()
                                                                                            class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 shadow-sm cursor-pointer"
                                                                                        >
                                                                                            "Remove key"
                                                                                        </button>
                                                                                        <button
                                                                                            type="button"
                                                                                            on:click=move |_| set_show_delete_key_form.set(None)
                                                                                            class="px-4 py-2 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                                                        >
                                                                                            "Cancel"
                                                                                        </button>
                                                                                        {move || {
                                                                                            delete_key_action.pending().get().then_some(view! { <Spinner /> })
                                                                                        }}
                                                                                    </div>
                                                                                    {move || {
                                                                                        delete_key_action
                                                                                            .value()
                                                                                            .get()
                                                                                            .and_then(std::result::Result::err)
                                                                                            .map(|err| {
                                                                                                view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                                                            })
                                                                                    }}
                                                                                </form>
    }
}

#[derive(Clone, Copy)]
struct KeyRows {
    delete_key_password: ReadSignal<String>,
    set_delete_key_password: WriteSignal<String>,
    delete_key_action: Action<(String, String), Result<(), AppError>>,
    set_show_delete_key_form: WriteSignal<Option<String>>,
    security_keys:
        LocalResource<Result<Vec<crate::features::me::types::SecurityKeySummary>, AppError>>,
    show_delete_key_form: ReadSignal<Option<String>>,
}

/// Lists credentials with row-bound delete confirmation state.
fn key_list(state: KeyRows) -> impl IntoView {
    let KeyRows {
        delete_key_password,
        set_delete_key_password,
        delete_key_action,
        set_show_delete_key_form,
        security_keys,
        show_delete_key_form,
    } = state;
    view! { <Show when=move || {
        security_keys.get().is_some_and(|r| r.is_ok_and(|keys| !keys.is_empty()))
    }>
        <div class="px-6 py-4 space-y-2">
            <For
                each=move || security_keys.get().and_then(std::result::Result::ok).unwrap_or_default()
                key=|key| key.credential_id.clone()
                children={
                    let show_delete_key_form = show_delete_key_form;

                    move |key| {
                        let credential_id = key.credential_id.clone();
                        let label = key.label.clone();

                        let credential_id_for_show = credential_id.clone();
                        let credential_id_for_delete = credential_id.clone();

                        view! {
                            <div class="flex flex-col space-y-4 group">
                                <div class=Theme::LIST_ITEM_FLAT>
                                    <div class="flex items-center space-x-3">
                                        <span class=Theme::ICON_SMALL>
                                            "key"
                                        </span>
                                        <div>
                                            <p class="text-sm text-gray-700 dark:text-gray-300 font-medium">
                                                {label}
                                            </p>
                                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                                {format!(
                                                    "Added {} | Last used {}",
                                                    format_rfc3339(&key.created_at),
                                                    key.last_used_at
                                                        .as_deref().map_or_else(|| {
                                                            "Never".to_string()
                                                        }, format_relative)
                                                )}
                                            </p>
                                        </div>
                                    </div>
                                    <span
                                        class="text-slate-300 hover:text-slate-600 transition-colors cursor-pointer"
                                        role="button"
                                        tabindex="0"
                                        aria-label="Remove security key"
                                        on:click={
                                            let credential_id = credential_id.clone();
                                            move |_| {
                                                set_show_delete_key_form.set(Some(credential_id.clone()));
                                            }
                                        }
                                        on:keydown={
                                            let credential_id = credential_id.clone();
                                            move |event| {
                                                if event.key() == "Enter" || event.key() == " " {
                                                    set_show_delete_key_form
                                                        .set(Some(credential_id.clone()));
                                                }
                                            }
                                        }
                                    >
                                        <span class="material-symbols-outlined text-sm">"delete"</span>
                                    </span>
                                </div>

                                <Show when=move || show_delete_key_form.get() == Some(credential_id_for_show.clone())>
                                    <div class="px-2">
                                        {delete_key_form(KeyRemoval { delete_key_password, set_delete_key_password, delete_key_action, set_show_delete_key_form, credential_id_for_delete: credential_id_for_delete.clone() })}
                                    </div>
                                </Show>
                            </div>
                        }
                    }
                }
            />
        </div>
    </Show> }
}
