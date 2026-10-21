//! Persisted passkey rows and password-confirmed delete controls.
//! Credential identifiers select a row; the server still verifies ownership.

use super::super::display::{format_relative, format_rfc3339};
use crate::{
    app_lib::{AppError, theme::Theme},
    components::{Alert, AlertKind, Spinner},
    features::passkeys::types::PasskeyCredentialListResponse,
};
use leptos::prelude::*;

/// Lists persisted credentials and keeps delete controls scoped to their row.
#[component]
pub(super) fn PasskeyList(
    supported: bool,
    passkeys: LocalResource<Result<PasskeyCredentialListResponse, AppError>>,
    show_delete_passkey_form: ReadSignal<Option<String>>,
    set_show_delete_passkey_form: WriteSignal<Option<String>>,
    delete_passkey_password: ReadSignal<String>,
    set_delete_passkey_password: WriteSignal<String>,
    delete_action: Action<(String, String), Result<(), AppError>>,
) -> impl IntoView {
    view! {
            <Show
                when=move || supported
                fallback=|| ().into_any()
            >
                {move || match passkeys.get() {
                    None => view! { <div class="px-6 py-4"><Spinner /></div> }.into_any(),
                    Some(Err(err)) => view! {
                        <div class="px-6 py-4">
                            <Alert kind=AlertKind::Error message=err.to_string() />
                        </div>
                    }
                    .into_any(),
                    Some(Ok(list)) => {
                        if list.credentials.is_empty() {
                            ().into_any()
                        } else {
                            let preview = list.preview_mode;
                            view! {
                                <div class="px-6 py-4 space-y-2">
                                    {list.credentials.into_iter().map(|cred| {
                                                                                                        let id = cred.id.clone();
                                        let credential_id_for_show = id.clone();
                                        let credential_id_for_delete = id.clone();
                                        let remove_button = if preview {
                                            None
                                        } else {
                                            let id_for_click = id.clone();
                                            let id_for_keydown = id.clone();
                                            Some(view! {
                                                <span
                                                    class="text-slate-300 hover:text-slate-600 transition-colors cursor-pointer"
                                                    role="button"
                                                    tabindex="0"
                                                    aria-label="Remove passkey"
                                                    on:click=move |_| {
                                                        set_show_delete_passkey_form
                                                            .set(Some(id_for_click.clone()));
                                                    }
                                                    on:keydown=move |event| {
                                                        if event.key() == "Enter" || event.key() == " " {
                                                            set_show_delete_passkey_form
                                                                .set(Some(id_for_keydown.clone()));
                                                        }
                                                    }
                                                >
                                                    <span class="material-symbols-outlined text-sm">
                                                        "delete"
                                                    </span>
                                                </span>
                                            })
                                        };
                                        view! {
                                            <div class="flex flex-col space-y-4">
                                                <div class=move || format!("{} group", Theme::LIST_ITEM_FLAT)>
                                                    <div class="flex items-center space-x-3">
                                                        <span class=Theme::ICON_SMALL>
                                                            "key"
                                                        </span>
                                                        <div>
                                                            <p class="text-sm text-gray-700 dark:text-gray-200 font-medium">
                                                                {cred.label.unwrap_or_else(|| "Passkey".to_string())}
                                                            </p>
                                                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                                                {format!(
                                                                    "Added {} | Last used {}",
                                                                    cred.created_at
                                                                        .as_deref().map_or_else(|| {
                                                                            "date unavailable".to_string()
                                                                        }, format_rfc3339),
                                                                    cred.last_used_at
                                                                        .as_deref().map_or_else(|| "Never".to_string(), format_relative)
                                                                )}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    {remove_button}
                                                </div>
                                                <Show when=move || show_delete_passkey_form.get() == Some(credential_id_for_show.clone())>
                                                    <div class="px-2">
                                                        {delete_form(DeleteForm { delete_passkey_password, set_delete_passkey_password, set_show_delete_passkey_form, delete_action, credential_id_for_delete: credential_id_for_delete.clone() })}
                                                    </div>
                                                </Show>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }
                    }
                }}
            </Show>
    }
}

#[derive(Clone)]
struct DeleteForm {
    delete_passkey_password: ReadSignal<String>,
    set_delete_passkey_password: WriteSignal<String>,
    set_show_delete_passkey_form: WriteSignal<Option<String>>,
    delete_action: Action<(String, String), Result<(), AppError>>,
    credential_id_for_delete: String,
}

/// Renders the confirmation form using only its owning section's state.
fn delete_form(state: DeleteForm) -> impl IntoView {
    let DeleteForm {
        delete_passkey_password,
        set_delete_passkey_password,
        set_show_delete_passkey_form,
        delete_action,
        credential_id_for_delete,
    } = state;
    view! {
    <form
                                                                class="space-y-4 max-w-md bg-red-50 dark:bg-red-900/10 p-4 rounded-lg border border-red-100 dark:border-red-900/30"
                                                                on:submit={
                                                                    let credential_id = credential_id_for_delete.clone();
                                                                                                                            move |event: leptos::ev::SubmitEvent| {
                                                                        event.prevent_default();
                                                                        let password = delete_passkey_password.get_untracked();
                                                                        if password.trim().is_empty() {
                                                                            return;
                                                                        }
                                                                        delete_action.dispatch((credential_id.clone(), password));
                                                                    }
                                                                }
                                                            >
                                                                <p class="text-xs text-red-700 dark:text-red-300 mb-4">
                                                                    "Deleting this passkey will remove it as a sign-in method. Please enter your password to confirm."
                                                                </p>
                                                                <div>
                                                                    <label class="block mb-1 text-xs font-medium text-red-900 dark:text-red-200" for="delete_passkey_password">
                                                                        "Password"
                                                                    </label>
                                                                    <input
                                                                        id="delete_passkey_password"
                                                                        type="password"
                                                                        class="bg-white border border-red-200 text-gray-900 text-sm rounded-lg focus:ring-red-500 focus:border-red-500 block w-full p-2 dark:bg-gray-800 dark:border-red-900/50 dark:text-white"
                                                                        required
                                                                        on:input=move |event| set_delete_passkey_password.set(event_target_value(&event))
                                                                    />
                                                                </div>
                                                                <div class="pt-2 flex items-center gap-3">
                                                                    <button
                                                                        type="submit"
                                                                        disabled=delete_action.pending()
                                                                        class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 shadow-sm cursor-pointer"
                                                                    >
                                                                        "Remove passkey"
                                                                    </button>
                                                                    <button
                                                                        type="button"
                                                                        on:click=move |_| set_show_delete_passkey_form.set(None)
                                                                        class="px-4 py-2 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                                    >
                                                                        "Cancel"
                                                                    </button>
                                                                    {move || {
                                                                        delete_action.pending().get().then_some(view! { <Spinner /> })
                                                                    }}
                                                                </div>
                                                                {move || {
                                                                    delete_action
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
