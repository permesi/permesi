//! Passkey (WebAuthn) UI section for the security settings page.

use crate::{
    app_lib::theme::Theme,
    app_lib::{AppError, config::AppConfig},
    components::{Alert, AlertKind, Spinner},
    features::{
        auth::{
            client as auth_client,
            opaque::{OpaqueSuite, identifiers, ksf, normalize_email},
            state::use_auth,
            token,
            types::{OpaqueReauthFinishRequest, OpaqueReauthStartRequest},
            webauthn,
        },
        passkeys::{
            client,
            types::{PasskeyRegisterFinishRequest, PasskeyRegisterOptionsResponse},
        },
    },
};
use base64::Engine;
use js_sys::{Date, Reflect};
use leptos::{ev, prelude::*, task::spawn_local};
use leptos_dom::helpers::{WindowListenerHandle, window_event_listener};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;
use std::rc::Rc;
use wasm_bindgen::{JsCast, JsValue};

fn webauthn_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    Reflect::has(window.as_ref(), &JsValue::from_str("PublicKeyCredential"))
        .ok()
        .unwrap_or(false)
}

fn challenge_timeout_ms(challenge: &serde_json::Value) -> Option<f64> {
    let pk_options = challenge.get("publicKey").unwrap_or(challenge);
    pk_options.get("timeout").and_then(|value| {
        value
            .as_f64()
            .or_else(|| value.as_u64().map(|ms| ms as f64))
    })
}

fn format_rfc3339(value: &str) -> String {
    let date = js_sys::Date::new(&JsValue::from_str(value));
    if date.get_time().is_nan() {
        value.to_string()
    } else {
        date.to_iso_string().into()
    }
}

fn format_relative(value: &str) -> String {
    let date = js_sys::Date::new(&JsValue::from_str(value));
    if date.get_time().is_nan() {
        return value.to_string();
    }
    let now_ms = js_sys::Date::now();
    let then_ms = date.get_time();
    let diff_ms = (now_ms - then_ms).max(0.0);
    let total_minutes = (diff_ms / 1000.0 / 60.0).floor() as i64;
    let cutoff_minutes = 30 * 24 * 60;
    if total_minutes >= cutoff_minutes {
        return format_rfc3339(value);
    }
    if total_minutes <= 0 {
        return "Just now".to_string();
    }
    let days = total_minutes / (60 * 24);
    let hours = (total_minutes % (60 * 24)) / 60;
    let mins = total_minutes % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{} day{}", days, if days == 1 { "" } else { "s" }));
        if hours > 0 {
            parts.push(format!(
                "{} hour{}",
                hours,
                if hours == 1 { "" } else { "s" }
            ));
        } else if mins > 0 {
            parts.push(format!("{} min{}", mins, if mins == 1 { "" } else { "s" }));
        }
    } else if hours > 0 {
        parts.push(format!(
            "{} hour{}",
            hours,
            if hours == 1 { "" } else { "s" }
        ));
        if mins > 0 {
            parts.push(format!("{} min{}", mins, if mins == 1 { "" } else { "s" }));
        }
    } else {
        parts.push(format!("{} min{}", mins, if mins == 1 { "" } else { "s" }));
    }

    format!("{} ago", parts.join(", "))
}

#[component]
pub fn PasskeysSection() -> impl IntoView {
    let auth = use_auth();
    let supported = webauthn_supported();
    let passkeys = LocalResource::new(move || async move { client::list_credentials().await });
    let (preview_mode, set_preview_mode) = signal(false);
    let (feedback, set_feedback) = signal::<Option<(AlertKind, String)>>(None);
    let (prepared_options, set_prepared_options) =
        signal::<Option<PasskeyRegisterOptionsResponse>>(None);
    let (prepared_at, set_prepared_at) = signal::<Option<f64>>(None);
    let (prepare_pending, set_prepare_pending) = signal(false);
    let (show_delete_passkey_form, set_show_delete_passkey_form) = signal::<Option<String>>(None);
    let (delete_passkey_password, set_delete_passkey_password) = signal(String::new());
    let section_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    let click_listener: StoredValue<Option<WindowListenerHandle>> = StoredValue::new(None);

    Effect::new(move |_| {
        if let Some(Ok(list)) = passkeys.get() {
            set_preview_mode.set(list.preview_mode);
        }
    });

    Effect::new(move |_| {
        let has_feedback = feedback.get().is_some();
        if has_feedback {
            let has_listener = click_listener
                .try_read_value()
                .map(|handle| handle.is_some())
                .unwrap_or(false);
            if has_listener {
                return;
            }
            let set_feedback = set_feedback.clone();
            let section_ref = section_ref.clone();
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
        } else if let Some(mut stored) = click_listener.try_write_value() {
            if let Some(handle) = stored.take() {
                handle.remove();
            }
        }
    });

    on_cleanup(move || {
        if let Some(mut stored) = click_listener.try_write_value() {
            if let Some(handle) = stored.take() {
                handle.remove();
            }
        }
    });

    let (create_pending, set_create_pending) = signal(false);
    let create_disabled = Signal::derive(move || create_pending.get());

    let prepare_registration = {
        let set_preview_mode = set_preview_mode.clone();
        let set_prepared_options = set_prepared_options.clone();
        let set_prepared_at = set_prepared_at.clone();
        let set_prepare_pending = set_prepare_pending.clone();
        let set_feedback = set_feedback.clone();
        Rc::new(move |announce: bool| {
            if prepare_pending.get_untracked() {
                return;
            }
            set_prepare_pending.set(true);
            let set_preview_mode = set_preview_mode.clone();
            let set_prepared_options = set_prepared_options.clone();
            let set_prepared_at = set_prepared_at.clone();
            let set_prepare_pending = set_prepare_pending.clone();
            let set_feedback = set_feedback.clone();
            spawn_local(async move {
                let result: Result<PasskeyRegisterOptionsResponse, AppError> = async {
                    let zero_token = token::fetch_zero_token().await?;
                    client::register_options(&zero_token).await
                }
                .await;

                match result {
                    Ok(options) => {
                        set_preview_mode.set(options.preview_mode);
                        set_prepared_at.set(Some(Date::now()));
                        set_prepared_options.set(Some(options));
                        if announce {
                            set_feedback.set(Some((
                                AlertKind::Info,
                                "Passkey request ready. Click Create passkey to continue."
                                    .to_string(),
                            )));
                        }
                    }
                    Err(err) => {
                        if announce {
                            set_feedback.set(Some((AlertKind::Error, err.to_string())));
                        }
                    }
                }
                set_prepare_pending.set(false);
            });
        })
    };

    let prepared_once = StoredValue::new(false);
    {
        let prepare_registration = prepare_registration.clone();
        Effect::new(move |_| {
            if supported && !prepared_once.get_value() {
                prepared_once.set_value(true);
                prepare_registration(false);
            }
        });
    }

    let delete_action = Action::new_local(move |(credential_id, password): &(String, String)| {
        let credential_id = credential_id.clone();
        let password = password.clone();
        let auth = auth.clone();
        async move {
            let config = AppConfig::load();
            let client_id = normalize_email(
                &auth
                    .session
                    .get_untracked()
                    .map(|s| s.email)
                    .unwrap_or_default(),
            );
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            let start = ClientLogin::<OpaqueSuite>::start(&mut rng, password.as_bytes())
                .map_err(|_| AppError::Config("Unable to start secure re-auth.".to_string()))?;
            let start_request = OpaqueReauthStartRequest {
                credential_request: base64::engine::general_purpose::STANDARD
                    .encode(start.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            let start_response =
                auth_client::opaque_reauth_start(&start_request, &zero_token).await?;

            let response_bytes = base64::engine::general_purpose::STANDARD
                .decode(start_response.credential_response)
                .map_err(|_| AppError::Config("Invalid re-auth response.".to_string()))?;
            let credential_response =
                CredentialResponse::<OpaqueSuite>::deserialize(&response_bytes).map_err(|_| {
                    AppError::Config("Unable to complete secure re-auth.".to_string())
                })?;

            let ksf_params = ksf();
            let params = ClientLoginFinishParameters::new(
                None,
                identifiers(client_id.as_bytes(), server_id.as_bytes()),
                Some(&ksf_params),
            );
            let finish = start
                .state
                .finish(password.as_bytes(), credential_response, params)
                .map_err(|_| AppError::Config("Unable to complete secure re-auth.".to_string()))?;

            let finish_request = OpaqueReauthFinishRequest {
                login_id: start_response.login_id,
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            auth_client::opaque_reauth_finish(&finish_request, &zero_token).await?;

            let zero_token = token::fetch_zero_token().await?;
            client::delete_credential(&credential_id, &zero_token).await
        }
    });
    let delete_action_value = delete_action.clone();

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
            <div class=Theme::ROW>
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3">
                        <span class=Theme::ICON>
                            "fingerprint"
                        </span>
                        <div>
                            <p class="text-sm font-medium text-gray-900 dark:text-white">
                                "Passkeys"
                            </p>
                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                {move || {
                                    if preview_mode.get() {
                                        "Preview mode enabled. Passkeys are not stored yet."
                                    } else {
                                        "Use a passkey to sign in without a password."
                                    }
                                }}
                            </p>
                        </div>
                    </div>
                    <button
                        on:click=move |_| {
                            if !supported {
                                set_feedback.set(Some((
                                    AlertKind::Info,
                                    "Passkeys are not supported in this browser.".to_string(),
                                )));
                                return;
                            }
                            if create_pending.get_untracked() {
                                return;
                            }
                            let passkeys = passkeys.clone();
                            let prepare_registration = prepare_registration.clone();
                            let set_feedback = set_feedback.clone();
                            let set_create_pending = set_create_pending.clone();
                            let set_prepared_options = set_prepared_options.clone();
                            let set_prepared_at = set_prepared_at.clone();
                            let prepared_options = prepared_options.get_untracked();
                            let prepared_at = prepared_at.get_untracked();
                            let prepare_pending = prepare_pending.get_untracked();
                            if prepared_options.is_none() {
                                if !prepare_pending {
                                    prepare_registration(true);
                                }
                                set_feedback.set(Some((
                                    AlertKind::Info,
                                    "Preparing passkey request. Click Create passkey again.".to_string(),
                                )));
                                return;
                            }
                            let options = prepared_options.expect("checked above");
                            if let (Some(prepared_at), Some(timeout_ms)) =
                                (prepared_at, challenge_timeout_ms(&options.challenge))
                            {
                                let elapsed = Date::now() - prepared_at;
                                if elapsed.is_finite() && elapsed > timeout_ms {
                                    set_prepared_options.set(None);
                                    set_prepared_at.set(None);
                                    if !prepare_pending {
                                        prepare_registration(true);
                                    }
                                    set_feedback.set(Some((
                                        AlertKind::Info,
                                        "Passkey request expired. Click Create passkey again."
                                            .to_string(),
                                    )));
                                    return;
                                }
                            }
                            let promise = match webauthn::begin_register_key(&options.challenge) {
                                Ok(promise) => promise,
                                Err(err) => {
                                    set_feedback.set(Some((AlertKind::Error, err.to_string())));
                                    set_create_pending.set(false);
                                    return;
                                }
                            };
                            set_feedback.set(Some((
                                AlertKind::Info,
                                "Starting passkey registration...".to_string(),
                            )));
                            set_create_pending.set(true);
                            set_prepared_options.set(None);
                            set_prepared_at.set(None);
                            spawn_local(async move {
                                let result: Result<_, AppError> = async {
                                    let response = webauthn::finish_register_key(promise).await?;

                                    let zero_token = token::fetch_zero_token().await?;
                                    client::register_finish(
                                        &PasskeyRegisterFinishRequest {
                                            reg_id: options.reg_id,
                                            response,
                                        },
                                        &zero_token,
                                    )
                                    .await
                                }
                                .await;

                                match result {
                                    Ok(response) => {
                                        let message = response
                                            .warning
                                            .unwrap_or_else(|| "Passkey created.".to_string());
                                        let kind = if response.stored {
                                            AlertKind::Success
                                        } else {
                                            AlertKind::Info
                                        };
                                        set_feedback.set(Some((kind, message)));
                                        passkeys.refetch();
                                    }
                                    Err(err) => {
                                        set_feedback.set(Some((AlertKind::Error, err.to_string())));
                                    }
                                }
                                set_create_pending.set(false);
                            });
                        }
                        class="text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer whitespace-nowrap shrink-0"
                        class:cursor-not-allowed=move || create_disabled.get()
                        class:opacity-70=move || create_disabled.get()
                        disabled=move || create_disabled.get()
                    >
                        "Create passkey"
                    </button>
                </div>
            </div>

            {move || {
                feedback
                    .get()
                    .map(|(kind, message)| view! { <div class="px-6 py-2"><Alert kind=kind message=message /></div> })
            }}
            {move || create_pending.get().then_some(view! { <div class="px-6 py-2"><Spinner /></div> })}

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
                                        let delete_action = delete_action.clone();
                                        let set_show_delete_passkey_form = set_show_delete_passkey_form.clone();
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
                                                                        .as_deref()
                                                                        .map(format_rfc3339)
                                                                        .unwrap_or_else(|| {
                                                                            "date unavailable".to_string()
                                                                        }),
                                                                    cred.last_used_at
                                                                        .as_deref()
                                                                        .map(format_relative)
                                                                        .unwrap_or_else(|| "Never".to_string())
                                                                )}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    {remove_button}
                                                </div>
                                                <Show when=move || show_delete_passkey_form.get() == Some(credential_id_for_show.clone())>
                                                    <div class="px-2">
                                                        <form
                                                            class="space-y-4 max-w-md bg-red-50 dark:bg-red-900/10 p-4 rounded-lg border border-red-100 dark:border-red-900/30"
                                                            on:submit={
                                                                let credential_id = credential_id_for_delete.clone();
                                                                let delete_action = delete_action.clone();
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
                                                                    .and_then(|res| res.err())
                                                                    .map(|err| {
                                                                        view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                                    })
                                                            }}
                                                        </form>
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
        </div>
    }
}
