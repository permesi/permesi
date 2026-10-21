//! Browser registration preparation and completion for passkeys.
//! The existing server ceremony remains authoritative; pending challenges stay local.
//!
//! Flow Overview: Prepare options, begin browser mediation inside a click, then
//! complete and submit its proof asynchronously. Failed proof never stores a credential.

use super::webauthn_supported;
use crate::{
    app_lib::{AppError, theme::Theme},
    components::{Alert, AlertKind, Spinner},
    features::{
        auth::{token, webauthn},
        passkeys::{
            client,
            types::{
                PasskeyCredentialListResponse, PasskeyRegisterFinishRequest,
                PasskeyRegisterOptionsResponse,
            },
        },
    },
};
use js_sys::Date;
use leptos::{prelude::*, task::spawn_local};
use std::rc::Rc;

/// Prepares and finishes registration without exposing the browser challenge to other views.
#[component]
pub(super) fn CreatePasskeyControl(
    passkeys: LocalResource<Result<PasskeyCredentialListResponse, AppError>>,
    feedback: ReadSignal<Option<(AlertKind, String)>>,
    set_feedback: WriteSignal<Option<(AlertKind, String)>>,
) -> impl IntoView {
    let supported = webauthn_supported();
    let (preview_mode, set_preview_mode) = signal(false);
    let (prepared_options, set_prepared_options) =
        signal::<Option<PasskeyRegisterOptionsResponse>>(None);
    let (prepared_at, set_prepared_at) = signal::<Option<f64>>(None);
    let (prepare_pending, set_prepare_pending) = signal(false);
    Effect::new(move |_| {
        if let Some(Ok(list)) = passkeys.get() {
            set_preview_mode.set(list.preview_mode);
        }
    });

    let (create_pending, set_create_pending) = signal(false);
    let create_disabled = Signal::derive(move || create_pending.get());

    let registration = Registration {
        supported,
        passkeys,
        create_pending,
        set_create_pending,
        prepare_pending,
        set_prepare_pending,
        prepared_options,
        set_prepared_options,
        prepared_at,
        set_prepared_at,
        set_preview_mode,
        set_feedback,
    };

    let prepare_registration =
        { Rc::new(move |announce: bool| prepare_options(registration, announce)) };

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

    view! {
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
                        on:click=move |_| create_passkey(registration, &*prepare_registration)
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

    }
}

/// Reads the browser timeout without extending the server-side challenge lifetime.
fn challenge_timeout_ms(challenge: &serde_json::Value) -> Option<f64> {
    let pk_options = challenge.get("publicKey").unwrap_or(challenge);
    pk_options
        .get("timeout")
        .and_then(serde_json::Value::as_f64)
}

#[derive(Clone, Copy)]
struct Registration {
    supported: bool,
    passkeys: LocalResource<Result<PasskeyCredentialListResponse, AppError>>,
    create_pending: ReadSignal<bool>,
    set_create_pending: WriteSignal<bool>,
    prepare_pending: ReadSignal<bool>,
    set_prepare_pending: WriteSignal<bool>,
    prepared_options: ReadSignal<Option<PasskeyRegisterOptionsResponse>>,
    set_prepared_options: WriteSignal<Option<PasskeyRegisterOptionsResponse>>,
    prepared_at: ReadSignal<Option<f64>>,
    set_prepared_at: WriteSignal<Option<f64>>,
    set_preview_mode: WriteSignal<bool>,
    set_feedback: WriteSignal<Option<(AlertKind, String)>>,
}

/// Prepares a server challenge without starting browser mediation.
fn prepare_options(state: Registration, announce: bool) {
    let Registration {
        prepare_pending,
        set_prepare_pending,
        set_prepared_options,
        set_prepared_at,
        set_preview_mode,
        set_feedback,
        ..
    } = state;

    if prepare_pending.get_untracked() {
        return;
    }
    set_prepare_pending.set(true);
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
                        "Passkey request ready. Click Create passkey to continue.".to_string(),
                    )));
                }
            }
            Err(err) => {
                if announce {
                    set_feedback.set(Some((
                        AlertKind::Error,
                        super::super::factor_mutation_error(&err),
                    )));
                }
            }
        }
        set_prepare_pending.set(false);
    });
}

/// Invokes browser registration synchronously after the unchanged preparation/expiry checks.
fn create_passkey(state: Registration, prepare_registration: &dyn Fn(bool)) {
    let Registration {
        supported,
        create_pending,
        set_create_pending,
        prepare_pending,
        prepared_options,
        set_prepared_options,
        prepared_at,
        set_prepared_at,
        set_feedback,
        ..
    } = state;

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
    let Some(options) = prepared_options else {
        return;
    };
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
                "Passkey request expired. Click Create passkey again.".to_string(),
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
    spawn_local(complete_registration(state, options, promise));
}

/// Finishes an already-started browser ceremony and submits its proof to the server.
async fn complete_registration(
    state: Registration,
    options: PasskeyRegisterOptionsResponse,
    promise: js_sys::Promise,
) {
    let Registration {
        passkeys,
        set_feedback,
        set_create_pending,
        ..
    } = state;

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
            set_feedback.set(Some((
                AlertKind::Error,
                super::super::factor_mutation_error(&err),
            )));
        }
    }
    set_create_pending.set(false);
}
