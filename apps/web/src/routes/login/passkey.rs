//! Passkey sign-in preparation, browser mediation and server session hydration.
//!
//! Flow Overview: Prepared options start browser mediation within the click;
//! the existing first-click fallback fetches options asynchronously before mediation.
//! Both paths submit proof and navigate according to the server session kind.

use super::LoginResult;
use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Spinner},
    features::auth::{
        client,
        state::use_auth,
        token,
        types::{PasskeyLoginFinishRequest, PasskeyLoginStartRequest, PasskeyLoginStartResponse},
        webauthn,
    },
};
use js_sys::{Date, Reflect};
use leptos::{prelude::*, task::spawn_local};
use leptos_router::hooks::use_navigate;
use wasm_bindgen::JsValue;

/// Detects browser support without treating it as authentication authority.
fn webauthn_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    Reflect::has(window.as_ref(), &JsValue::from_str("PublicKeyCredential"))
        .ok()
        .unwrap_or(false)
}

/// Reads the issued browser timeout without altering the server challenge.
fn challenge_timeout_ms(challenge: &serde_json::Value) -> Option<f64> {
    let pk_options = challenge.get("publicKey").unwrap_or(challenge);
    pk_options
        .get("timeout")
        .and_then(serde_json::Value::as_f64)
}

/// Offers passkey login while keeping challenge preparation and browser mediation local.
#[component]
pub(super) fn PasskeySignIn(
    show_password_fields: ReadSignal<bool>,
    set_show_password_fields: WriteSignal<bool>,
) -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let passkey_supported = webauthn_supported();
    let (passkey_feedback, set_passkey_feedback) = signal::<Option<(AlertKind, String)>>(None);
    let (passkey_pending, set_passkey_pending) = signal(false);
    let (passkey_prepare_pending, set_passkey_prepare_pending) = signal(false);
    let (passkey_options, set_passkey_options) = signal::<Option<PasskeyLoginStartResponse>>(None);
    let (passkey_prepared_at, set_passkey_prepared_at) = signal::<Option<f64>>(None);
    view! {
                                    <button
                                        type="button"
                                        class="w-full rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800 cursor-pointer disabled:cursor-not-allowed"
                                        class:opacity-70=move || {
                                            passkey_pending.get() || passkey_prepare_pending.get()
                                        }
                                        class:cursor-not-allowed=move || {
                                            passkey_pending.get() || passkey_prepare_pending.get()
                                        }
                                        disabled=move || {
                                            passkey_pending.get() || passkey_prepare_pending.get()
                                        }
                                        on:click=move |_| start_login(PasskeyLogin { passkey_supported, passkey_pending, set_passkey_pending, passkey_prepare_pending, set_passkey_prepare_pending, passkey_options, set_passkey_options, passkey_prepared_at, set_passkey_prepared_at, set_passkey_feedback }, auth, navigate.clone())
                                    >
                                        <span class="flex items-center justify-center space-x-2">
                                            {move || if passkey_pending.get() { view! { <Spinner /> }.into_any() } else { view! { <span>"Use passkey"</span> }.into_any() }}
                                        </span>
                                    </button>

                                    {move || {
                                        passkey_feedback.get().map(|(kind, message)| {
                                            view! { <Alert kind=kind message=message /> }
                                        })
                                    }}

                                    <div class="pt-2">
                                        <button
                                            type="button"
                                            class="text-sm font-medium text-slate-600 underline decoration-slate-300 underline-offset-4 transition hover:text-slate-900 cursor-pointer"
                                            on:click=move |_| {
                                                set_show_password_fields.update(|value| *value = !*value);
                                            }
                                        >
                                            {move || {
                                                if show_password_fields.get() {
                                                    "Hide password fields"
                                                } else {
                                                    "Use password instead"
                                                }
                                            }}
                                        </button>
                                    </div>
    }
}

/// Fetches fresh options and starts the existing browser-mediated login ceremony.
fn start_passkey_prepare_and_auth<N>(
    auth: crate::features::auth::state::AuthContext,
    navigate: N,
    set_passkey_prepare_pending: WriteSignal<bool>,
    set_passkey_feedback: WriteSignal<Option<(AlertKind, String)>>,
    set_passkey_options: WriteSignal<Option<PasskeyLoginStartResponse>>,
    set_passkey_prepared_at: WriteSignal<Option<f64>>,
    set_passkey_pending: WriteSignal<bool>,
) where
    N: Fn(&str, leptos_router::NavigateOptions) + Clone + 'static,
{
    set_passkey_prepare_pending.set(true);
    spawn_local(async move {
        let result: Result<PasskeyLoginStartResponse, AppError> = async {
            let zero_token = token::fetch_zero_token().await?;
            client::passkey_login_start(&PasskeyLoginStartRequest {}, &zero_token).await
        }
        .await;

        match result {
            Ok(options) => {
                set_passkey_prepared_at.set(Some(Date::now()));
                set_passkey_options.set(Some(options.clone()));
                start_passkey_auth(
                    auth,
                    navigate,
                    options,
                    set_passkey_feedback,
                    set_passkey_pending,
                );
            }
            Err(err) => {
                set_passkey_feedback.set(Some((AlertKind::Error, err.to_string())));
            }
        }
        set_passkey_prepare_pending.set(false);
    });
}

/// Submits browser proof and hydrates only the server-issued cookie session.
fn start_passkey_auth<N>(
    auth: crate::features::auth::state::AuthContext,
    navigate: N,
    options: PasskeyLoginStartResponse,
    set_passkey_feedback: WriteSignal<Option<(AlertKind, String)>>,
    set_passkey_pending: WriteSignal<bool>,
) where
    N: Fn(&str, leptos_router::NavigateOptions) + Clone + 'static,
{
    let promise = match webauthn::begin_authenticate_key(&options.challenge) {
        Ok(promise) => promise,
        Err(err) => {
            set_passkey_feedback.set(Some((AlertKind::Error, err.to_string())));
            return;
        }
    };
    set_passkey_feedback.set(Some((
        AlertKind::Info,
        "Waiting for passkey...".to_string(),
    )));
    set_passkey_pending.set(true);
    spawn_local(async move {
        let result: Result<LoginResult, AppError> = async {
            let response = webauthn::finish_authenticate_key(promise).await?;
            let zero_token = token::fetch_zero_token().await?;
            client::passkey_login_finish(
                &PasskeyLoginFinishRequest {
                    auth_id: options.auth_id,
                    response,
                },
                &zero_token,
            )
            .await?;
            let session = client::fetch_session().await?.ok_or_else(|| {
                AppError::Config("Login succeeded but no session found.".to_string())
            })?;
            Ok(LoginResult { session })
        }
        .await;

        match result {
            Ok(login) => {
                super::accept_login(auth, navigate, &login.session);
            }
            Err(err) => {
                set_passkey_feedback.set(Some((AlertKind::Error, err.to_string())));
            }
        }
        set_passkey_pending.set(false);
    });
}

#[derive(Clone, Copy)]
struct PasskeyLogin {
    passkey_supported: bool,
    passkey_pending: ReadSignal<bool>,
    set_passkey_pending: WriteSignal<bool>,
    passkey_prepare_pending: ReadSignal<bool>,
    set_passkey_prepare_pending: WriteSignal<bool>,
    passkey_options: ReadSignal<Option<PasskeyLoginStartResponse>>,
    set_passkey_options: WriteSignal<Option<PasskeyLoginStartResponse>>,
    passkey_prepared_at: ReadSignal<Option<f64>>,
    set_passkey_prepared_at: WriteSignal<Option<f64>>,
    set_passkey_feedback: WriteSignal<Option<(AlertKind, String)>>,
}

/// Starts browser mediation synchronously within the user gesture, retaining timeout checks.
fn start_login<N>(state: PasskeyLogin, auth: crate::features::auth::state::AuthContext, navigate: N)
where
    N: Fn(&str, leptos_router::NavigateOptions) + Clone + 'static,
{
    let PasskeyLogin {
        passkey_supported,
        passkey_pending,
        set_passkey_pending,
        passkey_prepare_pending,
        set_passkey_prepare_pending,
        passkey_options,
        set_passkey_options,
        passkey_prepared_at,
        set_passkey_prepared_at,
        set_passkey_feedback,
    } = state;

    set_passkey_feedback.set(None);
    if !passkey_supported {
        set_passkey_feedback.set(Some((
            AlertKind::Info,
            "Passkeys are not supported in this browser.".to_string(),
        )));
        return;
    }
    if passkey_pending.get_untracked() || passkey_prepare_pending.get_untracked() {
        return;
    }
    let prepared = passkey_options.get_untracked();
    if prepared.is_none() {
        set_passkey_feedback.set(Some((
            AlertKind::Info,
            "Preparing passkey login...".to_string(),
        )));
        start_passkey_prepare_and_auth(
            auth,
            navigate.clone(),
            set_passkey_prepare_pending,
            set_passkey_feedback,
            set_passkey_options,
            set_passkey_prepared_at,
            set_passkey_pending,
        );
        return;
    }
    let Some(options) = prepared else {
        return;
    };
    if let (Some(prepared_at), Some(timeout_ms)) = (
        passkey_prepared_at.get_untracked(),
        challenge_timeout_ms(&options.challenge),
    ) {
        let elapsed = Date::now() - prepared_at;
        if elapsed.is_finite() && elapsed > timeout_ms {
            set_passkey_options.set(None);
            set_passkey_prepared_at.set(None);
            set_passkey_feedback.set(Some((
                AlertKind::Info,
                "Passkey request expired. Preparing a new one...".to_string(),
            )));
            start_passkey_prepare_and_auth(
                auth,
                navigate.clone(),
                set_passkey_prepare_pending,
                set_passkey_feedback,
                set_passkey_options,
                set_passkey_prepared_at,
                set_passkey_pending,
            );
            return;
        }
    }
    set_passkey_options.set(None);
    set_passkey_prepared_at.set(None);
    start_passkey_auth(
        auth,
        navigate.clone(),
        options,
        set_passkey_feedback,
        set_passkey_pending,
    );
}
