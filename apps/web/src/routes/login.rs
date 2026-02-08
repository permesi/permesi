//! Login route that implements the client-side OPAQUE exchange. It keeps passwords
//! local, uses zero-token headers for permesi calls, and hydrates session state
//! via cookie-based auth.
//!
//! Flow Overview: Start OPAQUE with the server, finish the exchange, then fetch
//! the session and redirect to the home route.

use crate::{
    app_lib::{AppError, config::AppConfig},
    components::{Alert, AlertKind, AlreadySignedInPanel, Button, Spinner},
    features::auth::{
        client,
        opaque::{OpaqueSuite, identifiers, ksf, normalize_email},
        state::use_auth,
        token,
        types::{
            OpaqueLoginFinishRequest, OpaqueLoginStartRequest, PasskeyLoginFinishRequest,
            PasskeyLoginStartRequest, PasskeyLoginStartResponse, SessionKind, UserSession,
        },
        webauthn,
    },
    routes::paths,
};
use base64::Engine;
use js_sys::{Date, Reflect};
use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use leptos_router::hooks::use_navigate;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;
use wasm_bindgen::JsValue;

#[derive(Clone)]
/// Captures login form input for the async action without borrowing signals.
struct LoginInput {
    email: String,
    password: String,
}

#[derive(Clone)]
struct LoginResult {
    session: UserSession,
}

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

/// Renders the login form and drives the OPAQUE login flow.
/// On success it fetches the session cookie and updates auth state.
#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let passkey_supported = webauthn_supported();
    let (passkey_feedback, set_passkey_feedback) = signal::<Option<(AlertKind, String)>>(None);
    let (passkey_pending, set_passkey_pending) = signal(false);
    let (passkey_prepare_pending, set_passkey_prepare_pending) = signal(false);
    let (passkey_options, set_passkey_options) = signal::<Option<PasskeyLoginStartResponse>>(None);
    let (passkey_prepared_at, set_passkey_prepared_at) = signal::<Option<f64>>(None);
    let (show_password_fields, set_show_password_fields) = signal(false);

    let login_action = Action::new_local(move |input: &LoginInput| {
        let input = input.clone();
        async move {
            let config = AppConfig::load();
            let client_id = normalize_email(&input.email);
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            // Start OPAQUE locally so the password never leaves the browser.
            let start = ClientLogin::<OpaqueSuite>::start(&mut rng, input.password.as_bytes())
                .map_err(|_| AppError::Config("Unable to start secure login.".to_string()))?;
            let start_request = OpaqueLoginStartRequest {
                email: input.email.clone(),
                credential_request: base64::engine::general_purpose::STANDARD
                    .encode(start.message.serialize()),
            };
            // Zero tokens gate permesi auth calls and are separate from sessions.
            let zero_token = token::fetch_zero_token().await?;
            let start_response = client::opaque_login_start(&start_request, &zero_token).await?;

            // Decode the server's OPAQUE response before finishing the exchange.
            let response_bytes = base64::engine::general_purpose::STANDARD
                .decode(start_response.credential_response)
                .map_err(|_| AppError::Config("Invalid login response.".to_string()))?;
            let credential_response =
                CredentialResponse::<OpaqueSuite>::deserialize(&response_bytes).map_err(|_| {
                    AppError::Config("Unable to complete secure login.".to_string())
                })?;

            let ksf_params = ksf();
            // Bind identifiers and KSF params so the finish step is scoped correctly.
            let params = ClientLoginFinishParameters::new(
                None,
                identifiers(client_id.as_bytes(), server_id.as_bytes()),
                Some(&ksf_params),
            );
            let finish = start
                .state
                .finish(input.password.as_bytes(), credential_response, params)
                .map_err(|_| AppError::Config("Unable to complete secure login.".to_string()))?;

            let finish_request = OpaqueLoginFinishRequest {
                login_id: start_response.login_id,
                email: input.email.clone(),
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            // Finish login so the server can mint the session cookie.
            client::opaque_login_finish(&finish_request, &zero_token).await?;
            // Hydrate auth state by fetching the session established via cookie.
            let session = client::fetch_session().await?.ok_or_else(|| {
                AppError::Config("Login succeeded but no session found.".to_string())
            })?;
            Ok(LoginResult { session })
        }
    });

    let navigate_for_effect = navigate.clone();
    Effect::new(move |_| {
        if let Some(result) = login_action.value().get() {
            match result {
                Ok(login) => {
                    auth.set_session(login.session.clone());
                    match login.session.session_kind {
                        SessionKind::Full => {
                            if let Some(storage) = web_sys::window()
                                .and_then(|w| w.local_storage().ok())
                                .flatten()
                            {
                                let _ = storage.set_item("permesi_logged_in", "true");
                            }
                            navigate_for_effect(paths::DASHBOARD, Default::default());
                        }
                        SessionKind::MfaBootstrap => {
                            navigate_for_effect(paths::MFA_SETUP, Default::default());
                        }
                        SessionKind::MfaChallenge => {
                            navigate_for_effect(paths::MFA_CHALLENGE, Default::default());
                        }
                    }
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    {
        let set_passkey_options = set_passkey_options.clone();
        let set_passkey_prepared_at = set_passkey_prepared_at.clone();
        Effect::new(move |_| {
            let _ = email.get();
            set_passkey_options.set(None);
            set_passkey_prepared_at.set(None);
        });
    }

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        set_error.set(None);

        // Trim input before validation to avoid accidental whitespace failures.
        let email_value = email.get_untracked().trim().to_string();
        let password_value = password.get_untracked();
        if email_value.is_empty() || password_value.trim().is_empty() {
            set_error.set(Some(AppError::Config(
                "Email and password are required.".to_string(),
            )));
            return;
        }

        login_action.dispatch(LoginInput {
            email: email_value,
            password: password_value,
        });
    };

    view! {
        {
            move || {
                let auth = auth.clone();
                let navigate = navigate.clone();
                if auth.is_authenticated.get() {
                    view! { <AlreadySignedInPanel /> }.into_any()
                } else {
                    view! {
                        <div class="min-h-[70vh] flex items-center justify-center px-6 py-10">
                            <form
                                class="w-full max-w-md rounded-2xl border border-slate-200 bg-white/90 p-6 shadow-[0_20px_60px_-40px_rgba(15,23,42,0.35)] backdrop-blur sm:p-8"
                                on:submit=on_submit
                            >
                                <div class="space-y-2">
                                    <p class="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                                        "Sign in"
                                    </p>
                                    <h1 class="text-2xl font-semibold text-slate-900">
                                        "Sign in"
                                    </h1>
                                    <p class="text-sm text-slate-500">
                                        "Use a passkey for a faster, passwordless sign-in."
                                    </p>
                                </div>

                                <div class="mt-6 space-y-4">
                                    <div>
                                        <label
                                            class="block mb-2 text-sm font-medium text-slate-700"
                                            for="email"
                                        >
                                            "Email"
                                        </label>
                                        <input
                                            id="email"
                                            type="email"
                                            autofocus
                                            class="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-slate-900 focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
                                            autocomplete="email"
                                            inputmode="email"
                                            placeholder="name@inbox.im"
                                            required
                                            on:input=move |event| set_email.set(event_target_value(&event))
                                        />
                                    </div>

                                    <button
                                        type="button"
                                        class="w-full rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800"
                                        class:opacity-70=move || {
                                            passkey_pending.get() || passkey_prepare_pending.get()
                                        }
                                        class:cursor-not-allowed=move || {
                                            passkey_pending.get() || passkey_prepare_pending.get()
                                        }
                                        disabled=move || {
                                            passkey_pending.get() || passkey_prepare_pending.get()
                                        }
                                        on:click=move |_| {
                                            set_passkey_feedback.set(None);
                                            if !passkey_supported {
                                                set_passkey_feedback.set(Some((
                                                    AlertKind::Info,
                                                    "Passkeys are not supported in this browser.".to_string(),
                                                )));
                                                return;
                                            }
                                            if passkey_pending.get_untracked()
                                                || passkey_prepare_pending.get_untracked()
                                            {
                                                return;
                                            }
                                            let email_value = email.get_untracked().trim().to_string();
                                            if email_value.is_empty() {
                                                set_passkey_feedback.set(Some((
                                                    AlertKind::Info,
                                                    "Email is required to use a passkey.".to_string(),
                                                )));
                                                return;
                                            }
                                            let prepared = passkey_options.get_untracked();
                                            if prepared.is_none() {
                                                set_passkey_feedback.set(Some((
                                                    AlertKind::Info,
                                                    "Preparing passkey login...".to_string(),
                                                )));
                                                start_passkey_prepare_and_auth(
                                                    auth.clone(),
                                                    navigate.clone(),
                                                    email_value,
                                                    set_passkey_prepare_pending,
                                                    set_passkey_feedback,
                                                    set_passkey_options,
                                                    set_passkey_prepared_at,
                                                    set_passkey_pending,
                                                );
                                                return;
                                            }
                                            let options = prepared.expect("checked");
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
                                                        auth.clone(),
                                                        navigate.clone(),
                                                        email_value,
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
                                                auth.clone(),
                                                navigate.clone(),
                                                options,
                                                set_passkey_feedback,
                                                set_passkey_pending,
                                            );
                                        }
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
                                </div>

                                {move || {
                                    if show_password_fields.get() {
                                        view! {
                                            <div class="mt-6 space-y-4 border-t border-slate-100 pt-5">
                                                <div class="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                                                    "Continue with password"
                                                </div>
                                                <div>
                                                    <label
                                                        class="block mb-2 text-sm font-medium text-slate-700"
                                                        for="password"
                                                    >
                                                        "Password"
                                                    </label>
                                                    <input
                                                        id="password"
                                                        type="password"
                                                        class="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-slate-900 focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
                                                        autocomplete="current-password"
                                                        required
                                                        on:input=move |event| set_password.set(event_target_value(&event))
                                                    />
                                                </div>
                                                <Button
                                                    button_type="submit"
                                                    disabled=login_action.pending()
                                                >
                                                    "Continue with password"
                                                </Button>
                                            </div>
                                        }
                                            .into_any()
                                    } else {
                                        view! {
                                            <p class="mt-4 text-xs text-slate-400">
                                                "Prefer passkeys. Passwords are available if needed."
                                            </p>
                                        }
                                            .into_any()
                                    }
                                }}

                                {move || {
                                    login_action
                                        .pending()
                                        .get()
                                        .then_some(view! { <div class="mt-4"><Spinner /></div> })
                                }}
                                {move || {
                                    error
                                        .get()
                                        .map(|err| {
                                            let message = format_error(&err);
                                            view! {
                                                <div class="mt-4">
                                                    <Alert kind=AlertKind::Error message=message />
                                                </div>
                                            }
                                        })
                                }}
                            </form>
                        </div>
                    }
                        .into_any()
                }
            }
        }
    }
}

fn start_passkey_prepare_and_auth<N>(
    auth: crate::features::auth::state::AuthContext,
    navigate: N,
    email_value: String,
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
            client::passkey_login_start(
                &PasskeyLoginStartRequest { email: email_value },
                &zero_token,
            )
            .await
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
                auth.set_session(login.session.clone());
                match login.session.session_kind {
                    SessionKind::Full => {
                        if let Some(storage) = web_sys::window()
                            .and_then(|w| w.local_storage().ok())
                            .flatten()
                        {
                            let _ = storage.set_item("permesi_logged_in", "true");
                        }
                        navigate(paths::DASHBOARD, Default::default());
                    }
                    SessionKind::MfaBootstrap => {
                        navigate(paths::MFA_SETUP, Default::default());
                    }
                    SessionKind::MfaChallenge => {
                        navigate(paths::MFA_CHALLENGE, Default::default());
                    }
                }
            }
            Err(err) => {
                set_passkey_feedback.set(Some((AlertKind::Error, err.to_string())));
            }
        }
        set_passkey_pending.set(false);
    });
}

/// Maps internal errors to user-facing strings without leaking details.
fn format_error(err: &AppError) -> String {
    match err {
        AppError::Config(message) => message.clone(),
        _ => err.to_string(),
    }
}
