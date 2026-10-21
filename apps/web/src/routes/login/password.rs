//! Password sign-in form and the existing OPAQUE browser ceremony.
//! Passwords remain local; only a server-established session drives navigation.
//!
//! Flow Overview: Submit OPAQUE proof, fetch the cookie-backed session, then route
//! according to the server-issued full or limited session kind.

use super::{LoginResult, passkey::PasskeySignIn};
use crate::{
    app_lib::{AppError, config::AppConfig},
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{
        client,
        opaque::{OpaqueSuite, identifiers, ksf, normalize_email},
        state::use_auth,
        token,
        types::{OpaqueLoginFinishRequest, OpaqueLoginStartRequest},
    },
};
use base64::Engine;
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::hooks::use_navigate;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use opaque_rand_core::OsRng;

#[derive(Clone)]
/// Captures login form input for the async action without borrowing signals.
struct LoginInput {
    email: String,
    password: String,
}

/// Owns browser-local password and passkey sign-in state.
#[component]
pub(super) fn LoginForm(expired_authorization: bool) -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let (show_password_fields, set_show_password_fields) = signal(false);

    let login_action =
        Action::new_local(move |input: &LoginInput| perform_password_login(input.clone()));

    let navigate_for_effect = navigate.clone();
    Effect::new(move |_| {
        if let Some(result) = login_action.value().get() {
            match result {
                Ok(login) => {
                    super::accept_login(auth, navigate_for_effect.clone(), &login.session);
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let on_submit =
        move |event: SubmitEvent| submit_login(&event, email, password, set_error, login_action);

    view! {
        <div class="min-h-[70vh] flex items-center justify-center px-6 py-10">
                            <form
                                class="w-full max-w-md rounded-2xl border border-slate-200 bg-white/90 p-6 shadow-[0_20px_60px_-40px_rgba(15,23,42,0.35)] backdrop-blur sm:p-8"
                                on:submit=on_submit
                            >
                                {expired_authorization.then(|| view! { <Alert kind=AlertKind::Info message="The authorization request expired. Start sign-in again from the application; this login cannot resume it.".to_owned() /> })}
                                {sign_in_heading()}

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

                                    <PasskeySignIn show_password_fields set_show_password_fields />
                                </div>

                                {move || {
                                    if show_password_fields.get() {
                                        view! {
                                            <PasswordFields set_password login_action />
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
}

/// Completes OPAQUE locally and accepts only the server-issued session cookie.
async fn perform_password_login(input: LoginInput) -> Result<LoginResult, AppError> {
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
    let credential_response = CredentialResponse::<OpaqueSuite>::deserialize(&response_bytes)
        .map_err(|_| AppError::Config("Unable to complete secure login.".to_string()))?;

    let ksf_params = ksf();
    // Bind identifiers and KSF params so the finish step is scoped correctly.
    let params = ClientLoginFinishParameters::new(
        None,
        identifiers(client_id.as_bytes(), server_id.as_bytes()),
        Some(&ksf_params),
    );
    let finish = start
        .state
        .finish(
            &mut rng,
            input.password.as_bytes(),
            credential_response,
            params,
        )
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
    let session = client::fetch_session()
        .await?
        .ok_or_else(|| AppError::Config("Login succeeded but no session found.".to_string()))?;
    Ok(LoginResult { session })
}

/// Maps internal errors to user-facing strings without leaking details.
fn format_error(err: &AppError) -> String {
    match err {
        AppError::Config(message) => message.clone(),
        _ => err.to_string(),
    }
}

/// Shows password input only when the owning form enables password sign-in.
#[component]
fn PasswordFields(
    set_password: WriteSignal<String>,
    login_action: Action<LoginInput, Result<LoginResult, AppError>>,
) -> impl IntoView {
    view! { <div class="mt-6 space-y-4 border-t border-slate-100 pt-5">
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
    </div> }
}

/// Presents the shared sign-in heading without owning authentication state.
fn sign_in_heading() -> impl IntoView {
    view! { <div class="space-y-2">
        <p class="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-400">
            "Sign in"
        </p>
        <h1 class="text-2xl font-semibold text-slate-900">
            "Sign in"
        </h1>
        <p class="text-sm text-slate-500">
            "Use a passkey for a faster, passwordless sign-in."
        </p>
    </div> }
}

/// Validates local form input before dispatching the existing OPAQUE login action.
fn submit_login(
    event: &SubmitEvent,
    email: ReadSignal<String>,
    password: ReadSignal<String>,
    set_error: WriteSignal<Option<AppError>>,
    login_action: Action<LoginInput, Result<LoginResult, AppError>>,
) {
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
}
