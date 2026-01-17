//! Signup route that implements the client-side OPAQUE registration exchange. It
//! validates inputs locally, sends only OPAQUE messages to the API, and prompts
//! the user to verify their email before signing in. Requests are zero-token
//! gated to avoid unauthenticated abuse.
//!
//! Flow Overview: Start OPAQUE registration, finish the exchange, then display
//! the verification prompt.

use crate::{
    app_lib::{AppError, config::AppConfig},
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{
        client,
        opaque::{OpaqueSuite, identifiers, ksf, normalize_email},
        token,
        types::{OpaqueSignupFinishRequest, OpaqueSignupStartRequest},
    },
};
use base64::Engine;
use leptos::{ev::SubmitEvent, prelude::*};
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use rand::rngs::OsRng;

/// Minimum password length enforced by the client for early UX feedback.
const MIN_PASSWORD_LENGTH: usize = 12;
#[derive(Clone)]
/// Captures signup form input for the async action without borrowing signals.
struct SignupInput {
    email: String,
    password: String,
}

/// Renders the signup form and drives the OPAQUE registration flow.
/// On success it prompts the user to verify their email.
#[component]
pub fn SignUpPage() -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let (success, set_success) = signal(false);

    let signup_action = Action::new_local(move |input: &SignupInput| {
        let input = input.clone();
        async move {
            let config = AppConfig::load();
            let client_id = normalize_email(&input.email);
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            let start =
                ClientRegistration::<OpaqueSuite>::start(&mut rng, input.password.as_bytes())
                    .map_err(|_| AppError::Config("Unable to start secure signup.".to_string()))?;

            let start_request = OpaqueSignupStartRequest {
                email: input.email.clone(),
                registration_request: base64::engine::general_purpose::STANDARD
                    .encode(start.message.serialize()),
            };

            let zero_token = token::fetch_zero_token().await?;
            let start_response = client::opaque_signup_start(&start_request, &zero_token).await?;

            let response_bytes = base64::engine::general_purpose::STANDARD
                .decode(start_response.registration_response)
                .map_err(|_| AppError::Config("Invalid signup response.".to_string()))?;
            let registration_response = RegistrationResponse::<OpaqueSuite>::deserialize(
                &response_bytes,
            )
            .map_err(|_| AppError::Config("Unable to complete secure signup.".to_string()))?;

            let ksf_params = ksf();
            let params = ClientRegistrationFinishParameters::new(
                identifiers(client_id.as_bytes(), server_id.as_bytes()),
                Some(&ksf_params),
            );
            let finish = start
                .state
                .finish(
                    &mut rng,
                    input.password.as_bytes(),
                    registration_response,
                    params,
                )
                .map_err(|_| AppError::Config("Unable to complete secure signup.".to_string()))?;

            let finish_request = OpaqueSignupFinishRequest {
                email: input.email,
                registration_record: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };

            let zero_token = token::fetch_zero_token().await?;
            client::opaque_signup_finish(&finish_request, &zero_token).await
        }
    });

    Effect::new(move |_| {
        if let Some(result) = signup_action.value().get() {
            match result {
                Ok(()) => {
                    set_success.set(true);
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        set_error.set(None);
        set_success.set(false);

        let email_value = normalize_email(&email.get_untracked());
        let password_value = password.get_untracked();
        let confirm_value = confirm_password.get_untracked();

        if email_value.is_empty()
            || password_value.trim().is_empty()
            || confirm_value.trim().is_empty()
        {
            set_error.set(Some(AppError::Config(
                "Email and both password fields are required.".to_string(),
            )));
            return;
        }

        if !email_value.contains('@') {
            set_error.set(Some(AppError::Config(
                "Email address looks invalid.".to_string(),
            )));
            return;
        }

        if password_value != confirm_value {
            set_error.set(Some(AppError::Config(
                "Passwords do not match.".to_string(),
            )));
            return;
        }

        if password_value.trim().len() < MIN_PASSWORD_LENGTH {
            set_error.set(Some(AppError::Config(format!(
                "Password must be at least {MIN_PASSWORD_LENGTH} characters."
            ))));
            return;
        }

        signup_action.dispatch(SignupInput {
            email: email_value,
            password: password_value,
        });
    };

    view! {
        <div class="min-h-[70vh] flex items-center justify-center px-6 py-10">
            <form
                class="w-full max-w-md rounded-2xl border border-slate-200 bg-white/90 p-6 shadow-[0_20px_60px_-40px_rgba(15,23,42,0.35)] backdrop-blur sm:p-8"
                on:submit=on_submit
            >
                <div class="space-y-2">
                    <p class="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                        "Create account"
                    </p>
                    <h1 class="text-2xl font-semibold text-slate-900">
                        "Create account"
                    </h1>
                    <p class="text-sm text-slate-500">
                        "Start with a password. You can add passkeys after signing in."
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
                            autocomplete="new-password"
                            required
                            on:input=move |event| set_password.set(event_target_value(&event))
                        />
                    </div>
                    <div>
                        <label
                            class="block mb-2 text-sm font-medium text-slate-700"
                            for="confirm_password"
                        >
                            "Confirm password"
                        </label>
                        <input
                            id="confirm_password"
                            type="password"
                            class="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-slate-900 focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
                            autocomplete="new-password"
                            required
                            on:input=move |event| {
                                set_confirm_password.set(event_target_value(&event));
                            }
                        />
                    </div>

                    <Button button_type="submit" disabled=signup_action.pending()>
                        "Create account"
                    </Button>
                </div>

                {move || {
                    signup_action
                        .pending()
                        .get()
                        .then_some(view! { <div class="mt-4"><Spinner /></div> })
                }}
                {move || {
                    success
                        .get()
                        .then_some(view! {
                            <div class="mt-4">
                                <Alert
                                    kind=AlertKind::Success
                                    message="Check your email to verify your account.".to_string()
                                />
                            </div>
                        })
                }}
                {move || {
                    error.get().map(|err| {
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

/// Maps internal errors to user-facing strings without leaking details.
fn format_error(err: &AppError) -> String {
    match err {
        AppError::Config(message) => message.clone(),
        _ => err.to_string(),
    }
}
