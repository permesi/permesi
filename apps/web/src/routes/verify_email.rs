use crate::components::{Alert, AlertKind, AppShell, Button, Spinner};
use crate::features::auth::client;
use crate::features::auth::token;
use crate::features::auth::types::{ResendVerificationRequest, VerifyEmailRequest};
use leptos::prelude::*;
use wasm_bindgen::JsValue;
use web_sys::{UrlSearchParams, window};

#[derive(Clone, Debug, PartialEq)]
enum VerifyStatus {
    Idle,
    MissingToken,
    Pending,
    Success,
    Error(String),
}

#[derive(Clone, Debug, PartialEq)]
enum ResendStatus {
    Idle,
    Pending,
    Success,
    Error(String),
}

#[component]
pub fn VerifyEmailPage() -> impl IntoView {
    let (status, set_status) = signal(VerifyStatus::Idle);
    let (resend_email, set_resend_email) = signal(String::new());
    let (resend_status, set_resend_status) = signal(ResendStatus::Idle);

    let verify_action = Action::new_local(move |token_value: &String| {
        let token_value = token_value.clone();
        async move {
            let request = VerifyEmailRequest { token: token_value };
            let zero_token = token::fetch_zero_token().await?;
            client::verify_email(&request, &zero_token).await
        }
    });

    let resend_action = Action::new_local(move |email: &String| {
        let email = email.clone();
        async move {
            let request = ResendVerificationRequest { email };
            let zero_token = token::fetch_zero_token().await?;
            client::resend_verification(&request, &zero_token).await
        }
    });

    Effect::new(move |_| {
        if let Some(result) = verify_action.value().get() {
            match result {
                Ok(()) => set_status.set(VerifyStatus::Success),
                Err(err) => set_status.set(VerifyStatus::Error(err.to_string())),
            }
        }
    });

    Effect::new(move |_| {
        if status.get() != VerifyStatus::Idle {
            return;
        }

        match extract_token_from_hash() {
            Some(token) => {
                set_status.set(VerifyStatus::Pending);
                verify_action.dispatch(token);
            }
            None => set_status.set(VerifyStatus::MissingToken),
        }

        clear_token_fragment();
    });

    Effect::new(move |_| {
        if let Some(result) = resend_action.value().get() {
            match result {
                Ok(()) => set_resend_status.set(ResendStatus::Success),
                Err(err) => set_resend_status.set(ResendStatus::Error(err.to_string())),
            }
        }
    });

    let on_resend_click = move |_| {
        let email_value = resend_email.get_untracked().trim().to_string();
        if email_value.is_empty() {
            set_resend_status.set(ResendStatus::Error(
                "Email is required to resend verification.".to_string(),
            ));
            return;
        }
        if !email_value.contains('@') {
            set_resend_status.set(ResendStatus::Error(
                "Email address looks invalid.".to_string(),
            ));
            return;
        }

        set_resend_status.set(ResendStatus::Pending);
        resend_action.dispatch(email_value);
    };

    view! {
        <AppShell>
            <div class="max-w-lg mx-auto">
                <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                    "Verify your email"
                </h1>
                {move || match status.get() {
                    VerifyStatus::Idle | VerifyStatus::Pending => view! {
                        <div class="mt-4">
                            <Spinner />
                        </div>
                    }
                    .into_any(),
                    VerifyStatus::Success => view! {
                        <div class="mt-4">
                            <Alert kind=AlertKind::Success message="Email verified. You can sign in now.".to_string() />
                        </div>
                    }
                    .into_any(),
                    VerifyStatus::MissingToken => view! {
                        <div class="mt-4">
                            <Alert
                                kind=AlertKind::Error
                                message="Missing verification token. Check your email link.".to_string()
                            />
                        </div>
                    }
                    .into_any(),
                    VerifyStatus::Error(message) => view! {
                        <div class="mt-4">
                            <Alert kind=AlertKind::Error message=message />
                        </div>
                    }
                    .into_any(),
                }}
                <div class="mt-8 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-700 dark:bg-neutral-800">
                    <h2 class="text-sm font-semibold text-gray-900 dark:text-white">"Need a new link?"</h2>
                    <p class="mt-1 text-sm text-gray-600 dark:text-gray-300">
                        "Enter your email to resend the verification link."
                    </p>
                    <div class="mt-4">
                        <label
                            class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
                            for="resend_email"
                        >
                            "Email"
                        </label>
                        <input
                            id="resend_email"
                            type="email"
                            class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                            autocomplete="email"
                            placeholder="name@inbox.im"
                            on:input=move |event| set_resend_email.set(event_target_value(&event))
                        />
                    </div>
                    <div class="mt-4">
                        <Button
                            button_type="button"
                            disabled=resend_action.pending()
                            on_click=on_resend_click
                        >
                            "Resend verification"
                        </Button>
                    </div>
                    {move || {
                        resend_action
                            .pending()
                            .get()
                            .then_some(view! { <div class="mt-4"><Spinner /></div> })
                    }}
                    {move || match resend_status.get() {
                        ResendStatus::Idle | ResendStatus::Pending => None,
                        ResendStatus::Success => Some(view! {
                            <div class="mt-4">
                                <Alert
                                    kind=AlertKind::Success
                                    message="If that email exists, a new link is on the way.".to_string()
                                />
                            </div>
                        }),
                        ResendStatus::Error(message) => Some(view! {
                            <div class="mt-4">
                                <Alert kind=AlertKind::Error message=message />
                            </div>
                        }),
                    }}
                </div>
            </div>
        </AppShell>
    }
}

fn extract_token_from_hash() -> Option<String> {
    let hash = window()?.location().hash().ok()?;
    let trimmed = hash.trim_start_matches('#');
    if trimmed.is_empty() {
        return None;
    }
    let params = UrlSearchParams::new_with_str(trimmed).ok()?;
    params.get("token")
}

fn clear_token_fragment() {
    let Some(window) = window() else {
        return;
    };
    let history = match window.history() {
        Ok(history) => history,
        Err(_) => return,
    };
    let _ = history.replace_state_with_url(&JsValue::NULL, "", Some("/verify-email"));
}
