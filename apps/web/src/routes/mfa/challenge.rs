//! MFA Challenge route.
//!
//! Handles TOTP and recovery code verification during login:
//! 1. Ask for TOTP code.
//! 2. Option to use recovery code.
//! 3. Verify and redirect to dashboard.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{
        client,
        state::use_auth,
        types::{MfaRecoveryRequest, MfaTotpVerifyRequest},
    },
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

#[component]
pub fn MfaChallengePage() -> impl IntoView {
    let _auth = use_auth();
    let navigate = use_navigate();

    let (code, set_code) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let (show_recovery, set_show_recovery) = signal(false);

    let totp_enabled = move || _auth.session.get().map(|s| s.totp_enabled).unwrap_or(true);
    let webauthn_enabled = move || {
        _auth
            .session
            .get()
            .map(|s| s.webauthn_enabled)
            .unwrap_or(false)
    };

    let authenticate_key_action = Action::new_local(move |_: &()| {
        async move {
            // 1. Start WebAuthn authentication
            let start_response = client::mfa_webauthn_authenticate_start().await?;

            // 2. Browser interaction (hardware key touch)
            let auth_response =
                crate::features::auth::webauthn::authenticate_key(&start_response.challenge)
                    .await?;

            // 3. Finish authentication
            let session_token = client::mfa_webauthn_authenticate_finish(
                &crate::features::auth::types::WebauthnAuthenticateFinishRequest {
                    auth_id: start_response.auth_id,
                    response: auth_response,
                },
            )
            .await?;

            // 4. Fetch the full session
            let session = client::fetch_session(session_token.as_deref())
                .await?
                .ok_or_else(|| {
                    AppError::Config("Authentication succeeded but session not found.".to_string())
                })?;

            Ok::<(crate::features::auth::types::UserSession, Option<String>), AppError>((
                session,
                session_token,
            ))
        }
    });

    // Auto-trigger security key if it's the only factor available
    Effect::new(move |_| {
        if !show_recovery.get()
            && !totp_enabled()
            && webauthn_enabled()
            && authenticate_key_action.value().get().is_none()
            && !authenticate_key_action.pending().get()
        {
            authenticate_key_action.dispatch(());
        }
    });

    let verify_action = Action::new_local(move |code: &String| {
        // ... existing verify_action logic ...
        let code = code.clone();
        let is_recovery = show_recovery.get_untracked();
        async move {
            let session_token = if is_recovery {
                client::mfa_recovery(&MfaRecoveryRequest { code }).await?
            } else {
                client::mfa_totp_verify(&MfaTotpVerifyRequest { code }).await?
            };

            // After successful verification, fetch the new full session using the updated token
            let session = client::fetch_session(session_token.as_deref())
                .await?
                .ok_or_else(|| {
                    AppError::Config("Verification succeeded but session not found.".to_string())
                })?;

            Ok::<(crate::features::auth::types::UserSession, Option<String>), AppError>((
                session,
                session_token,
            ))
        }
    });

    let navigate_for_auth = navigate.clone();
    Effect::new(move |_| {
        if let Some(result) = authenticate_key_action.value().get() {
            match result {
                Ok((session, session_token)) => {
                    _auth.set_session(session);
                    if let Some(token) = session_token {
                        _auth.set_session_token(token);
                    }
                    if let Some(storage) = web_sys::window()
                        .and_then(|w| w.local_storage().ok())
                        .flatten()
                    {
                        let _ = storage.set_item("permesi_logged_in", "true");
                    }
                    navigate_for_auth(paths::DASHBOARD, Default::default());
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let navigate_for_verify = navigate.clone();
    Effect::new(move |_| {
        if let Some(result) = verify_action.value().get() {
            match result {
                Ok((session, session_token)) => {
                    // Update global state immediately
                    _auth.set_session(session.clone());
                    if let Some(token) = session_token {
                        _auth.set_session_token(token);
                    }

                    if show_recovery.get() {
                        navigate_for_verify(paths::MFA_SETUP, Default::default());
                    } else {
                        // Success: The server issued a full session cookie.
                        if let Some(storage) = web_sys::window()
                            .and_then(|w| w.local_storage().ok())
                            .flatten()
                        {
                            let _ = storage.set_item("permesi_logged_in", "true");
                        }
                        navigate_for_verify(paths::DASHBOARD, Default::default());
                    }
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    view! {
        <div class="min-h-[70vh] flex items-center justify-center px-6 py-10">
            <div class="w-full max-w-md rounded-2xl border border-slate-200 bg-white/90 p-6 shadow-[0_20px_60px_-40px_rgba(15,23,42,0.35)] backdrop-blur sm:p-8">
                <div class="space-y-2">
                    <p class="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                        "Verify"
                    </p>
                    <h1 class="text-2xl font-semibold text-slate-900">
                        {move || if show_recovery.get() { "Recovery code" } else { "Two-factor check" }}
                    </h1>
                    <p class="text-sm text-slate-500">
                        {move || if show_recovery.get() {
                            "Enter a recovery code to regain access to your account."
                        } else if totp_enabled() {
                            "Enter the 6-digit code from your authenticator app."
                        } else {
                            "Confirm with your security key."
                        }}
                    </p>
                </div>

                <div class="mt-6 space-y-6">
                    <Show when=move || totp_enabled() || show_recovery.get()>
                        <div>
                            <label class="block mb-2 text-sm font-medium text-slate-700">
                                {move || if show_recovery.get() { "Recovery code" } else { "Verification code" }}
                            </label>
                            <input
                                type="text"
                                class="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-slate-900 focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
                                on:input=move |ev| set_code.set(event_target_value(&ev))
                                on:keydown=move |ev| {
                                    if ev.key() == "Enter" {
                                        verify_action.dispatch(code.get());
                                    }
                                }
                            />
                        </div>

                        <Button
                            disabled=verify_action.pending()
                            on:click=move |_| { verify_action.dispatch(code.get()); }
                        >
                            "Verify"
                        </Button>
                    </Show>

                    <Show when=move || !show_recovery.get() && webauthn_enabled()>
                        <Show when=totp_enabled>
                            <div class="relative my-6">
                                <div class="absolute inset-0 flex items-center" aria-hidden="true">
                                    <div class="w-full border-t border-slate-200"></div>
                                </div>
                                <div class="relative flex justify-center">
                                    <span class="px-3 bg-white text-[11px] text-slate-400 uppercase tracking-[0.2em]">
                                        "Or"
                                    </span>
                                </div>
                            </div>
                        </Show>

                        <button
                            type="button"
                            disabled=authenticate_key_action.pending()
                            on:click=move |_| { authenticate_key_action.dispatch(()); }
                            class="w-full inline-flex justify-center items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-slate-200 cursor-pointer"
                        >
                            <span class="material-symbols-outlined text-base">"key"</span>
                            {move || if authenticate_key_action.pending().get() {
                                "Waiting for key..."
                            } else {
                                "Use security key"
                            }}
                        </button>

                        {move || {
                            authenticate_key_action
                                .value()
                                .get()
                                .and_then(|res| res.err())
                                .map(|err| {
                                    view! { <div class="mt-2"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                })
                        }}
                    </Show>

                    <div class="text-center">
                        <button
                            on:click=move |_| {
                                set_show_recovery.update(|v| *v = !*v);
                                set_error.set(None);
                            }
                            class="text-sm font-medium text-slate-600 underline decoration-slate-300 underline-offset-4 transition hover:text-slate-900 cursor-pointer"
                        >
                            {move || if show_recovery.get() {
                                if totp_enabled() { "Use authenticator app" } else { "Use security key" }
                            } else {
                                "Use a recovery code"
                            }}
                        </button>
                    </div>

                    {move || {
                        verify_action.pending().get().then_some(view! { <Spinner /> })
                    }}
                    {move || {
                        error.get().map(|err| view! { <Alert kind=AlertKind::Error message=err.to_string() /> })
                    }}
                </div>
            </div>
        </div>
    }
}
