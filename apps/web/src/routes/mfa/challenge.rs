//! MFA Challenge route.
//!
//! Handles TOTP and recovery code verification during login:
//! 1. Ask for TOTP code.
//! 2. Option to use recovery code.
//! 3. Verify and resume pending OAuth authorization or navigate to the dashboard.
//!
//! Recovery requires re-enrollment; its session update preserves the setup screen and
//! one-time recovery-code acknowledgement before the pending OAuth flow can resume.

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
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

/// Completes the existing server-verified MFA flow before resuming OAuth or the console.
/// Recovery preserves re-enrollment and recovery-code acknowledgement before navigation.
#[component]
pub fn MfaChallengePage() -> impl IntoView {
    let auth = use_auth();
    let (code, set_code) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let (challenge_exhausted, set_challenge_exhausted) = signal(false);
    let (show_recovery, set_show_recovery) = signal(false);

    let totp_enabled = move || auth.session.get().is_none_or(|s| s.totp_enabled);
    let webauthn_enabled = move || auth.session.get().is_some_and(|s| s.webauthn_enabled);

    let authenticate_key_action =
        Action::new_local(move |(): &()| async move { authenticate_security_key().await });

    auto_start_key_if_only_factor(auth, show_recovery, authenticate_key_action);

    let verify_action = Action::new_local(move |code: &String| {
        let code = code.clone();
        let is_recovery = show_recovery.get_untracked();
        async move { verify_factor(code, is_recovery).await }
    });

    watch_challenge_results(
        auth,
        show_recovery,
        authenticate_key_action,
        verify_action,
        set_error,
        set_challenge_exhausted,
    );
    view! {
        <div class="min-h-[70vh] flex items-center justify-center px-6 py-10">
            <div class="w-full max-w-md rounded-2xl border border-slate-200 bg-white/90 p-6 shadow-[0_20px_60px_-40px_rgba(15,23,42,0.35)] backdrop-blur sm:p-8">
                <ChallengeHeader show_recovery=show_recovery />

                <div class="mt-6 space-y-6">
                    <Show when=move || !challenge_exhausted.get() && (totp_enabled() || show_recovery.get())>
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

                    <Show when=move || !challenge_exhausted.get() && !show_recovery.get() && webauthn_enabled()>
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

                        <SecurityKeyButton action=authenticate_key_action />
                    </Show>

                    <Show when=move || !challenge_exhausted.get()>
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
                    </Show>

                    <Show when=move || challenge_exhausted.get()>
                        <ChallengeRestart />
                    </Show>

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

/// Clears the exhausted browser session and starts a fresh server-side login challenge.
#[component]
fn ChallengeRestart() -> impl IntoView {
    let auth = use_auth();
    let navigation = StoredValue::new(use_navigate());
    let (pending, set_pending) = signal(false);
    let (error, set_error) = signal::<Option<AppError>>(None);
    view! {
        <div role="alert" class="space-y-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-100">
            <p>"This MFA challenge has reached its attempt limit. Sign in again to start a new challenge."</p>
            <button type="button" disabled=pending class="cursor-pointer rounded-lg border border-amber-700 px-3 py-2 font-medium transition hover:bg-amber-100 focus:outline-none focus:ring-2 focus:ring-amber-500 disabled:cursor-not-allowed dark:border-amber-300 dark:hover:bg-amber-900" on:click=move |_| {
                set_pending.set(true);
                set_error.set(None);
                let navigate = navigation.get_value();
                spawn_local(async move {
                    match client::logout().await {
                        Ok(()) => {
                            auth.clear_session();
                            navigate(paths::LOGIN, leptos_router::NavigateOptions::default());
                        }
                        Err(err) => set_error.set(Some(err)),
                    }
                    set_pending.set(false);
                });
            }>
                "Sign in again"
            </button>
            {move || error.get().map(|err| view! { <Alert kind=AlertKind::Error message=err.to_string() /> })}
        </div>
    }
}

/// Completes the browser security-key ceremony and reloads the verified session.
async fn authenticate_security_key() -> Result<crate::features::auth::types::UserSession, AppError>
{
    let start = client::mfa_webauthn_authenticate_start().await?;
    let response = crate::features::auth::webauthn::authenticate_key(&start.challenge).await?;
    client::mfa_webauthn_authenticate_finish(
        &crate::features::auth::types::WebauthnAuthenticateFinishRequest {
            auth_id: start.auth_id,
            response,
        },
    )
    .await?;
    client::fetch_session().await?.ok_or_else(|| {
        AppError::Config("Authentication succeeded but session not found.".to_string())
    })
}

/// Verifies the selected factor and reloads the server-issued session before navigation.
async fn verify_factor(
    code: String,
    is_recovery: bool,
) -> Result<crate::features::auth::types::UserSession, AppError> {
    if is_recovery {
        client::mfa_recovery(&MfaRecoveryRequest { code }).await?;
    } else {
        client::mfa_totp_verify(&MfaTotpVerifyRequest { code }).await?;
    }
    client::fetch_session().await?.ok_or_else(|| {
        AppError::Config("Verification succeeded but session not found.".to_string())
    })
}

/// Starts the key prompt automatically only when no TOTP factor can be used.
fn auto_start_key_if_only_factor(
    auth: crate::features::auth::state::AuthContext,
    show_recovery: ReadSignal<bool>,
    action: Action<(), Result<crate::features::auth::types::UserSession, AppError>>,
) {
    Effect::new(move |_| {
        let session = auth.session.get();
        if !show_recovery.get()
            && session
                .as_ref()
                .is_some_and(|value| !value.totp_enabled && value.webauthn_enabled)
            && action.value().get().is_none()
            && !action.pending().get()
        {
            action.dispatch(());
        }
    });
}

/// Applies server-verified MFA outcomes before switching routes or resuming OAuth.
fn watch_challenge_results(
    auth: crate::features::auth::state::AuthContext,
    show_recovery: ReadSignal<bool>,
    authenticate_key_action: Action<
        (),
        Result<crate::features::auth::types::UserSession, AppError>,
    >,
    verify_action: Action<String, Result<crate::features::auth::types::UserSession, AppError>>,
    set_error: WriteSignal<Option<AppError>>,
    set_challenge_exhausted: WriteSignal<bool>,
) {
    let navigate = use_navigate();
    let navigate_for_auth = navigate.clone();
    Effect::new(move |_| {
        if let Some(result) = authenticate_key_action.value().get() {
            match result {
                Ok(session) => {
                    auth.set_session(session);
                    if let Some(storage) = web_sys::window()
                        .and_then(|w| w.local_storage().ok())
                        .flatten()
                    {
                        let _ = storage.set_item("permesi_logged_in", "true");
                    }
                    navigate_for_auth(paths::DASHBOARD, leptos_router::NavigateOptions::default());
                }
                Err(err) if is_challenge_exhausted(&err) => {
                    set_challenge_exhausted.set(true);
                    set_error.set(None);
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let navigate_for_verify = navigate.clone();
    Effect::new(move |_| {
        if let Some(result) = verify_action.value().get() {
            match result {
                Ok(session) => {
                    if show_recovery.get() {
                        // Recovery requires re-enrollment before resuming the OAuth presentation flow.
                        auth.set_session_preserving_mfa(session);
                        navigate_for_verify(
                            paths::MFA_SETUP,
                            leptos_router::NavigateOptions::default(),
                        );
                    } else {
                        auth.set_session(session);
                        // Success: The server issued a full session cookie.
                        if let Some(storage) = web_sys::window()
                            .and_then(|w| w.local_storage().ok())
                            .flatten()
                        {
                            let _ = storage.set_item("permesi_logged_in", "true");
                        }
                        navigate_for_verify(
                            paths::DASHBOARD,
                            leptos_router::NavigateOptions::default(),
                        );
                    }
                }
                Err(err) if is_challenge_exhausted(&err) => {
                    set_challenge_exhausted.set(true);
                    set_error.set(None);
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });
}

/// Only the server's explicit terminal challenge code disables local verification controls.
fn is_challenge_exhausted(error: &AppError) -> bool {
    matches!(error, AppError::Http { code: Some(code), .. } if code == "mfa_challenge_exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_lockout_requires_server_error_code() {
        assert!(is_challenge_exhausted(&AppError::Http {
            status: 429,
            code: Some("mfa_challenge_exhausted".to_string()),
            message: String::new(),
        }));
        assert!(!is_challenge_exhausted(&AppError::Http {
            status: 429,
            code: Some("rate_limited".to_string()),
            message: String::new(),
        }));
    }
}

/// Explains the currently selected MFA factor without implying client-side authority.
#[component]
fn ChallengeHeader(show_recovery: ReadSignal<bool>) -> impl IntoView {
    let auth = use_auth();
    let totp_enabled = move || {
        auth.session
            .get()
            .is_none_or(|session| session.totp_enabled)
    };
    view! {
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
    }
}

/// Keeps the key prompt action and its error presentation together.
#[component]
fn SecurityKeyButton(
    action: Action<(), Result<crate::features::auth::types::UserSession, AppError>>,
) -> impl IntoView {
    view! {
                        <button
                            type="button"
                            disabled=action.pending()
                            on:click=move |_| { action.dispatch(()); }
                            class="w-full inline-flex justify-center items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-slate-200 cursor-pointer"
                        >
                            <span class="material-symbols-outlined text-base">"key"</span>
                            {move || if action.pending().get() {
                                "Waiting for key..."
                            } else {
                                "Use security key"
                            }}
                        </button>

                        {move || {
                            action
                                .value()
                                .get()
                                .and_then(std::result::Result::err)
                                .map(|err| {
                                    view! { <div class="mt-2"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                })
                        }}
    }
}
