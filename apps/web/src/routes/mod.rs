//! Frontend route definitions wired into the root `App` component. Routing is
//! client-side only, so backend endpoints must enforce access control.

mod admin;
mod admin_claim;
mod dashboard;
mod health;
mod login;
mod me;
mod mfa;
mod not_found;
mod orgs;
mod signup;
mod users;
mod verify_email;

pub(crate) use admin::AdminPage;
pub(crate) use admin_claim::AdminClaimPage;
pub(crate) use dashboard::DashboardPage;
pub(crate) use health::HealthPage;
pub(crate) use login::LoginPage;
pub(crate) use me::{MePage, MeSecurityPage};
pub(crate) use mfa::{MfaChallengePage, MfaSetupPage};
pub(crate) use not_found::{NotFoundContent, NotFoundPage};
pub(crate) use orgs::{OrgDetailPage, OrgsListPage, ProjectDetailPage};
pub(crate) use signup::SignUpPage;
pub(crate) use users::{UserDetailPage, UsersListPage};
pub(crate) use verify_email::VerifyEmailPage;

use crate::components::layout::{AdminLayout, AuthLayout, PublicLayout};
use leptos::prelude::*;
use leptos_router::{
    components::{ParentRoute, Route, Routes},
    path,
};

/// Type-safe route definitions and helpers.
#[allow(dead_code)]
pub mod paths {
    pub const LANDING: &str = "/";
    pub const LOGIN: &str = "/login";
    pub const SIGNUP: &str = "/signup";
    pub const VERIFY_EMAIL: &str = "/verify-email";
    pub const HEALTH: &str = "/health";

    // Protected routes under /console prefix
    pub const DASHBOARD: &str = "/console/dashboard";
    pub const ME: &str = "/console/me";
    pub const ME_SECURITY: &str = "/console/me/security";
    pub const MFA_SETUP: &str = "/console/mfa/setup";
    pub const MFA_CHALLENGE: &str = "/console/mfa/challenge";
    pub const ADMIN: &str = "/console/admin";
    pub const ADMIN_CLAIM: &str = "/console/admin/claim";
    pub const ORGS: &str = "/console/orgs";
    pub const USERS: &str = "/console/users";

    pub fn org_detail(slug: &str) -> String {
        format!("/console/orgs/{}", slug)
    }

    pub fn project_detail(org_slug: &str, project_slug: &str) -> String {
        format!("/console/orgs/{}/projects/{}", org_slug, project_slug)
    }

    pub fn user_detail(id: &str) -> String {
        format!("/console/users/{}", id)
    }
}

/// Declares the application route tree.
#[component]
pub fn AppRoutes() -> impl IntoView {
    view! {
        <Routes fallback=|| view! { <NotFoundPage /> }>
            // Public routes
            <ParentRoute path=path!("") view=|| view! { <PublicLayout/> }>
                <Route path=path!("") view=LandingPage />
                <Route path=path!("health") view=HealthPage />
                <Route path=path!("login") view=LoginPage />
                <Route path=path!("signup") view=SignUpPage />
                <Route path=path!("verify-email") view=VerifyEmailPage />
            </ParentRoute>

            // Protected routes (gated by AuthLayout)
            // All protected routes live under /console to avoid ambiguous matching
            <ParentRoute path=path!("console") view=|| view! { <AuthLayout/> }>
                <Route path=path!("dashboard") view=DashboardPage />
                <Route path=path!("me") view=MePage />
                <Route path=path!("me/security") view=MeSecurityPage />
                <Route path=path!("mfa/setup") view=MfaSetupPage />
                <Route path=path!("mfa/challenge") view=MfaChallengePage />

                // Admin subtree (nested)
                <ParentRoute path=path!("admin") view=|| view! { <AdminLayout/> }>
                    <Route path=path!("") view=AdminPage />
                    <Route path=path!("claim") view=AdminClaimPage />
                </ParentRoute>

                <Route path=path!("orgs") view=OrgsListPage />
                <Route path=path!("orgs/:slug") view=OrgDetailPage />
                <Route path=path!("orgs/:slug/projects/:project_slug") view=ProjectDetailPage />
                <Route path=path!("users") view=UsersListPage />
                <Route path=path!("users/:id") view=UserDetailPage />
            </ParentRoute>

            <Route path=path!("/*any") view=NotFoundPage />
        </Routes>
    }
}

/// Landing page - shows dashboard for authenticated users, welcome for guests.
#[component]
fn LandingPage() -> impl IntoView {
    use crate::components::ui::Spinner;
    use crate::features::auth::state::use_auth;
    use leptos_router::hooks::use_navigate;

    let auth = use_auth();
    let navigate = use_navigate();

    view! {
        {move || {
            if auth.is_loading.get() {
                view! {
                    <div class="flex justify-center items-center min-h-screen">
                        <Spinner />
                    </div>
                }.into_any()
            } else if auth.is_authenticated.get() {
                // Redirect to dashboard if authenticated
                navigate(paths::DASHBOARD, Default::default());
                view! {}.into_any()
            } else {
                view! { <WelcomePage /> }.into_any()
            }
        }}
    }
}

/// Public welcome page for unauthenticated visitors.
#[component]
fn WelcomePage() -> impl IntoView {
    // AppShell is now provided by PublicLayout, so we just render content.
    use leptos_router::components::A;

    view! {
        <div class="flex flex-col items-center justify-center py-20 text-center">
            <h1 class="text-4xl font-bold text-gray-900 dark:text-white mb-4">
                "Welcome to Permesi"
            </h1>
            <p class="text-lg text-gray-600 dark:text-gray-400 mb-8 max-w-md">
                "Identity and Access Management"
            </p>
            <div class="flex gap-4">
                <A
                    href={paths::LOGIN}
                    {..}
                    class="px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
                >
                    "Sign In"
                </A>
                <A
                    href={paths::SIGNUP}
                    {..}
                    class="px-6 py-3 bg-gray-200 text-gray-900 font-medium rounded-lg hover:bg-gray-300 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600 transition-colors"
                >
                    "Sign Up"
                </A>
            </div>
        </div>
    }
}
