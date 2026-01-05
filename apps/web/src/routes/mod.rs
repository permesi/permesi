//! Frontend route definitions wired into the root `App` component. Routing is
//! client-side only, so backend endpoints must enforce access control.

mod admin;
mod admin_claim;
mod dashboard;
mod health;
mod login;
mod me;
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
pub(crate) use me::MePage;
pub(crate) use not_found::{NotFoundContent, NotFoundPage};
pub(crate) use orgs::{OrgDetailPage, OrgsListPage, ProjectDetailPage};
pub(crate) use signup::SignUpPage;
pub(crate) use users::{UserDetailPage, UsersListPage};
pub(crate) use verify_email::VerifyEmailPage;

use leptos::prelude::*;
use leptos_router::{
    components::{Route, Routes},
    path,
};

/// Declares the application route tree.
#[component]
pub fn AppRoutes() -> impl IntoView {
    view! {
        <Routes fallback=|| view! { <NotFoundPage /> }>
            // Public routes
            <Route path=path!("/") view=LandingPage />
            <Route path=path!("/health") view=HealthPage />
            <Route path=path!("/login") view=LoginPage />
            <Route path=path!("/signup") view=SignUpPage />
            <Route path=path!("/verify-email") view=VerifyEmailPage />

            // Protected routes (guards applied inside each page component)
            <Route path=path!("/dashboard") view=DashboardPage />
            <Route path=path!("/me") view=MePage />
            <Route path=path!("/admin") view=AdminPage />
            <Route path=path!("/admin/claim") view=AdminClaimPage />
            <Route path=path!("/orgs") view=OrgsListPage />
            <Route path=path!("/orgs/:slug") view=OrgDetailPage />
            <Route path=path!("/orgs/:slug/projects/:project_slug") view=ProjectDetailPage />
            <Route path=path!("/users") view=UsersListPage />
            <Route path=path!("/users/:id") view=UserDetailPage />

            <Route path=path!("/*any") view=NotFoundPage />
        </Routes>
    }
}

/// Landing page - shows dashboard for authenticated users, welcome for guests.
#[component]
fn LandingPage() -> impl IntoView {
    use crate::components::ui::Spinner;
    use crate::features::auth::state::use_auth;

    let auth = use_auth();

    view! {
        {move || {
            if auth.is_loading.get() {
                view! {
                    <div class="flex justify-center items-center min-h-screen">
                        <Spinner />
                    </div>
                }.into_any()
            } else if auth.is_authenticated.get() {
                view! { <DashboardPage /> }.into_any()
            } else {
                view! { <WelcomePage /> }.into_any()
            }
        }}
    }
}

/// Public welcome page for unauthenticated visitors.
#[component]
fn WelcomePage() -> impl IntoView {
    use crate::components::layout::AppShell;
    use leptos_router::components::A;

    view! {
        <AppShell>
            <div class="flex flex-col items-center justify-center py-20 text-center">
                <h1 class="text-4xl font-bold text-gray-900 dark:text-white mb-4">
                    "Welcome to Permesi"
                </h1>
                <p class="text-lg text-gray-600 dark:text-gray-400 mb-8 max-w-md">
                    "Identity and Access Management"
                </p>
                <div class="flex gap-4">
                    <A
                        href="/login"
                        {..}
                        class="px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
                    >
                        "Sign In"
                    </A>
                    <A
                        href="/signup"
                        {..}
                        class="px-6 py-3 bg-gray-200 text-gray-900 font-medium rounded-lg hover:bg-gray-300 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600 transition-colors"
                    >
                        "Sign Up"
                    </A>
                </div>
            </div>
        </AppShell>
    }
}
