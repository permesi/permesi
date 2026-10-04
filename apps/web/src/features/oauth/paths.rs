//! Centralized application ancestry paths for navigation and management requests.
//!
//! Every dynamic value is encoded as one path segment. Public client identifiers
//! are passed explicitly; internal client row IDs are never used by this helper.

use std::fmt::Write;

/// Selected organization/project/environment ancestry; no client-supplied policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentPaths {
    pub org: String,
    pub project: String,
    pub environment: String,
}

impl EnvironmentPaths {
    /// Returns the environment console page within its full tenant ancestry.
    #[must_use]
    pub fn console(&self) -> String {
        format!(
            "{}/envs/{}",
            self.project_console(),
            segment(&self.environment)
        )
    }

    /// Returns the existing parent project route for breadcrumbs.
    #[must_use]
    pub fn project_console(&self) -> String {
        format!(
            "/console/orgs/{}/projects/{}",
            segment(&self.org),
            segment(&self.project)
        )
    }

    /// Returns the application's collection API; detail GET does not exist.
    #[must_use]
    pub fn applications_api(&self) -> String {
        format!(
            "/v1/orgs/{}/projects/{}/envs/{}/apps",
            segment(&self.org),
            segment(&self.project),
            segment(&self.environment)
        )
    }

    /// Selects an application without modifying or shortening its ancestry.
    #[must_use]
    pub fn application(&self, id: &str) -> ApplicationPaths {
        ApplicationPaths {
            environment: self.clone(),
            application: id.to_owned(),
        }
    }
}

/// Full application context for both console routes and OAuth APIs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationPaths {
    pub environment: EnvironmentPaths,
    pub application: String,
}

impl ApplicationPaths {
    /// Returns the application overview route.
    #[must_use]
    pub fn console(&self) -> String {
        format!(
            "{}/apps/{}",
            self.environment.console(),
            segment(&self.application)
        )
    }

    /// Returns the OAuth configuration landing route.
    #[must_use]
    pub fn oauth(&self) -> String {
        format!("{}/oauth", self.console())
    }

    /// Returns the client collection console route.
    #[must_use]
    pub fn clients(&self) -> String {
        format!("{}/clients", self.oauth())
    }

    /// Returns a client detail route using its public OAuth identifier.
    #[must_use]
    pub fn client(&self, client_id: &str) -> String {
        format!("{}/{}", self.clients(), segment(client_id))
    }

    /// Returns the delegated scope registry console route.
    #[must_use]
    pub fn scopes(&self) -> String {
        format!("{}/scopes", self.oauth())
    }

    /// Returns the client collection management endpoint.
    #[must_use]
    pub fn clients_api(&self) -> String {
        format!("{}/oauth/clients", self.api())
    }

    /// Returns a client management endpoint using its public identifier.
    #[must_use]
    pub fn client_api(&self, client_id: &str) -> String {
        format!("{}/{}", self.clients_api(), segment(client_id))
    }

    /// Returns the redirect replacement/inspection endpoint.
    #[must_use]
    pub fn redirects_api(&self, client_id: &str) -> String {
        format!("{}/redirect-uris", self.client_api(client_id))
    }

    /// Returns the client delegated scope replacement/inspection endpoint.
    #[must_use]
    pub fn client_scopes_api(&self, client_id: &str) -> String {
        format!("{}/scopes", self.client_api(client_id))
    }

    /// Returns the application scope registry endpoint.
    #[must_use]
    pub fn scopes_api(&self) -> String {
        format!("{}/oauth/scopes", self.api())
    }

    /// Returns an application scope metadata endpoint, keyed by scope row ID.
    #[must_use]
    pub fn scope_api(&self, scope_id: &str) -> String {
        format!("{}/{}", self.scopes_api(), segment(scope_id))
    }

    /// Builds an API path independently of console routing.
    fn api(&self) -> String {
        format!(
            "{}/{}",
            self.environment.applications_api(),
            segment(&self.application)
        )
    }
}

/// Encodes separators and non-ASCII bytes so input cannot escape a single segment.
fn segment(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(char::from(byte));
        } else {
            // Writing to a String is infallible.
            let _ = write!(result, "%{byte:02X}");
        }
    }
    result
}
