//! Client and typed paths for read-only platform inspection, separate from tenant management.
//!
//! Flow Overview: the existing admin UI gate mounts a path-bound view; cookie-based
//! reads fetch basic metadata and bounded children. Every request is independently
//! authorized by the server. These paths never grant tenant membership or write access.

use crate::app_lib::{AppError, get_json_with_credentials};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InspectionPath {
    Organizations,
    Organization(String),
    Project(String, String),
    Environment(String, String, String),
    Application(String, String, String, String),
}

impl InspectionPath {
    /// Encodes individual untrusted path segments; hierarchy separators are server-defined.
    fn suffix(&self) -> String {
        let segments = match self {
            Self::Organizations => vec!["orgs"],
            Self::Organization(org) => vec!["orgs", org],
            Self::Project(org, project) => vec!["orgs", org, "projects", project],
            Self::Environment(org, project, env) => {
                vec!["orgs", org, "projects", project, "envs", env]
            }
            Self::Application(org, project, env, app) => {
                vec!["orgs", org, "projects", project, "envs", env, "apps", app]
            }
        };
        segments
            .into_iter()
            .map(crate::features::oauth::paths::segment)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Builds only administrator console links, never tenant-management links.
    pub fn console(&self) -> String {
        format!("/console/admin/{}", self.suffix())
    }

    /// Selects a read-only metadata endpoint with complete ancestry.
    pub fn api(&self) -> String {
        format!("/v1/admin/{}", self.suffix())
    }

    /// Returns the immediate ancestor for read-only breadcrumbs.
    pub fn parent(&self) -> Option<Self> {
        match self {
            Self::Organizations => None,
            Self::Organization(_) => Some(Self::Organizations),
            Self::Project(org, _) => Some(Self::Organization(org.clone())),
            Self::Environment(org, project, _) => Some(Self::Project(org.clone(), project.clone())),
            Self::Application(org, project, env, _) => {
                Some(Self::Environment(org.clone(), project.clone(), env.clone()))
            }
        }
    }

    /// Labels hierarchy navigation without inferring tenant privileges from the route.
    pub fn label(&self) -> String {
        match self {
            Self::Organizations => "Global Organizations".to_owned(),
            Self::Organization(org) => org.clone(),
            Self::Project(_, project) => project.clone(),
            Self::Environment(_, _, env) => env.clone(),
            Self::Application(_, _, _, app) => app.clone(),
        }
    }

    /// Identifies the next collection; applications expose metadata only.
    pub fn children(&self) -> Option<&'static str> {
        match self {
            Self::Organizations => Some("Organizations"),
            Self::Organization(_) => Some("Projects"),
            Self::Project(_, _) => Some("Environments"),
            Self::Environment(_, _, _) => Some("Applications"),
            Self::Application(..) => None,
        }
    }

    /// Builds a child's read-only path only from the expected public identifier.
    pub fn child(&self, row: &Metadata) -> Option<Self> {
        match self {
            Self::Organizations => Some(Self::Organization(row.slug.clone()?)),
            Self::Organization(org) => Some(Self::Project(org.clone(), row.slug.clone()?)),
            Self::Project(org, project) => Some(Self::Environment(
                org.clone(),
                project.clone(),
                row.slug.clone()?,
            )),
            Self::Environment(org, project, env) => Some(Self::Application(
                org.clone(),
                project.clone(),
                env.clone(),
                row.id.clone(),
            )),
            Self::Application(..) => None,
        }
    }

    /// Returns a collection endpoint without introducing a mutating API operation.
    fn collection_api(&self) -> Option<String> {
        let suffix = match self {
            Self::Organizations => return Some(self.api()),
            Self::Organization(_) => "projects",
            Self::Project(..) => "envs",
            Self::Environment(..) => "apps",
            Self::Application(..) => return None,
        };
        Some(format!("{}/{suffix}", self.api()))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Metadata {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub slug: Option<String>,
    pub tier: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Page {
    pub items: Vec<Metadata>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Inspection {
    pub metadata: Option<Metadata>,
    pub page: Option<Page>,
}

/// Fetches metadata before children so unavailable ancestry cannot render a usable subtree.
pub async fn load(path: &InspectionPath, after: Option<&str>) -> Result<Inspection, AppError> {
    let metadata = if matches!(path, InspectionPath::Organizations) {
        None
    } else {
        Some(get_json_with_credentials(&path.api()).await?)
    };
    let page = match path.collection_api() {
        Some(mut endpoint) => {
            if let Some(cursor) = after {
                endpoint.push_str("?after=");
                endpoint.push_str(&crate::features::oauth::paths::segment(cursor));
            }
            Some(get_json_with_credentials(&endpoint).await?)
        }
        None => None,
    };
    Ok(Inspection { metadata, page })
}

#[cfg(test)]
mod tests {
    use super::InspectionPath;

    /// Admin navigation must never fall back to membership-scoped management URLs.
    #[test]
    fn inspection_paths_keep_admin_namespace_and_escape_each_segment() {
        let path = InspectionPath::Application(
            "org/foreign".to_owned(),
            "project?admin=true".to_owned(),
            "env#fragment".to_owned(),
            "app".to_owned(),
        );
        assert_eq!(
            path.api(),
            "/v1/admin/orgs/org%2Fforeign/projects/project%3Fadmin%3Dtrue/envs/env%23fragment/apps/app"
        );
        assert!(path.console().starts_with("/console/admin/orgs/"));
        assert!(path.collection_api().is_none());
        assert_eq!(
            InspectionPath::Organizations.console(),
            crate::routes::paths::ADMIN_ORGS
        );
    }
}
