//! Versioned topology input, validated before starting any infrastructure.
//!
//! Flow Overview: decode a bounded JSON document, reject unsupported fields and
//! ambiguous topology, then provision named resources through real APIs. Manifests
//! cannot supply infrastructure addresses, callbacks, roles or credentials.

use crate::error::{Failure, Result, Safe, check};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io::Read as _, path::Path};

/// Version-one fixture topology; actors, clients and callback addresses are runner-owned.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub organization: String,
    pub project: String,
    pub environments: Vec<Environment>,
}

/// An explicit sibling environment with classification independent of its name.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub name: String,
    pub slug: String,
    pub tier: Tier,
    pub applications: Vec<Application>,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Production,
    NonProduction,
}

/// Application-owned delegated scopes, separate from immutable OIDC and internal permissions.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    pub scopes: Vec<Scope>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub name: String,
    pub description: String,
}

impl Manifest {
    /// Reads a bounded fixture file or the embedded default; decoding never starts services.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let bytes = if let Some(path) = path {
            let file = std::fs::File::open(path).safe("Cannot open fixture JSON.")?;
            let metadata = file.metadata().safe("Cannot read fixture metadata.")?;
            check(
                metadata.is_file() && metadata.len() <= 64 * 1024,
                "Fixture must be a regular JSON file of at most 64 KiB.",
            )?;
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .safe("Cannot read fixture JSON.")?;
            check(
                bytes.len() <= 64 * 1024,
                "Fixture JSON exceeds byte bounds.",
            )?;
            bytes
        } else {
            include_bytes!("../scenarios/default.json").to_vec()
        };
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|_| Failure::harness("Invalid or unsupported fixture JSON."))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Rejects ambiguous fixture inputs independently; negative API cases bypass this input layer.
    pub fn validate(&self) -> Result<()> {
        check(
            self.schema_version == 1,
            "Unsupported fixture schema version.",
        )?;
        check(
            valid_name(&self.organization) && valid_name(&self.project),
            "Invalid fixture resource name.",
        )?;
        check(
            (1..=8).contains(&self.environments.len()),
            "Fixtures require one to eight environments.",
        )?;
        check(
            self.environments
                .iter()
                .filter(|e| e.tier == Tier::Production)
                .count()
                <= 1,
            "Only one production environment is permitted.",
        )?;
        let mut names = HashSet::new();
        let mut slugs = HashSet::new();
        for environment in &self.environments {
            check(
                valid_name(&environment.name) && valid_slug(&environment.slug),
                "Invalid environment name or slug.",
            )?;
            check(
                names.insert(&environment.name) && slugs.insert(&environment.slug),
                "Duplicate environment name or slug.",
            )?;
            check(
                (1..=4).contains(&environment.applications.len()),
                "Environments require one to four applications.",
            )?;
            let mut applications = HashSet::new();
            for application in &environment.applications {
                check(
                    valid_name(&application.name) && applications.insert(&application.name),
                    "Invalid or duplicate application name.",
                )?;
                check(
                    (2..=16).contains(&application.scopes.len()),
                    "Applications require two to sixteen delegated scopes.",
                )?;
                let mut scopes = HashSet::new();
                for scope in &application.scopes {
                    check(
                        valid_scope(&scope.name) && scopes.insert(&scope.name),
                        "Invalid, reserved or duplicate delegated scope.",
                    )?;
                    check(
                        !scope.description.trim().is_empty()
                            && scope.description.len() <= 256
                            && !scope.description.chars().any(char::is_control),
                        "Invalid scope description.",
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Keeps fixture display names printable and within management API limits.
fn valid_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= 64
        && !value.chars().any(char::is_control)
}

/// Requires already canonical slugs so fixture paths need no normalization.
fn valid_slug(value: &str) -> bool {
    (2..=32).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !value.contains("--")
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// Validates only positive fixture scopes; independent protocol cases test server rejection.
fn valid_scope(value: &str) -> bool {
    let Some((resource, action)) = value.split_once(':') else {
        return false;
    };
    let part = |v: &str| {
        !v.is_empty()
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    };
    value.len() <= 64
        && part(resource)
        && part(action)
        && ![
            "platform",
            "users",
            "orgs",
            "projects",
            "environments",
            "applications",
            "oauth",
        ]
        .contains(&resource.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_slug_matches_api_bounds() {
        assert!(!valid_slug("a"));
        assert!(valid_slug("ab"));
        assert!(valid_slug(&"a".repeat(32)));
        assert!(!valid_slug(&"a".repeat(33)));
        assert!(!valid_slug("-ab"));
        assert!(!valid_slug("ab-"));
        assert!(!valid_slug("Ab"));
        assert!(!valid_slug("dev--env"));
    }

    #[test]
    fn manifest_rejects_unknown_fields_versions_and_unsafe_topology() -> Result<()> {
        let manifest = Manifest::load(None)?;
        let mut json = serde_json::to_value(&manifest).safe("Serialize fixture.")?;
        json.as_object_mut()
            .ok_or_else(|| Failure::harness("Fixture object."))?
            .insert("endpoint".into(), "https://foreign.test".into());
        assert!(serde_json::from_value::<Manifest>(json).is_err());
        let mut bad = manifest.clone();
        bad.schema_version = 2;
        assert!(bad.validate().is_err());
        bad = manifest.clone();
        bad.environments.push(
            bad.environments
                .first()
                .ok_or_else(|| Failure::harness("Fixture environment."))?
                .clone(),
        );
        assert!(bad.validate().is_err());
        bad = manifest;
        for e in &mut bad.environments {
            e.tier = Tier::Production;
        }
        assert!(bad.validate().is_err());
        for scope in [
            "openid",
            "platform:admin",
            "Users:write",
            "jobs:read write",
            "jobs::read",
        ] {
            assert!(!valid_scope(scope));
        }
        Ok(())
    }
}
