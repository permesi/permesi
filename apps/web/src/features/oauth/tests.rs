//! Native regressions for real console contracts and configuration transitions.

use super::{
    model::{
        NO_APPLICATION_SCOPES, NO_CLIENTS, add_redirect, application_scopes_empty, http_message,
        redirect_selection_matches, scope_selection_matches, toggle_scope,
    },
    paths::EnvironmentPaths,
    types::{
        ClientResponse, ClientScopesRequest, ClientType, CreateClientRequest, CreateScopeRequest,
        PatchClientRequest, PatchScopeRequest, RedirectsRequest, ScopeKind, ScopeResponse,
    },
};
use serde_json::{Value, json};

#[test]
fn unavailable_scopes_require_explicit_removal_and_cannot_be_added_as_choices() {
    use super::scope::{scope_assignment_groups, unavailable_scopes};
    let registry = vec![
        scope("jobs:read", ScopeKind::Application),
        scope("old.opaque", ScopeKind::Application),
        scope("future:scope", ScopeKind::Unknown),
        scope("openid", ScopeKind::Protocol),
    ];
    let mut selected = vec![
        "jobs:read".to_owned(),
        "old.opaque".to_owned(),
        "future:scope".to_owned(),
        "missing:scope".to_owned(),
        "openid".to_owned(),
    ];
    assert_eq!(
        unavailable_scopes(&selected, &registry),
        ["old.opaque", "future:scope", "missing:scope"]
    );
    assert_eq!(
        selected.len(),
        5,
        "Inspection must preserve saved authority"
    );
    assert!(
        !scope_assignment_groups(registry.clone())
            .iter()
            .flat_map(|group| &group.scopes)
            .any(|scope| scope.name == "old.opaque")
    );
    selected
        .retain(|name| !unavailable_scopes(std::slice::from_ref(name), &registry).contains(name));
    assert_eq!(selected, ["jobs:read", "openid"]);
    assert_eq!(
        unavailable_scopes(&selected, &registry),
        Vec::<String>::new()
    );
}

#[test]
fn application_scope_form_composes_one_token_without_fixed_action_vocabulary()
-> Result<(), &'static str> {
    use super::scope::compose_application_scope;
    for name in [
        "jobs:read",
        "jobs:write",
        "runs:execute",
        "runs:cancel",
        "deployments:approve",
        "members:invite",
        "Jobs:Custom+Action",
    ] {
        let (resource, action) = name.split_once(':').ok_or("Missing parts")?;
        assert_eq!(compose_application_scope(resource, action)?, name);
    }
    for (resource, action) in [
        ("", "read"),
        ("jobs", ""),
        ("jobs:sub", "read"),
        ("jobs", "read:all"),
        ("jobs", " read"),
        ("users", "invite"),
        ("PLATFORM", "manage"),
        ("jobs", "quote\""),
        ("jobs", "back\\slash"),
        ("jobs", "é"),
    ] {
        assert!(compose_application_scope(resource, action).is_err());
    }
    assert!(compose_application_scope("x", &"a".repeat(126)).is_ok());
    assert!(compose_application_scope("x", &"a".repeat(127)).is_err());
    Ok(())
}

#[test]
fn application_scope_grouping_preserves_wire_names_and_system_boundaries()
-> Result<(), &'static str> {
    use super::scope::{
        ApplicationScopeParts, ScopeGroup, ScopeGroupKind, scope_assignment_groups,
    };
    let registry = vec![
        scope("jobs:read", ScopeKind::Application),
        scope("jobs:write", ScopeKind::Application),
        scope("runs:execute", ScopeKind::Application),
        scope("runs:cancel", ScopeKind::Application),
        scope("Jobs:Read", ScopeKind::Application),
        scope("custom.scope+value", ScopeKind::Application),
        scope("urn:example:scope", ScopeKind::Application),
        scope("openid", ScopeKind::Protocol),
        scope("profile", ScopeKind::Protocol),
        scope("unexpected:read", ScopeKind::Unknown),
    ];
    for row in &registry {
        if row.kind != ScopeKind::Application || row.name.matches(':').count() != 1 {
            assert!(ApplicationScopeParts::from_scope(row).is_none());
        }
    }
    let groups = scope_assignment_groups(registry.clone());
    assert_eq!(
        groups.iter().map(ScopeGroup::label).collect::<Vec<_>>(),
        ["Jobs", "jobs", "runs", "System OIDC scopes"]
    );
    let [_capitalized, jobs, runs, protocol] = groups.as_slice() else {
        return Err("Missing expected groups");
    };
    assert_eq!(jobs.kind, ScopeGroupKind::Resource("jobs".to_owned()));
    assert_eq!(
        jobs.scopes
            .iter()
            .map(|scope| scope.name.as_str())
            .collect::<Vec<_>>(),
        ["jobs:read", "jobs:write"]
    );
    assert_eq!(protocol.kind, ScopeGroupKind::Protocol);
    let mut selected = Vec::new();
    let cancel = runs
        .scopes
        .iter()
        .find(|scope| scope.name == "runs:cancel")
        .ok_or("Missing cancel scope")?;
    toggle_scope(&mut selected, &registry, &cancel.name, true);
    assert_eq!(selected, ["runs:cancel"]);
    assert!(
        !groups
            .iter()
            .flat_map(|group| &group.scopes)
            .any(|scope| scope.kind == ScopeKind::Unknown)
    );
    for name in [":read", "jobs:", "jobs::read"] {
        assert!(ApplicationScopeParts::from_scope(&scope(name, ScopeKind::Application)).is_none());
    }
    Ok(())
}

/// Builds server-shaped registry metadata for case-sensitive checkbox tests.
fn scope(name: &str, kind: ScopeKind) -> ScopeResponse {
    ScopeResponse {
        id: name.to_owned(),
        application_id: "app".to_owned(),
        name: name.to_owned(),
        description: String::new(),
        kind,
        created_at: String::new(),
        updated_at: String::new(),
    }
}

#[test]
fn oauth_paths_keep_full_ancestry_and_public_client_id() {
    let env = EnvironmentPaths {
        org: "crono".to_owned(),
        project: "jobs".to_owned(),
        environment: "production".to_owned(),
    };
    let app = env.application("app-uuid");
    let console = "/console/orgs/crono/projects/jobs/envs/production/apps/app-uuid";
    let api = "/v1/orgs/crono/projects/jobs/envs/production/apps/app-uuid/oauth";
    assert_eq!(app.console(), console);
    assert_eq!(app.oauth(), format!("{console}/oauth"));
    assert_eq!(app.clients(), format!("{console}/oauth/clients"));
    assert_eq!(app.scopes(), format!("{console}/oauth/scopes"));
    assert_eq!(
        app.client("public-id"),
        format!("{console}/oauth/clients/public-id")
    );
    assert_eq!(app.clients_api(), format!("{api}/clients"));
    assert_eq!(
        app.client_api("public-id"),
        format!("{api}/clients/public-id")
    );
    assert_eq!(
        app.redirects_api("public-id"),
        format!("{api}/clients/public-id/redirect-uris")
    );
    assert_eq!(
        app.client_scopes_api("public-id"),
        format!("{api}/clients/public-id/scopes")
    );
    assert_eq!(app.scope_api("scope-id"), format!("{api}/scopes/scope-id"));
}

#[test]
fn oauth_paths_encode_each_segment() {
    let env = EnvironmentPaths {
        org: "org/other".to_owned(),
        project: "x?admin=yes".to_owned(),
        environment: "prod#fragment".to_owned(),
    };
    let app = env.application("app");
    assert_eq!(
        app.client_api("client/../other"),
        "/v1/orgs/org%2Fother/projects/x%3Fadmin%3Dyes/envs/prod%23fragment/apps/app/oauth/clients/client%2F..%2Fother"
    );
}

/// Resource deletion must retain the entire ancestry, including collection-like slugs.
#[test]
fn tenant_resource_paths_preserve_apps_environment_slug_and_encode_segments() {
    let environment = EnvironmentPaths {
        org: "org/foreign".to_owned(),
        project: "jobs?admin=true".to_owned(),
        environment: "apps".to_owned(),
    };
    assert_eq!(
        environment.api(),
        "/v1/orgs/org%2Fforeign/projects/jobs%3Fadmin%3Dtrue/envs/apps"
    );
    assert_eq!(
        environment.applications_api(),
        format!("{}/apps", environment.api())
    );
    assert_eq!(
        environment.application("app/other").api(),
        format!("{}/app%2Fother", environment.applications_api())
    );
}

#[test]
fn oauth_creation_and_patch_match_openapi_fields() -> Result<(), Box<dyn std::error::Error>> {
    let create = serde_json::to_value(CreateClientRequest {
        name: "browser".to_owned(),
        client_type: ClientType::Public,
    })?;
    assert_eq!(create, json!({"name":"browser","client_type":"public"}));
    let patch = serde_json::to_value(PatchClientRequest {
        name: None,
        disabled: Some(true),
    })?;
    assert_eq!(patch, json!({"disabled":true}));
    let scopes = serde_json::to_value(ClientScopesRequest {
        scopes: vec!["jobs:read".to_owned()],
    })?;
    assert_eq!(scopes, json!({"scopes":["jobs:read"]}));
    let scope = serde_json::to_value(CreateScopeRequest {
        name: "Jobs:Read".to_owned(),
        description: "Read".to_owned(),
    })?;
    assert_eq!(scope, json!({"name":"Jobs:Read","description":"Read"}));
    let redirects = serde_json::to_value(RedirectsRequest {
        redirect_uris: vec!["https://EXAMPLE/cb?x=%2f".to_owned()],
    })?;
    assert_eq!(
        redirects,
        json!({"redirect_uris":["https://EXAMPLE/cb?x=%2f"]})
    );
    let scope_patch = serde_json::to_value(PatchScopeRequest {
        description: "Updated description".to_owned(),
    })?;
    assert_eq!(scope_patch, json!({"description":"Updated description"}));
    let openapi: Value =
        serde_json::from_str(include_str!("../../../../../docs/openapi/permesi.json"))?;
    for (schema, payload) in [
        ("CreateClientRequest", create),
        ("PatchClientRequest", patch),
        ("ClientScopesRequest", scopes),
        ("CreateScopeRequest", scope),
        ("RedirectsRequest", redirects),
        ("PatchScopeRequest", scope_patch),
    ] {
        let schema = openapi
            .get("components")
            .and_then(|value| value.get("schemas"))
            .and_then(|value| value.get(schema))
            .ok_or("Missing schema")?;
        let properties = schema.get("properties");
        for key in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            assert!(
                payload.get(key).is_some(),
                "Missing required request field: {key}"
            );
        }
        for key in payload
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
        {
            assert!(
                properties.and_then(|value| value.get(key)).is_some(),
                "Missing API field: {key}"
            );
        }
    }
    Ok(())
}

#[test]
fn oauth_client_type_presentation_does_not_promise_grant_flows() -> Result<(), serde_json::Error> {
    assert_eq!(
        serde_json::from_str::<ClientType>("\"public\"")?,
        ClientType::Public
    );
    assert_eq!(
        serde_json::to_string(&ClientType::Confidential)?,
        "\"confidential\""
    );
    assert_eq!(ClientType::Public.label(), "Public");
    assert_eq!(ClientType::Confidential.label(), "Confidential");
    assert!(
        ClientType::Public
            .description()
            .contains("cannot safely store")
    );
    assert!(
        !ClientType::Confidential
            .description()
            .contains("Client Credentials")
    );
    assert!(serde_json::from_str::<ClientType>("\"machine\"").is_err());
    Ok(())
}

#[test]
fn oauth_client_lifecycle_uses_disabled_metadata() -> Result<(), serde_json::Error> {
    let mut client: ClientResponse = serde_json::from_value(
        json!({"id":"internal", "client_id":"public", "application_id":"app", "name":"web", "client_type":"public", "created_at":"now", "updated_at":"now", "disabled_at":null}),
    )?;
    assert_eq!(client.client_id, "public");
    assert_eq!(client.status(), "Active");
    client.disabled_at = Some("later".to_owned());
    assert_eq!(client.status(), "Disabled");
    Ok(())
}

#[test]
fn oauth_redirect_drafts_preserve_exact_values_and_duplicates() -> Result<(), &'static str> {
    let existing = vec!["https://EXAMPLE:443/a/../callback?x=%2f".to_owned()];
    let added = add_redirect(&existing, " https://example/callback?x=%2F ")?;
    assert_eq!(
        added,
        vec![
            existing.first().ok_or("Missing fixture")?.clone(),
            "https://example/callback?x=%2F".to_owned()
        ]
    );
    assert_eq!(
        add_redirect(&existing, "https://EXAMPLE:443/a/../callback?x=%2f"),
        Err("Duplicate redirect URI.")
    );
    assert!(add_redirect(&existing, " ").is_err());
    assert_eq!(existing.len(), 1);
    Ok(())
}

#[test]
fn oauth_redirect_draft_accepts_raw_uri_and_preserves_validation_message()
-> Result<(), &'static str> {
    // Complex validation is left to the API; an invalid URI stays editable on error.
    let draft = add_redirect(&[], "https://example/callback#fragment")?;
    assert_eq!(
        http_message(
            400,
            "Redirect URI contains invalid characters or is too long."
        ),
        "Redirect URI contains invalid characters or is too long."
    );
    assert_eq!(draft, vec!["https://example/callback#fragment"]);
    assert!(!http_message(500, "SQL secret metadata").contains("SQL"));
    assert!(!http_message(400, "<html>proxy error details</html>").contains("<html>"));
    assert!(http_message(404, "Request failed.").contains("organization role"));
    Ok(())
}

#[test]
fn oauth_scope_assignment_is_registry_bound_and_case_sensitive() {
    let registry = vec![
        scope("jobs:read", ScopeKind::Application),
        scope("openid", ScopeKind::Protocol),
    ];
    let mut selected = Vec::new();
    toggle_scope(&mut selected, &registry, "Jobs:Read", true);
    toggle_scope(&mut selected, &registry, "users:write", true);
    assert_eq!(selected, Vec::<String>::new());
    toggle_scope(&mut selected, &registry, "jobs:read", true);
    toggle_scope(&mut selected, &registry, "jobs:read", true);
    toggle_scope(&mut selected, &registry, "openid", true);
    assert_eq!(selected, vec!["jobs:read", "openid"]);
    toggle_scope(&mut selected, &registry, "jobs:read", false);
    assert_eq!(selected, vec!["openid"]);
}

#[test]
fn oauth_protocol_and_unknown_scope_kinds_are_read_only() -> Result<(), serde_json::Error> {
    assert!(!scope("openid", ScopeKind::Protocol).editable());
    assert_eq!(
        scope("openid", ScopeKind::Protocol).kind_label(),
        "System · OIDC"
    );
    assert!(scope("jobs:read", ScopeKind::Application).editable());
    let unknown = serde_json::from_str::<ScopeKind>("\"future\"")?;
    assert!(!scope("future", unknown).editable());
    Ok(())
}

#[test]
fn oauth_empty_states_distinguish_seeded_protocol_scopes() {
    assert_eq!(NO_CLIENTS, "No OAuth clients");
    assert_eq!(NO_APPLICATION_SCOPES, "No application scopes");
    assert!(application_scopes_empty(&[]));
    assert!(application_scopes_empty(&[scope(
        "openid",
        ScopeKind::Protocol
    )]));
    assert!(!application_scopes_empty(&[
        scope("openid", ScopeKind::Protocol),
        scope("jobs:read", ScopeKind::Application)
    ]));
}

#[test]
fn oauth_scope_assignment_undo_does_not_revoke_saved_grants() {
    let registry = vec![
        scope("jobs:read", ScopeKind::Application),
        scope("openid", ScopeKind::Protocol),
        scope("future", ScopeKind::Unknown),
    ];
    let saved = vec!["jobs:read".to_owned(), "openid".to_owned()];
    let mut draft = saved.clone();
    toggle_scope(&mut draft, &registry, "jobs:read", false);
    assert!(!scope_selection_matches(&saved, &draft));
    toggle_scope(&mut draft, &registry, "jobs:read", true);
    assert!(scope_selection_matches(&saved, &draft));
    toggle_scope(&mut draft, &registry, "future", true);
    assert!(scope_selection_matches(&saved, &draft));
}

#[test]
fn oauth_redirect_remove_and_readd_does_not_revoke_saved_grants() -> Result<(), &'static str> {
    let saved = vec![
        "https://EXAMPLE:443/cb?x=%2f".to_owned(),
        "https://example/second".to_owned(),
    ];
    let remaining = vec!["https://example/second".to_owned()];
    let restored = add_redirect(&remaining, "https://EXAMPLE:443/cb?x=%2f")?;
    assert!(redirect_selection_matches(&saved, &restored));
    let normalized = vec![
        "https://example/cb?x=%2F".to_owned(),
        "https://example/second".to_owned(),
    ];
    assert!(!redirect_selection_matches(&saved, &normalized));
    Ok(())
}

#[test]
fn oauth_response_dtos_match_required_openapi_fields() -> Result<(), Box<dyn std::error::Error>> {
    let openapi: Value =
        serde_json::from_str(include_str!("../../../../../docs/openapi/permesi.json"))?;
    let client = json!({"id":"internal", "client_id":"public", "application_id":"app", "name":"web", "client_type":"confidential", "created_at":"now", "updated_at":"now", "disabled_at":null});
    let scope = json!({"id":"scope", "application_id":"app", "name":"openid", "description":"OIDC", "kind":"protocol", "created_at":"now", "updated_at":"now"});
    let application = json!({"id":"app", "name":"Crono", "created_at":"now"});
    let _: ClientResponse = serde_json::from_value(client.clone())?;
    let _: ScopeResponse = serde_json::from_value(scope.clone())?;
    let _: crate::orgs_types::ApplicationResponse = serde_json::from_value(application.clone())?;
    for (name, payload) in [
        ("ClientResponse", client),
        ("ScopeResponse", scope),
        ("ApplicationResponse", application),
    ] {
        let schema = openapi
            .get("components")
            .and_then(|value| value.get("schemas"))
            .and_then(|value| value.get(name))
            .ok_or("Missing response schema")?;
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .ok_or("Missing required response fields")?;
        for key in required.iter().filter_map(Value::as_str) {
            assert!(
                payload.get(key).is_some(),
                "Missing required response field: {name}.{key}"
            );
        }
        let mut minimal = payload
            .as_object()
            .ok_or("Invalid response fixture")?
            .clone();
        minimal.retain(|key, _| {
            required
                .iter()
                .any(|field| field.as_str() == Some(key.as_str()))
        });
        let minimal = Value::Object(minimal);
        match name {
            "ClientResponse" => {
                let value: ClientResponse = serde_json::from_value(minimal)?;
                assert!(value.disabled_at.is_none());
            }
            "ScopeResponse" => {
                let _: ScopeResponse = serde_json::from_value(minimal)?;
            }
            "ApplicationResponse" => {
                let _: crate::orgs_types::ApplicationResponse = serde_json::from_value(minimal)?;
            }
            _ => return Err("Unknown response fixture".into()),
        }
    }
    Ok(())
}
#[test]
fn navigation_active_preserves_application_and_subsection_hierarchy() {
    use super::model::navigation_active;
    let app = "/console/orgs/org/projects/project/envs/env/apps/app";
    let oauth = format!("{app}/oauth");
    let clients = format!("{oauth}/clients");
    let detail = format!("{clients}/public-client");
    assert!(navigation_active(app, app, false));
    assert!(!navigation_active(&detail, app, false));
    assert!(navigation_active(&detail, &oauth, true));
    assert!(navigation_active(&detail, &clients, true));
    assert!(!navigation_active(&detail, &oauth, false));
    assert!(!navigation_active(
        &format!("{clients}-other"),
        &clients,
        true
    ));
    assert!(!navigation_active(
        &format!("{oauth}/scopes"),
        &clients,
        true
    ));
    assert!(navigation_active(&format!("{oauth}/"), &oauth, false));
}

#[test]
fn confidential_credential_paths_encode_ids_and_rotation_binds_expected_current()
-> Result<(), serde_json::Error> {
    let paths = EnvironmentPaths {
        org: "org".into(),
        project: "project".into(),
        environment: "prod".into(),
    }
    .application("app");
    assert!(
        paths
            .secret_api("client", "../other")
            .ends_with("/clients/client/secrets/..%2Fother")
    );
    assert_eq!(
        serde_json::to_value(super::types::CreateSecretRequest {})?,
        json!({})
    );
    assert_eq!(
        serde_json::to_value(super::types::RotateSecretRequest {
            current_secret_id: "reviewed-id".into()
        })?,
        json!({"current_secret_id":"reviewed-id"})
    );
    let metadata: Vec<super::types::SecretMetadata> = serde_json::from_value(
        json!([{ "id":"credential", "created_at":"time", "expires_at":null }]),
    )?;
    assert_eq!(metadata.len(), 1);
    Ok(())
}
