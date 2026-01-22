use service_utils::tls;

#[test]
fn load_reqwest_ca_defaults_to_system_roots_when_unconfigured() {
    // This test runs in its own binary (integration test), so the global OnceLock
    // in service_utils::tls is guaranteed to be unset at the start.

    // Attempt to load CAs without calling set_runtime_paths first.
    // Previously, this would error. Now it should return Ok(vec![]).
    let result = tls::load_reqwest_ca();

    assert!(
        result.is_ok(),
        "load_reqwest_ca should succeed even if TLS paths are not configured"
    );

    let cas = result.unwrap();
    assert!(
        cas.is_empty(),
        "Should return empty CA list (implying system roots) when unconfigured"
    );
}
