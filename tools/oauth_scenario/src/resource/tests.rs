//! Valid signatures isolate resource claim, tenant, scope and JOSE rejection paths.

#![allow(clippy::indexing_slicing)]

use super::*;
use crate::test_tokens;

#[tokio::test]
async fn cache_cancellation_cannot_extend_stale_key_authority() -> Result<()> {
    let listener = listener()?; // Deliberately never accept: verified TLS cannot finish.
    let verifier = Verifier::new(
        Transport {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .safe("Cannot build test transport.")?,
            issuer: format!(
                "https://localhost:{}",
                listener.local_addr().safe("Test port unavailable.")?.port()
            ),
        },
        "jobs-api".into(),
    );
    *verifier.cache.lock().await = Cache {
        keys: parse_keys(&test_tokens::jwks()?)?,
        loaded: Instant::now().checked_sub(Duration::from_secs(61)),
        unknown_refresh: None,
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(30), verifier.key("test-key"))
            .await
            .is_err()
    );
    assert!(verifier.cache.lock().await.keys.is_empty());
    assert!(verifier.key("test-key").await.is_err());
    assert_eq!(verifier.fetches.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn cache_coalesces_unknown_kids_and_failed_initial_fetches() -> Result<()> {
    for status in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
        let issuer =
            crate::test_http::Issuer::start(test_tokens::jwks()?.to_string(), status).await?;
        let verifier = Arc::new(Verifier::new(issuer.transport.clone(), "jobs-api".into()));
        if status == StatusCode::OK {
            verifier.key("test-key").await?;
        }
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let verifier = verifier.clone();
            tasks.spawn(async move { verifier.key(&Uuid::new_v4().to_string()).await.is_err() });
        }
        while let Some(result) = tasks.join_next().await {
            assert!(result.safe("Test task failed.")?);
        }
        let expected = if status == StatusCode::OK { 2 } else { 1 };
        assert_eq!(issuer.requests.load(Ordering::SeqCst), expected);
        assert_eq!(verifier.fetches.load(Ordering::SeqCst), expected);
    }
    Ok(())
}

#[tokio::test]
async fn resource_listener_closes_after_explicit_shutdown_and_drop() -> Result<()> {
    for explicit in [true, false] {
        let files = crate::files::PrivateDir::new()?;
        let tls = Tls::new(&files)?;
        let transport = Transport {
            client: tls.client(2)?,
            issuer: "https://localhost:1234".into(),
        };
        let mut server = ResourceServer::start(&tls, transport, "jobs-api".into()).await?;
        let url = format!(
            "{}/orgs/{}/apps/{}/jobs",
            server.origin,
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        assert_eq!(
            tls.client(2)?
                .get(&url)
                .send()
                .await
                .safe("Test listener did not start.")?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        if explicit {
            server.stop().await?;
        }
        drop(server);
        tokio::task::yield_now().await;
        assert!(tls.client(2)?.get(url).send().await.is_err());
    }
    Ok(())
}

/// Constructs canonical fixture claims; every mutation starts from a working control.
fn claims(now: i64) -> Value {
    json!({"iss":"https://localhost:1234","aud":"jobs-api","sub":Uuid::new_v4(),"client_id":Uuid::new_v4(),"jti":Uuid::new_v4(),"grant_id":Uuid::new_v4(),"organization_id":Uuid::new_v4(),"application_id":Uuid::new_v4(),"scope":"openid jobs:read","iat":now,"exp":now+60})
}

/// Supplies only public cached keys; a known-kid signature failure must not fetch or refresh.
async fn verifier() -> Result<Verifier> {
    let verifier = Verifier::new(
        Transport {
            client: reqwest::Client::new(),
            issuer: "https://localhost:1234".into(),
        },
        "jobs-api".into(),
    );
    *verifier.cache.lock().await = Cache {
        keys: parse_keys(&test_tokens::jwks()?)?,
        loaded: Some(Instant::now()),
        unknown_refresh: None,
    };
    Ok(verifier)
}

#[tokio::test]
async fn bearer_rejects_correctly_signed_invalid_claims() -> Result<()> {
    let verifier = verifier().await?;
    let now = chrono::Utc::now().timestamp();
    let good = claims(now);
    let header = json!({"alg":"RS256","typ":"at+jwt","kid":"test-key"});
    verifier
        .authenticate(&test_tokens::sign(&header, &good)?)
        .await?;
    for (field, value) in [
        ("iss", json!("https://attacker.invalid")),
        ("aud", json!("another-api")),
        ("exp", json!(now)),
        ("iat", json!(now + 10)),
        ("nbf", json!(now + 10)),
        ("exp", json!(now + 3601)),
        ("sub", json!(Uuid::nil())),
        ("jti", json!(Uuid::nil())),
        ("grant_id", json!(Uuid::nil())),
        ("scope", json!("jobs:read jobs:read")),
        ("scope", json!("jobs:read\tusers:write")),
        ("scope", json!("")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(
            verifier
                .authenticate(&test_tokens::sign(&header, &bad)?)
                .await
                .is_err()
        );
    }
    assert_eq!(verifier.fetches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn bearer_rejects_type_algorithm_header_and_signature_substitution() -> Result<()> {
    let verifier = verifier().await?;
    let claims = claims(chrono::Utc::now().timestamp());
    let header = json!({"alg":"RS256","typ":"at+jwt","kid":"test-key"});
    let good = test_tokens::sign(&header, &claims)?;
    verifier.authenticate(&good).await?;
    for (field, value) in [
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("typ", json!("JWT")),
        ("jku", json!("https://attacker.invalid/keys")),
        ("crit", json!(["exp"])),
    ] {
        let mut bad = header.clone();
        bad[field] = value;
        assert!(
            verifier
                .authenticate(&test_tokens::sign(&bad, &claims)?)
                .await
                .is_err()
        );
    }
    let mut tampered = claims.clone();
    tampered["aud"] = json!("other-api");
    let (_, _, signature) = parts(&good)?;
    let forged = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).safe("Test encoding failed.")?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).safe("Test encoding failed.")?),
        signature
    );
    assert!(verifier.authenticate(&forged).await.is_err());
    assert_eq!(verifier.fetches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn resource_access_requires_exact_tenant_application_and_delegated_scope() -> Result<()> {
    let mut claims: Claims = serde_json::from_value(claims(100)).safe("Invalid test claims.")?;
    assert_eq!(
        access(&claims, claims.organization_id, claims.application_id),
        StatusCode::OK
    );
    assert_eq!(
        access(&claims, Uuid::new_v4(), claims.application_id),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        access(&claims, claims.organization_id, Uuid::new_v4()),
        StatusCode::NOT_FOUND
    );
    for scope in [
        "openid",
        "platform:admin users:write",
        "jobs:read-all",
        "jobs:write",
    ] {
        claims.scope = scope.into();
        assert_eq!(
            access(&claims, claims.organization_id, claims.application_id),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            access(&claims, Uuid::new_v4(), claims.application_id),
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}

#[tokio::test]
async fn bearer_rejects_duplicate_json_members_and_array_audience() -> Result<()> {
    let verifier = verifier().await?;
    let claims = claims(chrono::Utc::now().timestamp());
    let header = json!({"alg":"RS256","typ":"at+jwt","kid":"test-key"});
    verifier
        .authenticate(&test_tokens::sign(&header, &claims)?)
        .await?;
    let duplicate_header = format!(
        "{},\"kid\":\"test-key\"}}",
        header.to_string().trim_end_matches('}')
    );
    let duplicate_claims = format!(
        "{},\"aud\":\"jobs-api\"}}",
        claims.to_string().trim_end_matches('}')
    );
    assert!(
        verifier
            .authenticate(&test_tokens::sign_raw(
                &duplicate_header,
                &claims.to_string()
            )?)
            .await
            .is_err()
    );
    assert!(
        verifier
            .authenticate(&test_tokens::sign_raw(
                &header.to_string(),
                &duplicate_claims
            )?)
            .await
            .is_err()
    );
    let mut array = claims.clone();
    array["aud"] = json!(["jobs-api"]);
    assert!(
        verifier
            .authenticate(&test_tokens::sign(&header, &array)?)
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn bearer_parser_rejects_ambiguous_headers_and_unbounded_tokens() -> Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        axum::http::HeaderValue::from_static("session=fixture"),
    );
    assert!(bearer(&headers).is_err());
    headers.insert(
        header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer a.b.c"),
    );
    assert_eq!(bearer(&headers)?, "a.b.c");
    headers.append(
        header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer other"),
    );
    assert!(bearer(&headers).is_err());
    for bad in ["a.b", "a.b.c.d", "..", &"x".repeat(8193)] {
        assert!(parts(bad).is_err());
    }
    assert!(decode("YWJj=").is_err());
    Ok(())
}

#[test]
fn jwks_rejects_private_material_ambiguous_keys_and_algorithm_changes() -> Result<()> {
    let good = test_tokens::jwks()?;
    parse_keys(&good)?;
    for (field, value) in [
        ("d", json!("secret")),
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("kty", json!("oct")),
        ("n", json!("AQ")),
    ] {
        let mut bad = good.clone();
        let first = bad
            .pointer_mut("/keys/0")
            .ok_or_else(|| Failure::harness("Missing test key."))?;
        first[field] = value;
        assert!(parse_keys(&bad).is_err());
    }
    let row = good
        .pointer("/keys/0")
        .ok_or_else(|| Failure::harness("Missing test key."))?;
    assert!(parse_keys(&json!({"keys":[row,row]})).is_err());
    assert!(parse_keys(&json!({"keys":vec![row;33]})).is_err());
    Ok(())
}
