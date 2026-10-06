//! Typed native management client and real OPAQUE account registration.
//!
//! Flow Overview: fetch real Genesis admission, register an OPAQUE account, read
//! its verification capability only from the isolated outbox, then establish a real
//! session through the browser or native OPAQUE proofs. Both paths verify session
//! kind and identity server-side. Fixture hierarchy, scopes and clients are created
//! through management APIs. Cookies and proofs are never persisted or reported.

use crate::{
    browser::Browser,
    error::{Failure, Result, Safe, check},
    infrastructure::random,
    manifest::Manifest,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    key_exchange::tripledh::TripleDh,
};
use opaque_rand_core::OsRng;
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

/// Cookie-backed client restricted to the generated issuer origin; no automatic redirects.
#[derive(Clone)]
pub struct Api {
    pub origin: String,
    pub client: reqwest::Client,
    cookie: SecretString,
    pub user_id: Option<Uuid>,
}

impl Api {
    /// Back-channel token exchange without session cookies, redirects or authority-bearing queries.
    pub async fn token(
        &self,
        fields: &[(&str, &str)],
        basic: Option<&str>,
    ) -> Result<reqwest::Response> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.extend_pairs(fields.iter().copied());
        let mut request = self
            .client
            .post(format!("{}/token", self.origin))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form.finish());
        if let Some(basic) = basic {
            request = request.header(reqwest::header::AUTHORIZATION, basic);
        }
        request.send().await.safe("Token HTTP request failed.")
    }
    /// Constructs an anonymous client before registration; callers cannot supply an external origin.
    pub fn anonymous(origin: String, client: reqwest::Client) -> Self {
        Self {
            origin,
            client,
            cookie: SecretString::from(String::new()),
            user_id: None,
        }
    }

    /// Retains only the actual browser's full-session cookie after verifying session kind server-side.
    pub async fn authenticated(&self, login: &Value) -> Result<Self> {
        let cookie = login
            .get("cookies")
            .and_then(Value::as_array)
            .and_then(|cookies| {
                cookies.iter().find(|cookie| {
                    cookie.get("name").and_then(Value::as_str) == Some("permesi_session")
                })
            })
            .and_then(|cookie| cookie.get("value"))
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::assertion("Real login did not set the session cookie."))?;
        self.authenticate_cookie(cookie).await
    }

    /// Verify a cookie actually issued by the native OPAQUE endpoint against the session API.
    pub async fn authenticated_response(&self, response: &reqwest::Response) -> Result<Self> {
        check(
            response.status() == StatusCode::NO_CONTENT,
            "Native OPAQUE login did not succeed.",
        )?;
        let cookie = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| value.split(';').next()?.strip_prefix("permesi_session="))
            .ok_or_else(|| {
                Failure::assertion("Native OPAQUE login did not issue its session cookie.")
            })?;
        self.authenticate_cookie(cookie).await
    }

    /// Accept only a verified full session; browser/native response data alone confers no authority.
    async fn authenticate_cookie(&self, cookie: &str) -> Result<Self> {
        let mut authenticated = Self {
            origin: self.origin.clone(),
            client: self.client.clone(),
            cookie: SecretString::from(format!("permesi_session={cookie}")),
            user_id: None,
        };
        let session: Value = authenticated
            .json(Method::GET, "/v1/auth/session", None, StatusCode::OK)
            .await?;
        check(
            session.get("session_kind").and_then(Value::as_str) == Some("full"),
            "Real login did not establish a full session.",
        )?;
        authenticated.user_id = Some(
            text_field(&session, "user_id")?
                .parse()
                .safe("Invalid authenticated user identity.")?,
        );
        Ok(authenticated)
    }

    /// Sends one request without retries. A relative management path cannot exfiltrate cookies.
    pub async fn response(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<reqwest::Response> {
        check(
            (path.starts_with("/v1/")
                || path.starts_with("/authorize?")
                || path.starts_with("/.well-known/")
                || path == "/jwks.json")
                && !path.contains(['\r', '\n'])
                && !path.starts_with("//"),
            "Invalid native API path.",
        )?;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin));
        if !self.cookie.expose_secret().is_empty() {
            request = request.header(reqwest::header::COOKIE, self.cookie.expose_secret());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.safe("Management HTTP request failed.")
    }

    /// Checks exact status before decoding a DTO; response bodies are not error diagnostics.
    pub async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        expected: StatusCode,
    ) -> Result<T> {
        let response = self.response(method, path, body).await?;
        check(
            response.status() == expected,
            match response.status().as_u16() {
                401 => "Management API unexpectedly rejected the session.",
                403 => "Management API unexpectedly denied authority.",
                409 => "Management API unexpectedly reported a conflict.",
                429 => "Management API unexpectedly rate limited the request.",
                500..=599 => "Management API unexpectedly reported a server error.",
                _ => "Management API returned an unexpected status.",
            },
        )?;
        response
            .json()
            .await
            .safe("Management API returned an invalid DTO.")
    }

    /// Asserts lifecycle status without decoding an error response or following its redirect.
    pub async fn status(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        expected: StatusCode,
    ) -> Result<()> {
        check(
            self.response(method, path, body).await?.status() == expected,
            "Lifecycle API returned an unexpected status.",
        )
    }

    /// Deletes only the reviewed immutable organization identity, using the existing race guard header.
    pub async fn delete_org(&self, org: &Resource, expected: StatusCode) -> Result<()> {
        let response = self
            .client
            .delete(format!("{}/v1/orgs/{}", self.origin, org.slug))
            .header(reqwest::header::COOKIE, self.cookie.expose_secret())
            .header("X-Permesi-Expected-Organization-Id", org.id.to_string())
            .send()
            .await
            .safe("Organization deletion request failed.")?;
        check(
            response.status() == expected,
            "Organization deletion returned an unexpected status.",
        )
    }

    /// Fetch one real Genesis token; it stays in memory and is never a diagnostic.
    async fn admission_token(&self) -> Result<SecretString> {
        let token: Value = self
            .client
            .get(format!(
                "{}/admission/token?client_id={}",
                self.origin,
                Uuid::nil()
            ))
            .send()
            .await
            .safe("Admission token request failed.")?
            .error_for_status()
            .safe("Genesis rejected admission token issuance.")?
            .json()
            .await
            .safe("Invalid admission response.")?;
        let token = text_field(&token, "token")?;
        Ok(SecretString::from(token))
    }

    /// Send admission-protected account requests, retaining the original session for reauthentication.
    async fn auth_response(&self, path: &str, body: Value) -> Result<reqwest::Response> {
        let token = self.admission_token().await?;
        let mut request = self
            .client
            .post(format!("{}{path}", self.origin))
            .header("X-Permesi-Zero-Token", token.expose_secret())
            .json(&body);
        if !self.cookie.expose_secret().is_empty() {
            request = request.header(reqwest::header::COOKIE, self.cookie.expose_secret());
        }
        request.send().await.safe("Account HTTP request failed.")
    }

    /// Uses a fresh real admission token for every OPAQUE/email mutation.
    async fn auth_post(&self, path: &str, body: Value, expected: StatusCode) -> Result<Value> {
        let response = self.auth_response(path, body).await?;
        if response.status() != expected {
            let body = response
                .text()
                .await
                .safe("Cannot inspect account failure category.")?;
            let message = match body.as_str() {
                "Invalid token" => "Real Genesis admission token was rejected.",
                "Missing zero token" => "Registration omitted the admission header.",
                "Invalid email" => "Fixture account email was rejected.",
                "Invalid registration request" => "OPAQUE registration request was rejected.",
                _ => match path {
                    "/v1/auth/opaque/signup/start" => {
                        "OPAQUE signup start returned an unexpected status."
                    }
                    "/v1/auth/opaque/signup/finish" => {
                        "OPAQUE signup finish returned an unexpected status."
                    }
                    _ => "Email verification returned an unexpected status.",
                },
            };
            return Err(Failure::assertion(message));
        }
        if expected == StatusCode::NO_CONTENT {
            Ok(Value::Null)
        } else {
            response
                .json()
                .await
                .safe("Invalid account registration response.")
        }
    }
}

/// Existing-account credentials held only for real OPAQUE login and never serializable.
pub struct Actor {
    pub email: String,
    pub password: SecretString,
}

impl Actor {
    /// Start a native proof on the selected real replica; no protocol state is seeded in SQL.
    pub async fn password_proof(&self, api: &Api, flow: PasswordFlow) -> Result<PasswordProof> {
        let mut rng = OsRng;
        let client =
            ClientLogin::<Suite>::start(&mut rng, self.password.expose_secret().as_bytes())
                .safe("Cannot start OPAQUE login.")?;
        let credential_request = STANDARD.encode(client.message.serialize());
        let payload = match flow {
            PasswordFlow::Login => {
                json!({"email":self.email,"credential_request":credential_request})
            }
            PasswordFlow::Reauthenticate => json!({"credential_request":credential_request}),
        };
        let response = api
            .auth_post(flow.start_path(), payload, StatusCode::OK)
            .await?;
        let id = text_field(&response, "login_id")?
            .parse()
            .safe("Invalid OPAQUE exchange reference.")?;
        let bytes = STANDARD
            .decode(text_field(&response, "credential_response")?)
            .safe("Invalid OPAQUE credential response encoding.")?;
        let response = CredentialResponse::<Suite>::deserialize(&bytes)
            .safe("Invalid OPAQUE credential response.")?;
        let ksf = opaque_argon2::Argon2::default();
        let finish = client
            .state
            .finish(
                &mut rng,
                self.password.expose_secret().as_bytes(),
                response,
                ClientLoginFinishParameters::new(
                    None,
                    Identifiers {
                        client: Some(self.email.as_bytes()),
                        server: Some(b"api.permesi.dev"),
                    },
                    Some(&ksf),
                ),
            )
            .safe("Cannot complete OPAQUE client proof.")?;
        Ok(PasswordProof {
            id,
            email: self.email.clone(),
            finalization: SecretString::from(STANDARD.encode(finish.message.serialize())),
            flow,
        })
    }
    /// Registers and verifies a new account through real admission-protected product endpoints.
    pub async fn signup(api: &Api, pool: &PgPool) -> Result<Self> {
        let email = format!("scenario-{}@example.test", Uuid::new_v4().simple());
        let password = random()?;
        let mut rng = OsRng;
        let start = ClientRegistration::<Suite>::start(&mut rng, password.as_bytes())
            .safe("Cannot start OPAQUE registration.")?;
        let response = api.auth_post("/v1/auth/opaque/signup/start", json!({"email":email,"registration_request":STANDARD.encode(start.message.serialize())}), StatusCode::OK).await?;
        let bytes = STANDARD
            .decode(text_field(&response, "registration_response")?)
            .safe("Invalid OPAQUE registration encoding.")?;
        let response = RegistrationResponse::<Suite>::deserialize(&bytes)
            .safe("Invalid OPAQUE registration transcript.")?;
        let ksf = opaque_argon2::Argon2::default();
        let params = ClientRegistrationFinishParameters::new(
            Identifiers {
                client: Some(email.as_bytes()),
                server: Some(b"api.permesi.dev"),
            },
            Some(&ksf),
        );
        let finish = start
            .state
            .finish(&mut rng, password.as_bytes(), response, params)
            .safe("Cannot finish OPAQUE registration.")?;
        api.auth_post("/v1/auth/opaque/signup/finish", json!({"email":email,"registration_record":STANDARD.encode(finish.message.serialize())}), StatusCode::CREATED).await?;
        let outbox: String = sqlx::query_scalar("SELECT payload_json::text FROM email_outbox WHERE to_email=$1 ORDER BY created_at DESC LIMIT 1").bind(&email).fetch_one(pool).await.safe("Cannot read isolated verification outbox.")?;
        let outbox: Value =
            serde_json::from_str(&outbox).safe("Invalid isolated outbox payload.")?;
        let verify_url = text_field(&outbox, "verify_url")?;
        let url = Url::parse(&verify_url).safe("Invalid isolated verification URL.")?;
        check(
            url.origin().ascii_serialization() == api.origin,
            "Verification URL escaped the isolated issuer.",
        )?;
        let token = url::form_urlencoded::parse(url.fragment().unwrap_or("").as_bytes())
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| Failure::harness("Verification capability missing."))?;
        api.auth_post(
            "/v1/auth/verify-email",
            json!({"token":token}),
            StatusCode::NO_CONTENT,
        )
        .await?;
        Ok(Self {
            email,
            password: SecretString::from(password),
        })
    }

    /// Establishes a fresh real browser context; no session row or role claim is seeded.
    pub async fn login(
        &self,
        browser: &mut Browser,
        api: &Api,
        callback: &str,
        name: &str,
    ) -> Result<Api> {
        browser
            .call(json!({"action":"new","actor":name,"origin":api.origin,"callback":callback}))
            .await?;
        let login = browser.call(json!({"action":"login","actor":name,"navigate":true,"email":self.email,"password":self.password.expose_secret()})).await?;
        api.authenticated(&login).await
    }
}

/// Native fixture purposes mirror existing endpoints; no browser field selects server authority.
#[derive(Clone, Copy)]
pub enum PasswordFlow {
    Login,
    Reauthenticate,
}

impl PasswordFlow {
    /// Start endpoint for one fixed protocol purpose.
    fn start_path(self) -> &'static str {
        match self {
            Self::Login => "/v1/auth/opaque/login/start",
            Self::Reauthenticate => "/v1/auth/opaque/reauth/start",
        }
    }
    /// Finish endpoint must retain the purpose selected at start.
    fn finish_path(self) -> &'static str {
        match self {
            Self::Login => "/v1/auth/opaque/login/finish",
            Self::Reauthenticate => "/v1/auth/opaque/reauth/finish",
        }
    }
}

/// Real client finalization retained only in memory; no Debug or Serialize implementation.
pub struct PasswordProof {
    id: Uuid,
    email: String,
    finalization: SecretString,
    flow: PasswordFlow,
}

impl PasswordProof {
    /// Submit exactly one proof with fresh admission; callers assert both success and replay denial.
    pub async fn finish(&self, api: &Api) -> Result<reqwest::Response> {
        let payload = match self.flow {
            PasswordFlow::Login => {
                json!({"login_id":self.id.to_string(),"email":self.email,"credential_finalization":self.finalization.expose_secret()})
            }
            PasswordFlow::Reauthenticate => {
                json!({"login_id":self.id.to_string(),"credential_finalization":self.finalization.expose_secret()})
            }
        };
        api.auth_response(self.flow.finish_path(), payload).await
    }
}

struct Suite;
impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, opaque_sha2::Sha512>;
    type Ksf = opaque_argon2::Argon2<'static>;
}

#[derive(Deserialize, Clone)]
pub struct Resource {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub slug: String,
}

#[derive(Deserialize, Clone)]
pub struct Registration {
    pub id: Uuid,
    pub client_id: Uuid,
    pub application_id: Uuid,
    pub client_type: String,
}

/// A newly provisioned application with its full ancestry and custom registry.
pub struct Application {
    pub resource: Resource,
    pub path: String,
    pub scopes: Vec<String>,
    pub descriptions: Vec<String>,
    pub public: Registration,
    pub confidential: Registration,
}

/// Fresh case-local tenant; setup is a fixture operation, not a dependency on another test case.
pub struct Fixture {
    pub org: Resource,
    pub project: Resource,
    pub project_path: String,
    pub environments: Vec<(Resource, String, Vec<Application>)>,
}

impl Fixture {
    /// Creates manifest-owned resources through the API; every case has independent grants/clients.
    pub async fn create(api: &Api, manifest: &Manifest, seed: u64, callback: &str) -> Result<Self> {
        let identity = Uuid::new_v4().simple().to_string();
        let org: Resource = api.json(Method::POST, "/v1/orgs", Some(json!({"name":format!("{} [{identity}]",manifest.organization),"slug":format!("scenario-{seed}-{identity}")})), StatusCode::CREATED).await?;
        let project_path = format!("/v1/orgs/{}/projects", org.slug);
        let project: Resource = api
            .json(
                Method::POST,
                &project_path,
                Some(json!({"name":manifest.project,"slug":"scenario-project"})),
                StatusCode::CREATED,
            )
            .await?;
        let project_path = format!("{project_path}/{}", project.slug);
        let mut environments = Vec::new();
        for environment in &manifest.environments {
            let resource: Resource = api.json(Method::POST, &format!("{project_path}/envs"), Some(json!({"name":environment.name,"slug":environment.slug,"tier":environment.tier})), StatusCode::CREATED).await?;
            let path = format!("{project_path}/envs/{}", resource.slug);
            let mut applications = Vec::new();
            for application in &environment.applications {
                let app: Resource = api
                    .json(
                        Method::POST,
                        &format!("{path}/apps"),
                        Some(json!({"name":application.name})),
                        StatusCode::CREATED,
                    )
                    .await?;
                let path = format!("{path}/apps/{}", app.id);
                let mut scopes = Vec::new();
                for scope in &application.scopes {
                    let _: Value = api
                        .json(
                            Method::POST,
                            &format!("{path}/oauth/scopes"),
                            Some(json!({"name":scope.name,"description":scope.description})),
                            StatusCode::CREATED,
                        )
                        .await?;
                    scopes.push(scope.name.clone());
                }
                let first = scopes
                    .first()
                    .ok_or_else(|| Failure::harness("Fixture omitted required scopes."))?;
                let public = create_client(
                    api,
                    &path,
                    "public",
                    callback,
                    &["openid".to_owned(), "profile".to_owned(), first.clone()],
                )
                .await?;
                // Confidential callbacks require HTTPS, so they use the gateway-owned callback path.
                let confidential = create_client(
                    api,
                    &path,
                    "confidential",
                    &format!("{}/client-callback", api.origin),
                    &scopes,
                )
                .await?;
                applications.push(Application {
                    resource: app,
                    path,
                    scopes,
                    descriptions: application
                        .scopes
                        .iter()
                        .map(|scope| scope.description.clone())
                        .collect(),
                    public,
                    confidential,
                });
            }
            environments.push((resource, path, applications));
        }
        Ok(Self {
            org,
            project,
            project_path,
            environments,
        })
    }

    /// Returns the first application for cases that exercise one registration; all others stay isolated.
    pub fn app(&self) -> Result<&Application> {
        self.environments
            .first()
            .and_then(|(_, _, apps)| apps.first())
            .ok_or_else(|| Failure::harness("Fixture omitted application."))
    }
}

/// Creates and configures a client through separate existing management endpoints.
pub async fn create_client(
    api: &Api,
    path: &str,
    kind: &str,
    callback: &str,
    scopes: &[String],
) -> Result<Registration> {
    let client: Registration = api
        .json(
            Method::POST,
            &format!("{path}/oauth/clients"),
            Some(json!({"name":format!("Scenario {kind} [{}]", Uuid::new_v4().simple()),"client_type":kind})),
            StatusCode::CREATED,
        )
        .await?;
    let redirects = if kind == "public" {
        vec![callback.to_owned(), format!("{callback}/alternate")]
    } else {
        vec![callback.to_owned()]
    };
    let _: Value = api
        .json(
            Method::PUT,
            &format!("{path}/oauth/clients/{}/redirect-uris", client.client_id),
            Some(json!({"redirect_uris":redirects})),
            StatusCode::OK,
        )
        .await?;
    let _: Value = api
        .json(
            Method::PUT,
            &format!("{path}/oauth/clients/{}/scopes", client.client_id),
            Some(json!({"scopes":scopes})),
            StatusCode::OK,
        )
        .await?;
    let persisted: Vec<String> = api
        .json(
            Method::GET,
            &format!("{path}/oauth/clients/{}/redirect-uris", client.client_id),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        persisted.len() == redirects.len() && redirects.iter().all(|uri| persisted.contains(uri)),
        "Registered redirects did not round-trip exactly.",
    )?;
    Ok(client)
}

/// Extracts private fields without ever embedding the response or field value in an error.
pub fn text_field(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::harness("Expected response field is missing."))
}
