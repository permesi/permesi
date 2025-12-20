use admission_token::{AdmissionTokenClaims, Jwks, TOKEN_VERSION, sign_rs256};
use anyhow::{Context, Result, anyhow};
use std::fs;
use std::sync::OnceLock;
use tracing::error;

#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    pub issuer: String,
    pub audience: String,
    pub kid: String,
    private_key_pem: Vec<u8>,
    jwks: Jwks,
}

impl AdmissionConfig {
    pub fn from_env() -> Result<Self> {
        let issuer = std::env::var("GENESIS_ADMISSION_ISS")
            .unwrap_or_else(|_| "https://genesis.permesi.dev".to_string());
        let audience =
            std::env::var("GENESIS_ADMISSION_AUD").unwrap_or_else(|_| "permesi".to_string());
        let kid =
            std::env::var("GENESIS_ADMISSION_KID").unwrap_or_else(|_| "genesis-1".to_string());

        let private_key_pem = if let Ok(path) = std::env::var("GENESIS_ADMISSION_PRIVATE_KEY_PATH")
        {
            fs::read(&path).with_context(|| {
                format!("failed to read GENESIS_ADMISSION_PRIVATE_KEY_PATH: {path}")
            })?
        } else if let Ok(pem) = std::env::var("GENESIS_ADMISSION_PRIVATE_KEY_PEM") {
            pem.into_bytes()
        } else {
            return Err(anyhow!(
                "missing GENESIS_ADMISSION_PRIVATE_KEY_PEM or GENESIS_ADMISSION_PRIVATE_KEY_PATH"
            ));
        };

        let jwks = Jwks::from_rsa_private_key_pem_or_der(&private_key_pem, kid.clone())
            .context("failed to derive JWKS from private key")?;

        Ok(Self {
            issuer,
            audience,
            kid,
            private_key_pem,
            jwks,
        })
    }

    pub fn jwks(&self) -> &Jwks {
        &self.jwks
    }

    pub fn sign(&self, claims: &AdmissionTokenClaims) -> Result<String> {
        Ok(sign_rs256(&self.private_key_pem, self.kid.clone(), claims)?)
    }
}

static ADMISSION_CONFIG: OnceLock<AdmissionConfig> = OnceLock::new();

pub fn admission_config() -> Result<&'static AdmissionConfig> {
    let cfg = ADMISSION_CONFIG.get_or_init(|| match AdmissionConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Admission config initialization failed: {e:#}");
            AdmissionConfig {
                issuer: String::new(),
                audience: String::new(),
                kid: String::new(),
                private_key_pem: Vec::new(),
                jwks: Jwks { keys: Vec::new() },
            }
        }
    });

    if cfg.private_key_pem.is_empty() {
        return Err(anyhow!("admission token signing key not configured"));
    }
    Ok(cfg)
}

pub fn make_claims(
    now_unix_seconds: i64,
    exp_unix_seconds: i64,
    jti: String,
    sub: Option<String>,
) -> Result<AdmissionTokenClaims> {
    let cfg = admission_config()?;
    Ok(AdmissionTokenClaims {
        v: TOKEN_VERSION,
        iss: cfg.issuer.clone(),
        aud: cfg.audience.clone(),
        iat: now_unix_seconds,
        exp: exp_unix_seconds,
        jti,
        sub,
    })
}
