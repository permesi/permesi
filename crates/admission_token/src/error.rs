use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid token format")]
    TokenFormat,
    #[error("invalid token header")]
    InvalidHeader,
    #[error("invalid footer")]
    InvalidFooter,
    #[error("missing footer")]
    MissingFooter,
    #[error("invalid base64url encoding")]
    Base64,
    #[error("invalid json")]
    Json(#[from] serde_json::Error),
    #[error("unsupported paserk prefix")]
    UnsupportedPaserk,
    #[error("invalid paserk id")]
    InvalidPaserkId,
    #[error("invalid paserk key length")]
    InvalidKeyLength,
    #[error("invalid key type")]
    InvalidKeyType,
    #[error("unknown key id: {0}")]
    UnknownKid(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("invalid issued-at")]
    InvalidIat,
    #[error("invalid expiration")]
    InvalidExp,
    #[error("token expired")]
    Expired,
    #[error("invalid token ttl")]
    InvalidTtl,
    #[error("invalid action")]
    InvalidAction,
    #[error("invalid paserk version")]
    InvalidPaserkVersion,
    #[error("invalid paserk purpose")]
    InvalidPaserkPurpose,
    #[error("invalid length")]
    InvalidLength,
    #[error("time parse error")]
    TimeParse,
    #[error("time format error")]
    TimeFormat,
    #[error("hash error")]
    Hash,
}
