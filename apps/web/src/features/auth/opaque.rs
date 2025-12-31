use argon2::Argon2;
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::{CipherSuite, Identifiers};

pub struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Argon2<'static>;
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn identifiers<'a>(client_id: &'a [u8], server_id: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(client_id),
        server: Some(server_id),
    }
}

pub fn ksf() -> Argon2<'static> {
    Argon2::default()
}
