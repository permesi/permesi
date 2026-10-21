//! SMTP delivery is an external side effect and always runs after outbox claim commit.
//! Only the exact server-owned verification template is rendered; provider errors are opaque.
use super::{EmailMessage, config::SmtpSettings};
use anyhow::{Result, anyhow};
use lettre::{
    AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use secrecy::ExposeSecret as _;

/// Concrete transport avoids dynamic async traits and keeps secret-bearing configuration private.
pub(super) struct Sender {
    pub(super) transport: AsyncSmtpTransport<Tokio1Executor>,
    pub(super) settings: SmtpSettings,
}
impl Sender {
    /// Requires either TLS-on-connect or mandatory STARTTLS; certificate checks are never disabled.
    pub(super) fn new(settings: SmtpSettings) -> Result<Self> {
        let builder = if settings.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)
        }
        .map_err(|_| anyhow!("SMTP TLS configuration failed"))?;
        let mut builder = builder.port(settings.port).timeout(Some(settings.timeout));
        if let (Some(username), Some(password)) = (&settings.username, &settings.password) {
            builder = builder.credentials(Credentials::new(
                username.expose_secret().to_owned(),
                password.expose_secret().to_owned(),
            ));
        }
        Ok(Self {
            transport: builder.build(),
            settings,
        })
    }

    /// Renders and sends without logging identifiers, links, payloads or provider error text.
    pub(super) async fn send(&self, message: &EmailMessage) -> Result<()> {
        let email = self.render(message)?;
        tokio::time::timeout(self.settings.timeout, self.transport.send(email))
            .await
            .map_err(|_| anyhow!("smtp_timeout"))?
            .map_err(|_| anyhow!("smtp_delivery_failed"))?;
        Ok(())
    }

    /// Only generated verification templates reach SMTP; unrecognized payloads fail closed.
    fn render(&self, message: &EmailMessage) -> Result<Message> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Verification {
            email: String,
            verify_url: String,
        }
        if message.template != "verify_email" {
            return Err(anyhow!("invalid_email_template"));
        }
        let payload: Verification = serde_json::from_str(&message.payload_json)
            .map_err(|_| anyhow!("invalid_email_payload"))?;
        if payload.email != message.to_email {
            return Err(anyhow!("invalid_email_recipient"));
        }
        Message::builder().from(self.settings.from.clone())
            .to(message.to_email.parse().map_err(|_| anyhow!("invalid_email_recipient"))?)
            .subject("Verify your Permesi email address")
            .body(format!("Verify your email address using this link:\n\n{}\n\nIf you did not request this account, ignore this email.", payload.verify_url))
            .map_err(|_| anyhow!("invalid_email_message"))
    }
}
