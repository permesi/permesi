//! Local TLS SMTP peer exercises real transport, certificate validation and bounded failure.
use super::*;
use lettre::{
    AsyncSmtpTransport, Tokio1Executor,
    transport::smtp::client::{Certificate, Tls, TlsParameters},
};
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tracing::instrument::WithSubscriber as _;

/// Validated test configuration uses normal dispatch parsing rather than disabling TLS.
fn settings(port: u16, tls: &str) -> Result<DeliveryConfig> {
    let matches = crate::cli::commands::with_registration_args(clap::Command::new("test"))
        .mut_args(|arg| arg.env(None::<&str>))
        .try_get_matches_from([
            "test",
            "--email-delivery",
            "smtp",
            "--smtp-host",
            "localhost",
            "--smtp-from",
            "Permesi <accounts@permesi.test>",
            "--smtp-port",
            &port.to_string(),
            "--smtp-tls",
            tls,
            "--smtp-timeout-seconds",
            "1",
        ])?;
    DeliveryConfig::from_matches(&matches)
}

/// A local peer accepts a single message and captures only in memory; no delivery credential is logged.
async fn smtp_peer() -> Result<(u16, Vec<u8>, tokio::task::JoinHandle<Result<String>>)> {
    smtp_peer_with_gate(None).await
}

/// Pauses real SMTP after DATA so the test probes database locks during active network work.
async fn smtp_peer_with_gate(
    mut gate: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
) -> Result<(u16, Vec<u8>, tokio::task::JoinHandle<Result<String>>)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let der = certificate.cert.der().to_vec();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into()),
        )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let tls = acceptor.accept(socket).await?;
        let mut stream = BufReader::new(tls);
        stream
            .get_mut()
            .write_all(b"220 localhost ESMTP\r\n")
            .await?;
        let mut message = String::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await? == 0 {
                break;
            }
            let response = if line.starts_with("EHLO") {
                "250 localhost\r\n"
            } else if line.starts_with("DATA") {
                stream.get_mut().write_all(b"354 Send message\r\n").await?;
                if let Some((ready, release)) = gate.take() {
                    let _ = ready.send(());
                    release.await?;
                }
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await? == 0 || line == ".\r\n" {
                        break;
                    }
                    message.push_str(&line);
                }
                "250 queued\r\n"
            } else if line.starts_with("QUIT") {
                stream.get_mut().write_all(b"221 bye\r\n").await?;
                break;
            } else {
                "250 ok\r\n"
            };
            stream.get_mut().write_all(response.as_bytes()).await?;
        }
        Ok(message)
    });
    Ok((port, der, task))
}

/// Real TLS delivery succeeds only when the fixture's CA is explicitly trusted.
#[tokio::test]
async fn smtp_tls_delivery_sends_verification_without_database_lock() -> Result<()> {
    let (_postgres, pool) = database().await?;
    enqueue(&pool).await?;
    let (ready, arrived) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    let (port, root, peer) = smtp_peer_with_gate(Some((ready, resume))).await?;
    let delivery = settings(port, "implicit")?;
    let config = EmailWorkerConfig::new();
    let settings = delivery.smtp.clone().context("SMTP")?;
    let tls = TlsParameters::builder(settings.host.clone())
        .add_root_certificate(Certificate::from_der(root)?)
        .build()?;
    let sender = transport::Sender {
        transport: AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
            .port(port)
            .tls(Tls::Wrapper(tls))
            .build(),
        settings,
    };
    let probe = async {
        arrived.await?;
        let mut independent = pool.begin().await?;
        sqlx::query("SELECT id FROM email_outbox FOR UPDATE NOWAIT")
            .execute(&mut *independent)
            .await?;
        independent.rollback().await?;
        let _ = release.send(());
        anyhow::Ok(())
    };
    let cancel = CancellationToken::new();
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = TraceSink(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .finish();
    let delivery_work = Box::pin(
        process_outbox_batch(&pool, &sender, &delivery, &config, &cancel)
            .with_subscriber(subscriber),
    );
    let (sent, unlocked) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(delivery_work, probe)
    })
    .await?;
    sent?;
    unlocked?;
    let row: (String, i32, bool) =
        sqlx::query_as("SELECT status::text,attempts,claim_id IS NULL FROM email_outbox")
            .fetch_one(&pool)
            .await?;
    assert_eq!(row, ("sent".into(), 1, true));
    let body = tokio::time::timeout(Duration::from_secs(3), peer).await???;
    assert!(body.contains("Verify your Permesi email address"));
    assert!(body.contains("private-test-capability"));
    let logs = String::from_utf8(
        output
            .lock()
            .map_err(|_| anyhow::anyhow!("capture poisoned"))?
            .clone(),
    )?;
    assert!(logs.contains("email delivery attempt"));
    for secret in [
        "recipient@example.test",
        "private-test-capability",
        "verify_url",
        "payload_json=",
    ] {
        assert!(!logs.contains(secret));
    }
    Ok(())
}

/// Production TLS construction rejects the untrusted fixture instead of sending its capability.
#[tokio::test]
async fn smtp_rejects_untrusted_certificate_without_exposing_payload() -> Result<()> {
    let (port, _root, peer) = smtp_peer().await?;
    let delivery = settings(port, "implicit")?;
    let sender = transport::Sender::new(delivery.smtp.context("SMTP")?)?;
    let message = EmailMessage { to_email:"recipient@example.test".into(),template:"verify_email".into(),payload_json:r#"{"email":"recipient@example.test","verify_url":"https://permesi.test/#token=private-test-capability"}"#.into() };
    let error = sender
        .send(&message)
        .await
        .err()
        .context("TLS must reject fixture")?;
    assert_eq!(error.to_string(), "smtp_delivery_failed");
    assert!(
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await??
            .is_err()
    );
    Ok(())
}

/// A stalled SMTP connection is bounded independently of database lock/statement timeouts.
#[tokio::test]
async fn smtp_stalled_connection_times_out_and_keeps_mail_unsent() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let delivery = settings(listener.local_addr()?.port(), "implicit")?;
    let sender = transport::Sender::new(delivery.smtp.context("SMTP")?)?;
    let message = EmailMessage { to_email:"recipient@example.test".into(),template:"verify_email".into(),payload_json:r#"{"email":"recipient@example.test","verify_url":"https://permesi.test/#token=private-test-capability"}"#.into() };
    let started = std::time::Instant::now();
    let result = sender.send(&message).await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    Ok(())
}

/// Invalid policy fails startup; credentials remain redacted even when config debugging is enabled.
#[test]
fn smtp_configuration_requires_explicit_secure_delivery() -> Result<()> {
    let parse = |args: &[&str]| -> Result<DeliveryConfig> {
        let matches = crate::cli::commands::with_registration_args(clap::Command::new("test"))
            .mut_args(|arg| arg.env(None::<&str>))
            .try_get_matches_from(args)?;
        DeliveryConfig::from_matches(&matches)
    };
    for args in [
        vec!["test", "--email-delivery", "smtp"],
        vec!["test", "--smtp-password", "private-password"],
        vec!["test", "--smtp-tls", "none"],
        vec![
            "test",
            "--smtp-timeout-seconds",
            "60",
            "--email-lease-seconds",
            "10",
        ],
    ] {
        assert!(parse(&args).is_err());
    }
    let mut config = settings(465, "implicit")?;
    let smtp = config.smtp.as_mut().context("SMTP")?;
    smtp.username = Some(SecretString::from("private-username"));
    smtp.password = Some(SecretString::from("private-password"));
    let debug = format!("{config:?}");
    assert!(!debug.contains("private-username") && !debug.contains("private-password"));
    Ok(())
}

/// STARTTLS is mandatory: a plaintext peer cannot receive the recipient, credentials or message.
#[tokio::test]
async fn smtp_starttls_refuses_plaintext_downgrade() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let delivery = settings(listener.local_addr()?.port(), "starttls")?;
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut stream = BufReader::new(socket);
        stream
            .get_mut()
            .write_all(b"220 localhost ESMTP\r\n")
            .await?;
        let mut greeting = String::new();
        stream.read_line(&mut greeting).await?;
        anyhow::ensure!(greeting.starts_with("EHLO"), "SMTP greeting");
        stream.get_mut().write_all(b"250 localhost\r\n").await?;
        let mut next = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_line(&mut next)).await;
        anyhow::ensure!(
            !next.starts_with("MAIL") && !next.starts_with("AUTH") && !next.starts_with("DATA"),
            "SMTP must not continue in plaintext"
        );
        anyhow::Ok(())
    });
    let sender = transport::Sender::new(delivery.smtp.context("SMTP")?)?;
    let message = EmailMessage { to_email:"recipient@example.test".into(),template:"verify_email".into(),payload_json:r#"{"email":"recipient@example.test","verify_url":"https://permesi.test/#token=private-test-capability"}"#.into() };
    assert!(sender.send(&message).await.is_err());
    tokio::time::timeout(Duration::from_secs(3), peer).await???;
    Ok(())
}
