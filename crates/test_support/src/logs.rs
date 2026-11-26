//! Capture of everything `tracing` emits while a piece of code runs, for tests that
//! assert a secret never reaches a log line or a span.
//!
//! Flow Overview: [`capture_until`] installs a TRACE-level subscriber for the calling
//! task only, runs the operation, and returns the text it produced, including one line
//! for every span that was opened with the fields recorded on it.
//!
//! The repetition exists because `tracing` caches, per callsite, whether any subscriber
//! is interested. Tests in other threads reach the same callsites with no subscriber, and
//! a callsite first registered in such a race can be cached as disabled. A hygiene test
//! must never pass because nothing was captured, so the operation is repeated, with the
//! cache rebuilt each time, until a line the caller knows must appear has been seen.

use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("log capture poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn text(captured: &Mutex<Vec<u8>>) -> String {
    captured.lock().map_or_else(
        |_| String::new(),
        |bytes| String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Run `operation` under a TRACE subscriber until `marker` appears in the output, then
/// once more, and return everything captured (events and span fields, no ANSI).
///
/// `marker` must be text the operation always emits; the returned text is guaranteed to
/// contain it, so a caller's "does not contain" assertions are never vacuous.
///
/// # Errors
/// Returns an error if `marker` never appears, which means nothing reliable was captured.
pub async fn capture_until<F, Fut>(marker: &str, mut operation: F) -> anyhow::Result<String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Sink(captured.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_span_events(FmtSpan::NEW)
        .with_writer(move || sink.clone())
        .finish();
    let observed = captured.clone();
    async {
        for _ in 0..200 {
            tracing::callsite::rebuild_interest_cache();
            operation().await;
            if text(&observed).contains(marker) {
                // One more pass with every callsite now registered and recomputed, so a
                // callsite that lost the race on the pass above is captured as well.
                tracing::callsite::rebuild_interest_cache();
                operation().await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    .with_subscriber(subscriber)
    .await;
    let logs = text(&captured);
    anyhow::ensure!(
        logs.contains(marker),
        "expected log marker {marker:?} was never captured"
    );
    Ok(logs)
}
