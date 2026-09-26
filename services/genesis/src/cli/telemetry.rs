//! Structured logging with optional OpenTelemetry (OTLP/gRPC) trace export.
//!
//! Local logging through `tracing-subscriber` is always installed. Exporting spans is
//! split into two independent decisions so operators can reason about each one:
//!
//! - **Compile time:** the default-off `telemetry` Cargo feature pulls in the
//!   OpenTelemetry SDK, the OTLP exporter, and tonic. A default build carries none of
//!   that code, and changing it requires a new binary. Release images, Debian packages,
//!   and the dev stack are built with `--features telemetry`.
//! - **Startup configuration:** a telemetry-enabled binary creates an exporter only when
//!   `OTEL_EXPORTER_OTLP_ENDPOINT` is present at process start. If the variable is set
//!   on a binary built without the feature, a warning is logged instead of silently
//!   dropping traces.
//!
//! Flow Overview:
//! 1) `init` builds the console layer and the `EnvFilter` from the CLI verbosity.
//! 2) With the feature and an endpoint, `init_tracer` builds a gzip-compressed tonic
//!    exporter (TLS with native roots for `https://` endpoints), registers the global
//!    tracer provider and the W3C trace-context + baggage propagators, and keeps the
//!    provider in a `OnceLock` for shutdown.
//! 3) The binary calls `shutdown_tracer` after the action returns so batched spans,
//!    including those that explain an error exit, are flushed.
//!
//! `OTEL_EXPORTER_OTLP_HEADERS` commonly carries collector credentials; the values are
//! converted into gRPC metadata and are never logged.

use anyhow::Result;
#[cfg(feature = "telemetry")]
use anyhow::anyhow;
#[cfg(feature = "telemetry")]
use base64::{Engine, engine::general_purpose};
#[cfg(feature = "telemetry")]
use opentelemetry::propagation::TextMapCompositePropagator;
#[cfg(feature = "telemetry")]
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::{Compression, WithExportConfig, WithTonicConfig};
#[cfg(feature = "telemetry")]
use opentelemetry_sdk::{
    Resource,
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{SdkTracerProvider, Tracer},
};
use std::env::var;
#[cfg(feature = "telemetry")]
use std::{collections::HashMap, sync::OnceLock, time::Duration};
#[cfg(feature = "telemetry")]
use tonic::{
    metadata::{Ascii, Binary, MetadataKey, MetadataMap, MetadataValue},
    transport::ClientTlsConfig,
};
use tracing::Level;
#[cfg(feature = "telemetry")]
use tracing::{debug, warn};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};
#[cfg(feature = "telemetry")]
use ulid::Ulid;

const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Tracer provider kept for `shutdown_tracer`; set at most once by `init_tracer`.
#[cfg(feature = "telemetry")]
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

#[cfg(feature = "telemetry")]
fn parse_headers_env(headers_str: &str) -> HashMap<String, String> {
    headers_str
        .split(',')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.trim().to_string();
            let value = parts.next()?.trim().to_string();
            Some((key, value))
        })
        .collect()
}

// Convert HashMap<String, String> into tonic::MetadataMap
// - Supports ASCII metadata (normal keys)
// - Supports binary metadata keys (ending with "-bin"), values must be base64-encoded
#[cfg(feature = "telemetry")]
fn headers_to_metadata(headers: &HashMap<String, String>) -> Result<MetadataMap> {
    let mut meta = MetadataMap::with_capacity(headers.len());

    for (k, v) in headers {
        let key_str = k.to_ascii_lowercase();

        if key_str.ends_with("-bin") {
            let bytes = general_purpose::STANDARD
                .decode(v.as_bytes())
                .map_err(|e| anyhow!("failed to base64-decode value for key {key_str}: {e}"))?;

            let key = MetadataKey::<Binary>::from_bytes(key_str.as_bytes())
                .map_err(|e| anyhow!("invalid binary metadata key {key_str}: {e}"))?;

            let val = MetadataValue::from_bytes(&bytes);
            meta.insert_bin(key, val);
        } else {
            let key = MetadataKey::<Ascii>::from_bytes(key_str.as_bytes())
                .map_err(|e| anyhow!("invalid ASCII metadata key {key_str}: {e}"))?;

            let val: MetadataValue<_> = v
                .parse()
                .map_err(|e| anyhow!("invalid ASCII metadata value for key {key_str}: {e}"))?;
            meta.insert(key, val);
        }
    }

    Ok(meta)
}

#[cfg(feature = "telemetry")]
fn normalize_endpoint(ep: String) -> String {
    if ep.starts_with("http://") || ep.starts_with("https://") {
        ep
    } else {
        // Default to https for gRPC if no scheme supplied
        format!("https://{}", ep.trim_end_matches('/'))
    }
}

#[cfg(feature = "telemetry")]
fn init_tracer() -> Result<Tracer> {
    // We only support gRPC now. If the user set a different protocol, log and ignore.
    if let Ok(proto) = var("OTEL_EXPORTER_OTLP_PROTOCOL")
        && proto != "grpc"
    {
        debug!(
            "OTEL_EXPORTER_OTLP_PROTOCOL='{}' ignored: only 'grpc' is supported now",
            proto
        );
    }

    // gRPC sensible default
    let default_ep = "http://localhost:4317";
    let endpoint = var(ENV_OTLP_ENDPOINT).unwrap_or_else(|_| default_ep.to_string());
    let endpoint = normalize_endpoint(endpoint);

    let headers = var("OTEL_EXPORTER_OTLP_HEADERS")
        .ok()
        .map(|s| parse_headers_env(&s))
        .unwrap_or_default();

    // Build gRPC exporter
    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .with_compression(Compression::Gzip)
        .with_timeout(Duration::from_secs(3));

    // TLS (https) support
    if let Some(host) = endpoint
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())
        .and_then(|h| h.split(':').next())
    {
        let tls = ClientTlsConfig::new()
            .domain_name(host.to_string())
            .with_native_roots();
        builder = builder.with_tls_config(tls);
    }

    if !headers.is_empty() {
        let metadata = headers_to_metadata(&headers)?;
        builder = builder.with_metadata(metadata);
    }

    let exporter = builder.build()?;

    // Generate or take service.instance.id
    let instance_id =
        var("OTEL_SERVICE_INSTANCE_ID").unwrap_or_else(|_| Ulid::generate().to_string());

    let trace_provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder_empty()
                .with_attributes(vec![
                    KeyValue::new("service.name", env!("CARGO_PKG_NAME")),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    KeyValue::new("service.instance.id", instance_id),
                ])
                .build(),
        )
        .build();

    // Store provider for later shutdown
    let _ = TRACER_PROVIDER.set(trace_provider.clone());

    // Register globally
    global::set_tracer_provider(trace_provider.clone());
    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));

    Ok(trace_provider.tracer(env!("CARGO_PKG_NAME")))
}

/// Initialize local logging and, when compiled in and configured, OTLP trace export.
///
/// Export requires both the `telemetry` Cargo feature and `OTEL_EXPORTER_OTLP_ENDPOINT`
/// at startup (gRPC only). Without the feature the endpoint is ignored with a warning.
///
/// # Errors
///
/// Returns an error if tracer or subscriber initialization fails
pub fn init(verbosity_level: Option<Level>) -> Result<()> {
    let verbosity_level = verbosity_level.unwrap_or(Level::ERROR);

    let fmt_layer = fmt::layer()
        .with_file(false)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_target(false)
        .pretty();

    let filter = EnvFilter::builder()
        .with_default_directive(verbosity_level.into())
        .from_env_lossy()
        .add_directive("hyper=error".parse()?)
        .add_directive("tokio=error".parse()?);

    #[cfg(feature = "telemetry")]
    {
        let filter = filter.add_directive("opentelemetry_sdk=warn".parse()?);

        if var(ENV_OTLP_ENDPOINT).is_ok() {
            let tracer = init_tracer()?;
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

            let subscriber = Registry::default()
                .with(fmt_layer)
                .with(otel_layer)
                .with(filter);
            tracing::subscriber::set_global_default(subscriber)?;
        } else {
            let subscriber = Registry::default().with(fmt_layer).with(filter);
            tracing::subscriber::set_global_default(subscriber)?;
        }
    }

    #[cfg(not(feature = "telemetry"))]
    {
        let subscriber = Registry::default().with(fmt_layer).with(filter);
        tracing::subscriber::set_global_default(subscriber)?;

        if var(ENV_OTLP_ENDPOINT).is_ok() {
            tracing::warn!(
                "{ENV_OTLP_ENDPOINT} is set but this binary was built without the `telemetry` feature; traces are not exported"
            );
        }
    }

    Ok(())
}

/// Flush batched spans and shut down the tracer provider.
///
/// Blocks until the exporter drains or times out, so async callers should run it on a
/// blocking thread. Returns `true` when a provider had been initialized.
#[cfg(feature = "telemetry")]
#[must_use]
pub fn shutdown_tracer() -> bool {
    let Some(tp) = TRACER_PROVIDER.get() else {
        return false;
    };

    debug!("shutting down tracer provider");
    if let Err(err) = tp.shutdown() {
        warn!(error = %err, "tracer provider shutdown failed");
    }
    debug!("tracer provider shutdown complete");
    true
}

/// Built without the `telemetry` feature: there is never a provider to flush.
#[cfg(not(feature = "telemetry"))]
#[must_use]
pub const fn shutdown_tracer() -> bool {
    false
}

#[cfg(test)]
mod shutdown_tests {
    use super::shutdown_tracer;

    #[test]
    fn shutdown_tracer_without_provider_returns_false() {
        assert!(!shutdown_tracer());
    }
}

#[cfg(all(test, feature = "telemetry"))]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_parse_headers_env_empty() {
        let result = parse_headers_env("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_headers_env_single() {
        let result = parse_headers_env("key1=value1");
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("key1"), Some(&"value1".to_string()));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_parse_headers_env_multiple() {
        let result = parse_headers_env("key1=value1,key2=value2,key3=value3");
        assert_eq!(result.len(), 3);
        assert_eq!(result.get("key1"), Some(&"value1".to_string()));
        assert_eq!(result.get("key2"), Some(&"value2".to_string()));
        assert_eq!(result.get("key3"), Some(&"value3".to_string()));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_parse_headers_env_with_spaces() {
        let result = parse_headers_env("key1 = value1 , key2 = value2");
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("key1"), Some(&"value1".to_string()));
        assert_eq!(result.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_parse_headers_env_malformed() {
        // Missing values should be filtered out
        let result = parse_headers_env("key1=value1,malformed,key2=value2");
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("key1"), Some(&"value1".to_string()));
        assert_eq!(result.get("key2"), Some(&"value2".to_string()));
        assert!(!result.contains_key("malformed"));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_headers_to_metadata_empty() {
        let headers = HashMap::new();
        let result = headers_to_metadata(&headers);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_headers_to_metadata_ascii() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("x-custom-header".to_string(), "custom-value".to_string());

        let result = headers_to_metadata(&headers);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 2);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_headers_to_metadata_binary() {
        let mut headers = HashMap::new();
        // Base64 encoded "binary data"
        headers.insert("custom-bin".to_string(), "YmluYXJ5IGRhdGE=".to_string());

        let result = headers_to_metadata(&headers);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_headers_to_metadata_invalid_base64() {
        let mut headers = HashMap::new();
        headers.insert("custom-bin".to_string(), "not-valid-base64!!!".to_string());

        let result = headers_to_metadata(&headers);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed to base64-decode")
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_headers_to_metadata_mixed() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("custom-bin".to_string(), "YmluYXJ5IGRhdGE=".to_string());

        let result = headers_to_metadata(&headers);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 2);
    }

    #[test]
    fn test_normalize_endpoint_http() {
        let result = normalize_endpoint("http://localhost:4317".to_string());
        assert_eq!(result, "http://localhost:4317");
    }

    #[test]
    fn test_normalize_endpoint_https() {
        let result = normalize_endpoint("https://api.example.com:4317".to_string());
        assert_eq!(result, "https://api.example.com:4317");
    }

    #[test]
    fn test_normalize_endpoint_no_scheme() {
        let result = normalize_endpoint("localhost:4317".to_string());
        assert_eq!(result, "https://localhost:4317");
    }

    #[test]
    fn test_normalize_endpoint_trailing_slash() {
        let result = normalize_endpoint("api.example.com:4317/".to_string());
        assert_eq!(result, "https://api.example.com:4317");
    }

    #[test]
    fn test_normalize_endpoint_with_path() {
        let result = normalize_endpoint("https://api.example.com:4317/v1/traces".to_string());
        assert_eq!(result, "https://api.example.com:4317/v1/traces");
    }
}
