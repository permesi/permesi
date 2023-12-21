use crate::cli::{actions::Action, commands, dispatch::handler};
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime::Tokio, trace, Resource};
use std::time::Duration;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

/// Start the CLI
pub fn start() -> Result<Action> {
    let matches = commands::new().get_matches();

    let verbosity_level = match matches.get_one::<u8>("verbosity").map_or(0, |&v| v) {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        3 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    let otlp_exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_timeout(Duration::from_secs(3));

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(otlp_exporter)
        .with_trace_config(trace::config().with_resource(Resource::new(vec![
            KeyValue::new("service.name", env!("CARGO_PKG_NAME")),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ])))
        .install_batch(Tokio)?;

    let telemetry = OpenTelemetryLayer::new(tracer);

    let fmt_layer = fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false);

    // RUST_LOG=
    let env_filter = EnvFilter::builder()
        .with_default_directive(verbosity_level.into())
        .from_env_lossy();

    let subscriber = Registry::default()
        .with(fmt_layer)
        .with(telemetry)
        .with(env_filter);

    tracing::subscriber::set_global_default(subscriber)?;

    let action = handler(&matches)?;

    Ok(action)
}
