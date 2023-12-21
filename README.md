# permesi

**permesi** Identity and Access Management

[![crates.io](https://img.shields.io/crates/v/permesi.svg)](https://crates.io/crates/permesi)
[![Test & Build](https://github.com/permesi/permesi/actions/workflows/build.yml/badge.svg)](https://github.com/permesi/permesi/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/permesi/permesi/graph/badge.svg?token=ODC4S2YHPF)](https://codecov.io/gh/permesi/permesi)

TODO

Example for opentelemetry-collector:

```yaml
---
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:

exporters:
  otlp/honeycomb:
    endpoint: api.honeycomb.io:443
    headers:
      x-honeycomb-team: XXX
  otlp/aspecto:
    endpoint: otelcol.aspecto.io:4317
    headers:
      Authorization: XXX

service:
  pipelines:
    traces:
      receivers:
        - otlp
      processors:
        - batch
      exporters:
        - otlp/honeycomb
        - otlp/aspecto
```


Set the `OTEL_EXPORTER_OTLP_ENDPOINT` variable:

    export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
