run:
  podman run --rm --name postgres \
  -e POSTGRES_USER=permesi \
  -e POSTGRES_PASSWORD=permesi \
  -p 5432:5432 \
  -v $PWD/.postgres-volume:/var/lib/postgresql/data \
  postgres:latest &

postgres_stop:
    podman stop postrgres

clippy:
    cargo clippy --all -- -W clippy::all -W clippy::nursery -D warnings

jaeger:
  podman run --rm --name jaeger \
  -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
  -p 6831:6831/udp \
  -p 6832:6832/udp \
  -p 5778:5778 \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  -p 14250:14250 \
  -p 14268:14268 \
  -p 14269:14269 \
  -p 9411:9411 \
  jaegertracing/all-in-one:latest &

jaeger_stop:
    podman stop jaeger

otel:
    podman run --rm --name otel-collector \
    -p 4317:4317 \
    -p 4318:4318 \
    -p 8888:8888 \
    -v $PWD/.otel-collector-config.yml:/etc/otelcol-contrib/config.yaml \
    otel/opentelemetry-collector-contrib:latest &
