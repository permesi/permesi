# Stage 1: build a static binary with musl.
FROM messense/rust-musl-cross:x86_64-musl AS builder
ARG TARGET=x86_64-unknown-linux-musl

# Keep the builder minimal; we only need git for Cargo deps.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release --locked -p genesis --target "${TARGET}" && \
    strip "target/${TARGET}/release/genesis"

# Stage 2: grab CA certs from Alpine (for TLS).
FROM alpine:3.21 AS certs
RUN apk add --no-cache ca-certificates

# Stage 3: ultra-small runtime (scratch + binary + certs).
FROM scratch
ARG TARGET=x86_64-unknown-linux-musl
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/${TARGET}/release/genesis /app/genesis
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/app/genesis"]
