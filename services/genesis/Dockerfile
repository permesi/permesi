# Stage 1: build a static binary with musl.
FROM messense/rust-musl-cross:x86_64-musl AS builder

# Keep the builder minimal; we only need git for Cargo deps.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release --locked -p genesis --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/genesis

# Stage 2: grab CA certs from Alpine (for TLS).
FROM alpine:latest AS certs
RUN apk add --no-cache ca-certificates

# Stage 3: ultra-small runtime (scratch + binary + certs).
FROM scratch
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/genesis /app/
USER 65532:65532

CMD ["./genesis"]
