# The service binary is compiled once by CI (or `just image`) with the run's Rust
# toolchain and copied in here, so the image holds exactly the bytes the release
# publishes and no base image decides the compiler version. The build context must
# contain dist-bin/permesi, a static x86_64-unknown-linux-musl release binary.

# Stage 1: grab CA certs from Alpine (for TLS).
FROM docker.io/library/alpine:3.21 AS certs
RUN apk add --no-cache ca-certificates

# Stage 2: ultra-small runtime (scratch + prebuilt binary + certs).
FROM scratch
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Artifact downloads drop file modes, so set the executable bit explicitly.
COPY --chmod=0555 dist-bin/permesi /app/permesi
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/app/permesi"]
