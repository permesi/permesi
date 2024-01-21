# Build stage for x86_64
FROM messense/rust-musl-cross:x86_64-musl as builder-x86_64

RUN apt-get update && \
    apt-get install -y git libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release --locked --features "openssl/vendored"

# Build stage for arm64
FROM messense/rust-musl-cross:aarch64-musl as builder-arm64

RUN apt-get update && \
    apt-get install -y git libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release --locked --features "openssl/vendored"

# Runtime image
FROM alpine:latest

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

# Create a non-root user
RUN adduser -D app

WORKDIR /app

# Use a variable for the binary name to handle different file extensions
ARG BINARY_NAME=permesi

# Copy the compiled binary from the appropriate builder stage
COPY --from=builder-x86_64 /app/target/x86_64-unknown-linux-musl/release/$BINARY_NAME /app/
COPY --from=builder-arm64 /app/target/aarch64-unknown-linux-musl/release/$BINARY_NAME /app/

# Set the user to the non-root user
USER app

CMD ["./permesi"]
