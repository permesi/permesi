FROM messense/rust-musl-cross:x86_64-musl AS builder

RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release --locked -p genesis --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/genesis

# Runtime image
FROM alpine:latest

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

# Create a non-root user
RUN adduser -D app

WORKDIR /app

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/genesis /app/

# Set the user to the non-root user
USER app

CMD ["./genesis"]
