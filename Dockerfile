# Use the official Rust image to compile the application
FROM rust:latest as builder

WORKDIR /usr/src/iam-platform
COPY . .

# Force SQLx to skip checking a live database during the build stage
ENV SQLX_OFFLINE=true

# Build the application in release mode for production efficiency
RUN cargo build --release

# Use a clean, minimal image to run the compiled binary
FROM debian:bookworm-slim

# Bypassing apt-get downloads by using a pre-configured slim rust image as the runner
FROM rust:1.78-slim

WORKDIR /app
COPY --from=builder /usr/src/iam-platform/target/release/iam-platform /app/iam-platform
COPY ./migrations /app/migrations

EXPOSE 3000

CMD ["./iam-platform"]