# Stage 1: Build
FROM rust:latest as builder

WORKDIR /usr/src/iam-platform
COPY . .

ENV SQLX_OFFLINE=true

RUN cargo build --release

# Stage 2: Run
FROM rust:1.78-slim

WORKDIR /app
COPY --from=builder /usr/src/iam-platform/target/release/iam-platform /app/iam-platform
COPY ./migrations /app/migrations

EXPOSE 3000

CMD ["./iam-platform"]