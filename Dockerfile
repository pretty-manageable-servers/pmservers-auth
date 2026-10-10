FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --release
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/pmservers-auth /usr/local/bin/pmservers-auth
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pmservers-auth"]
