# Build from the repository root: docker build -f server/Dockerfile .
FROM rust:1.96-trixie AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY lib ./lib
COPY core ./core
COPY client ./client
COPY mobile ./mobile
COPY server ./server
RUN cargo build --locked --release -p hibiki-server

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hibiki \
    && useradd --uid 10001 --gid hibiki --home-dir /var/lib/hibiki --no-create-home hibiki \
    && install -d -o hibiki -g hibiki -m 0700 /var/lib/hibiki
COPY --from=builder /src/target/release/hibiki-server /usr/local/bin/hibiki-server
COPY server/container.toml /etc/hibiki/server.toml
ENV HOME=/var/lib/hibiki RUST_LOG=info HIBIKI_SERVER_CONFIG=/etc/hibiki/server.toml
USER 10001:10001
VOLUME ["/var/lib/hibiki"]
EXPOSE 7749
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent "${HIBIKI_SERVER_HEALTHCHECK_URL:-http://127.0.0.1:7749/healthz}" || exit 1
ENTRYPOINT ["/usr/local/bin/hibiki-server"]
