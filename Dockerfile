# syntax=docker/dockerfile:1
# OutisDNS multi-stage build: compile a static release binary, ship a slim image.
# There is no database: configuration is a single TOML file (atomic writes).

# Proxy settings for the build only (declared so BuildKit forwards them to
# cargo; they are intentionally not persisted into the final image).
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY

FROM rust:1.97-bookworm AS builder
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY
WORKDIR /build

# Dependency layer: cache the registry build separately from sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'pub fn placeholder() {}' > src/lib.rs && \
    echo 'fn main() {}' > src/bin/loadtest.rs && \
    echo 'fn main() {}' > src/bin/hotpath-bench.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
COPY config ./config
RUN touch src/main.rs src/lib.rs src/bin/*.rs && cargo build --release

FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/outisdns /usr/local/bin/outisdns
COPY --from=builder /build/target/release/outisdns-loadtest /usr/local/bin/outisdns-loadtest
COPY config/outisdns.toml /etc/outisdns/outisdns.toml
COPY dashboard /app/dashboard

WORKDIR /app
# Runs as root: binding :53 needs CAP_NET_BIND_SERVICE (or root), and the
# config directory must stay writable for the atomic config writes + backup.
EXPOSE 53/udp 53/tcp 8080/tcp

# Liveness: the gateway answers a probe query (even SERVFAIL proves the data
# plane is up). Use --require-ok to additionally demand a usable rcode.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["outisdns", "--config", "/etc/outisdns/outisdns.toml", "probe", \
       "--server", "127.0.0.1:53", "--timeout-ms", "2000"]

ENTRYPOINT ["outisdns"]
CMD ["--config", "/etc/outisdns/outisdns.toml", "serve"]
