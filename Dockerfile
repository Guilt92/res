# syntax=docker/dockerfile:1
# res multi-stage build: compile a static release binary, ship a slim image.
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
RUN touch src/main.rs src/lib.rs src/bin/*.rs && cargo build --release

FROM debian:trixie-slim
# /app must stay traversable by the runtime UID: the dashboard path is relative
# to WORKDIR and compose may run the process as another UID. /etc/res stays
# private and writable only by the image user (the bind mount overrides it).
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 res && \
    useradd --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin res && \
    install -d -o res -g res -m 0750 /etc/res && \
    install -d -o res -g res -m 0755 /app

COPY --from=builder --chown=res:res /build/target/release/res /usr/local/bin/res
COPY --from=builder --chown=res:res /build/target/release/res-loadtest /usr/local/bin/res-loadtest
COPY --chown=res:res config/res.toml /etc/res/res.toml
COPY --chown=res:res dashboard /app/dashboard
RUN chmod -R a+rX /app/dashboard
COPY --chmod=0755 --chown=res:res docker/entrypoint.sh /usr/local/bin/res-entrypoint

WORKDIR /app
# Run unprivileged. Docker's default `net.ipv4.ip_unprivileged_port_start=0`
# lets UID 10001 bind :53; runtimes that raise it need
# `--sysctl net.ipv4.ip_unprivileged_port_start=53`. The config directory must
# stay writable by this UID for atomic config writes, backups and
# res.credentials (bind mounts must be owned accordingly).
USER 10001:10001
EXPOSE 53/udp 53/tcp 8080/tcp

# Liveness: the gateway answers a probe query (even SERVFAIL proves the data
# plane is up). Use --require-ok to additionally demand a usable rcode.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["res", "--config", "/etc/res/res.toml", "probe", \
       "--server", "127.0.0.1:53", "--timeout-ms", "2000"]

# Fail-closed bootstrap: require explicit password env or a persisted
# credentials file. Compose supplies the env; no password is generated or
# written to logs.
ENTRYPOINT ["/usr/local/bin/res-entrypoint"]
CMD ["--config", "/etc/res/res.toml", "serve"]
