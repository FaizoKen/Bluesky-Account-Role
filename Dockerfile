# NOTE: pin both base images to digests (`@sha256:…`) before production
# deployment so supply-chain compromise on the upstream tag can't poison a
# rebuild. Tracked separately as a deploy-time concern.

FROM rust:1.88-bookworm AS builder
WORKDIR /app

# Cache dependencies in a separate layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/bluesky-account-role target/release/deps/bluesky_account_role*

# Build actual source. Release profile already sets `strip = true` in
# Cargo.toml, so no explicit `strip` invocation is needed here.
COPY src/ src/
COPY migrations/ migrations/
COPY templates/ templates/
COPY favicon.ico ./
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app

COPY --from=builder /app/target/release/bluesky-account-role /usr/local/bin/

EXPOSE 8095

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --max-time 2 \
        http://127.0.0.1:8095/bluesky-account-role/health || exit 1

USER app:app

CMD ["bluesky-account-role"]
