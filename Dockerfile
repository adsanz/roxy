# ============================================================================
# Stage 1: Build
# ============================================================================
FROM rust:1.94-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    clang \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies by building them first (this saves us a complete rebuild if no deps change)
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src benches/common && \
    echo "fn main() {}" > src/main.rs && \
    echo "// dummy lib" > src/lib.rs && \
    echo "// dummy bench file" > benches/rules.rs && \
    echo "// dummy bench file" > benches/request.rs && \
    echo "// dummy common" > benches/common/mod.rs && \
    cargo build --release && \
    rm -rf src

# Build the actual application
COPY src ./src
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --locked && \
    strip target/release/roxy

# ============================================================================
# Stage 2: Runtime (distroless for minimal attack surface)
# ============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Copy the binary
COPY --from=builder --chown=nonroot:nonroot /build/target/release/roxy /usr/local/bin/roxy

# Default config location
WORKDIR /etc/roxy

# Expose default proxy port
EXPOSE 8080

# Run as non-root user (uid 65532 in distroless)
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/roxy"]
CMD ["--config", "/etc/roxy/config.yaml"]
