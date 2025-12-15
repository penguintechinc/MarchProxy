# MarchProxy ALB (Application Load Balancer) - Envoy L7 Proxy
# Combines Envoy proxy with Go filters (TinyGo Wasm) for authentication, licensing, and metrics

# Stage 1: Build Go filters using TinyGo for WebAssembly (optional)
FROM golang:1.24-bookworm AS filter-builder

WORKDIR /build

# Install TinyGo for WebAssembly compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* && \
    curl -L https://github.com/tinygo-org/tinygo/releases/download/v0.32.0/tinygo_0.32.0_amd64.deb -o tinygo.deb && \
    apt-get install -y ./tinygo.deb && \
    rm tinygo.deb

# Build Go Wasm filters (dummy - will be replaced with actual filters)
RUN mkdir -p /build/filters && echo "# Filter placeholder" > /build/filters/placeholder.txt

# Stage 2: Production Envoy image
FROM envoyproxy/envoy:v1.28-latest

LABEL maintainer="MarchProxy Contributors"
LABEL description="MarchProxy ALB - Application Load Balancer with Envoy L7"

# Install additional runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create directories for configuration and filters
RUN mkdir -p /etc/envoy /var/log/envoy /var/lib/envoy /opt/filters \
    && chown -R nobody:nogroup /etc/envoy /var/log/envoy /var/lib/envoy /opt/filters

# Copy Envoy configuration
COPY envoy/ /etc/envoy/

# Copy filter builder artifacts (when available)
COPY --from=filter-builder /build/filters/ /opt/filters/

# Set environment variables
ENV ENVOY_CONFIG_PATH=/etc/envoy/envoy.yaml \
    ENVOY_ADMIN_ADDRESS=0.0.0.0 \
    ENVOY_ADMIN_PORT=9901 \
    ENVOY_LOG_LEVEL=info \
    FILTER_PATH=/opt/filters

# Expose ports
# 10000 - HTTP/HTTPS traffic (main)
# 9901  - Admin interface
# 50052 - gRPC ModuleService (if supervisor running)
EXPOSE 10000 9901 50052

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9901/ready || exit 1

# Set user
USER nobody

# Run Envoy
ENTRYPOINT ["envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml", "-l", "info"]
