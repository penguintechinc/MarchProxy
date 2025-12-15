# Multi-stage build for MarchProxy DBLB
FROM golang:1.24-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-1.0.0} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=${GIT_COMMIT:-unknown}" \
    -o proxy-dblb \
    ./cmd/main.go

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 dblb && \
    useradd -u 1000 -g dblb -m -s /sbin/nologin dblb

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/proxy-dblb /app/proxy-dblb

# Configuration is mounted at runtime, no default config needed

# Set ownership
RUN chown -R dblb:dblb /app

# Switch to non-root user
USER dblb

# Expose ports
# MySQL
EXPOSE 3306
# PostgreSQL
EXPOSE 5432
# MongoDB
EXPOSE 27017
# Redis
EXPOSE 6379
# MSSQL
EXPOSE 1433
# Admin/Metrics
EXPOSE 7002
# gRPC
EXPOSE 50052

# Health check using Go binary (no wget dependency)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/proxy-dblb", "--healthcheck"]

# Set entrypoint
ENTRYPOINT ["/app/proxy-dblb"]

# Default command (can be overridden)
CMD ["--config", "/app/config.yaml"]
