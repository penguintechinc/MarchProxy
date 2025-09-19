# MarchProxy Docker Multi-Stage Build
# Build stage for Go applications
FROM golang:1.21-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go modules
COPY proxy/go.mod proxy/go.sum ./
RUN go mod download

# Copy source code
COPY proxy/ ./

# Build the proxy application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -o marchproxy-proxy ./cmd/proxy

# Build additional tools
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -o marchproxy-health ./cmd/health

RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -o marchproxy-metrics ./cmd/metrics

# Python build stage for manager
FROM python:3.11-slim AS python-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements
COPY manager/requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy manager application
COPY manager/ ./

# Production stage - Manager
FROM python:3.11-slim AS manager

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r marchproxy && useradd -r -g marchproxy marchproxy

# Set working directory
WORKDIR /app

# Copy Python dependencies
COPY --from=python-builder /root/.local /home/marchproxy/.local

# Copy application
COPY --from=python-builder /build ./

# Set ownership
RUN chown -R marchproxy:marchproxy /app

# Switch to app user
USER marchproxy

# Set PATH for local packages
ENV PATH=/home/marchproxy/.local/bin:$PATH

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run with dumb-init
ENTRYPOINT ["dumb-init", "--"]
CMD ["python", "-m", "py4web", "run", "apps", "--host", "0.0.0.0", "--port", "8000"]

# Production stage - Proxy
FROM alpine:3.18 AS proxy

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl \
    dumb-init

# Create app user
RUN addgroup -g 1000 marchproxy && \
    adduser -D -s /bin/sh -u 1000 -G marchproxy marchproxy

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=go-builder /build/marchproxy-proxy ./
COPY --from=go-builder /build/marchproxy-health ./
COPY --from=go-builder /build/marchproxy-metrics ./

# Copy configuration files
COPY proxy/configs/ ./configs/

# Set ownership
RUN chown -R marchproxy:marchproxy /app

# Switch to app user
USER marchproxy

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ./marchproxy-health || exit 1

# Expose ports
EXPOSE 80 443 8080 8090

# Run with dumb-init
ENTRYPOINT ["dumb-init", "--"]
CMD ["./marchproxy-proxy"]

# Development stage
FROM golang:1.21-alpine AS development

# Install development tools
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    gcc \
    musl-dev \
    curl \
    make \
    bash \
    vim \
    tmux

# Install Go tools
RUN go install github.com/cosmtrek/air@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install github.com/swaggo/swag/cmd/swag@latest

# Set working directory
WORKDIR /workspace

# Copy go modules for caching
COPY proxy/go.mod proxy/go.sum ./
RUN go mod download

# Create non-root user
RUN addgroup -g 1000 developer && \
    adduser -D -s /bin/sh -u 1000 -G developer developer

# Set ownership
RUN chown -R developer:developer /workspace

# Switch to developer user
USER developer

# Expose development ports
EXPOSE 80 443 8080 8090 9090

CMD ["air", "-c", ".air.toml"]

# Testing stage
FROM golang:1.21-alpine AS testing

# Install test dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev \
    make

# Set working directory
WORKDIR /test

# Copy source code
COPY proxy/ ./

# Download dependencies
RUN go mod download

# Run tests with coverage
RUN go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Generate test reports
RUN go tool cover -html=coverage.out -o coverage.html

# Benchmark stage
FROM golang:1.21-alpine AS benchmark

# Install benchmark dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev

# Set working directory
WORKDIR /bench

# Copy source code
COPY proxy/ ./

# Download dependencies
RUN go mod download

# Run benchmarks
RUN go test -bench=. -benchmem ./... > benchmark.txt

# Security scanning stage
FROM alpine:3.18 AS security

# Install security tools
RUN apk add --no-cache \
    curl \
    jq

# Install Trivy for vulnerability scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Copy binaries to scan
COPY --from=go-builder /build/marchproxy-proxy ./

# Run security scan
RUN trivy filesystem --exit-code 0 --severity HIGH,CRITICAL --format json --output trivy-report.json .

# Multi-architecture build stage
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS cross-builder

ARG TARGETOS
ARG TARGETARCH

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go modules
COPY proxy/go.mod proxy/go.sum ./
RUN go mod download

# Copy source code
COPY proxy/ ./

# Build for target platform
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -a -installsuffix cgo \
    -ldflags='-w -s' \
    -o marchproxy-proxy ./cmd/proxy

# Distroless production stage
FROM gcr.io/distroless/static:nonroot AS distroless

# Copy binary
COPY --from=cross-builder /build/marchproxy-proxy /app/

# Copy timezone data
COPY --from=cross-builder /usr/share/zoneinfo /usr/share/zoneinfo

# Health check (limited in distroless)
# HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#     CMD ["/app/marchproxy-proxy", "health"] || exit 1

# Expose ports
EXPOSE 80 443

# Use non-root user
USER 65532:65532

# Run application
ENTRYPOINT ["/app/marchproxy-proxy"]

# Debug stage with shell access
FROM alpine:3.18 AS debug

# Install debugging tools
RUN apk add --no-cache \
    bash \
    curl \
    htop \
    strace \
    tcpdump \
    netcat-openbsd \
    bind-tools \
    ca-certificates

# Copy binary
COPY --from=go-builder /build/marchproxy-proxy ./
COPY --from=go-builder /build/marchproxy-health ./
COPY --from=go-builder /build/marchproxy-metrics ./

# Make executable
RUN chmod +x marchproxy-*

# Expose ports
EXPOSE 80 443 8080 8090

CMD ["./marchproxy-proxy"]

# Default production target
FROM proxy AS production