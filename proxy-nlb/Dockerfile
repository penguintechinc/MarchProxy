# Multi-stage Dockerfile for MarchProxy NLB (Network Load Balancer)
# Supports: production, development, testing, debug targets

# Build stage
FROM golang:1.24-trixie AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the NLB (supports both cmd/main.go and cmd/nlb/main.go)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o proxy-nlb ./cmd/main.go

# Production stage
FROM debian:12-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/proxy-nlb .

# Create directories for logs
RUN mkdir -p /var/log/marchproxy/nlb \
    && chmod 755 /var/log/marchproxy/nlb

# Expose ports
# 8080 - Main traffic port
# 8082 - Metrics/health port
# 50051 - gRPC server port
EXPOSE 8080 8082 50051

# Health check using Go binary (no curl dependency)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["./proxy-nlb", "--healthcheck"]

# Run as non-root user
RUN useradd -r -u 1000 marchproxy
USER marchproxy

ENTRYPOINT ["./proxy-nlb"]

# Development stage
FROM builder AS development

WORKDIR /app

# Install development tools
RUN go install github.com/cosmtrek/air@latest \
    && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Copy source
COPY . .

EXPOSE 8080 8082 50051

CMD ["air", "-c", ".air.toml"]

# Testing stage
FROM builder AS testing

WORKDIR /app

# Copy source and tests
COPY . .

# Install test dependencies
RUN go install gotest.tools/gotestsum@latest

# Run tests with coverage
RUN go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

CMD ["gotestsum", "--junitfile", "test-results.xml", "--", "-v", "-race", "./..."]

# Debug stage
FROM production AS debug

# Install debugging tools
USER root
RUN apt-get update && apt-get install -y \
    gdb \
    strace \
    tcpdump \
    net-tools \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Build with debug symbols
COPY --from=builder /build/proxy-nlb .

USER marchproxy

ENTRYPOINT ["./proxy-nlb"]
