# Multi-stage Dockerfile for MarchProxy ALB
# Combines Envoy proxy with Go supervisor for ModuleService gRPC interface

# Stage 1: Build Go supervisor
FROM golang:1.24-trixie AS go-builder

WORKDIR /build

# Copy go module files
COPY proxy-alb/go.mod proxy-alb/go.sum ./

# Download dependencies
RUN go mod download

# Copy proto and source code
COPY proto/ ./proto/
COPY proxy-alb/ ./

# Build the supervisor binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-v1.0.0} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.gitCommit=${GIT_COMMIT:-unknown}" \
    -o alb-supervisor \
    main.go

# Stage 2: Generate protobuf code
FROM golang:1.24-trixie AS proto-builder

WORKDIR /build

# Install protoc and plugins
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Copy proto files
COPY proto/ /build/proto/

# Generate Go code from proto
RUN cd proto/marchproxy && \
    protoc --go_out=. --go_opt=paths=source_relative \
           --go-grpc_out=. --go-grpc_opt=paths=source_relative \
           module_service.proto

# Stage 3: Production image with Envoy
FROM envoyproxy/envoy:v1.28-latest

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    iptables \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r envoy && useradd -r -g envoy envoy

# Create directories
RUN mkdir -p /etc/envoy /var/log/envoy /var/lib/envoy && \
    chown -R envoy:envoy /etc/envoy /var/log/envoy /var/lib/envoy

# Copy Envoy configuration
COPY proxy-alb/envoy/envoy.yaml /etc/envoy/envoy.yaml

# Copy Go supervisor from builder
COPY --from=go-builder /build/alb-supervisor /usr/local/bin/alb-supervisor
RUN chmod +x /usr/local/bin/alb-supervisor

# Copy generated proto code
COPY --from=proto-builder /build/proto/ /usr/local/lib/proto/

# Set environment variables
ENV ENVOY_BINARY=/usr/local/bin/envoy \
    ENVOY_CONFIG_PATH=/etc/envoy/envoy.yaml \
    ENVOY_ADMIN_PORT=9901 \
    ENVOY_LISTEN_PORT=10000 \
    ENVOY_LOG_LEVEL=info \
    GRPC_PORT=50051 \
    METRICS_PORT=9090 \
    HEALTH_PORT=8080 \
    LOG_LEVEL=info

# Expose ports
# 10000 - HTTP/HTTPS traffic
# 9901  - Envoy admin
# 50051 - gRPC ModuleService
# 9090  - Prometheus metrics
# 8080  - Health checks
EXPOSE 10000 9901 50051 9090 8080

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Set user
USER envoy

# Run supervisor (which manages Envoy)
ENTRYPOINT ["/usr/local/bin/alb-supervisor"]
