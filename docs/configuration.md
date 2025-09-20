# Configuration Reference

This document provides a comprehensive reference for configuring MarchProxy components.

## Configuration Hierarchy

MarchProxy uses a three-tier configuration system:

1. **Control Panel Settings** (Database) - Highest priority
2. **Environment Variables** - Fallback for initial setup
3. **Default Values** - System defaults

## Manager Configuration

### Database Configuration

#### Environment Variables
```bash
# Primary database connection (used if no DB config exists)
DATABASE_URL=postgresql://user:pass@host:port/dbname

# Individual components (fallbacks)
DB_HOST=postgres                    # Database hostname
DB_PORT=5432                       # Database port
DB_NAME=marchproxy                 # Database name
DB_USERNAME=marchproxy             # Database username
DB_PASSWORD=secure_password        # Database password
DB_SSL_MODE=prefer                 # SSL mode: disable, allow, prefer, require
DB_POOL_SIZE=20                    # Connection pool size
DB_MAX_OVERFLOW=10                 # Max overflow connections
```

#### Control Panel Settings
Access via: **Settings → Database Configuration**

- **Host**: Database server hostname or IP
- **Port**: Database server port (default: 5432)
- **Database**: Database name
- **Username**: Database user
- **Password**: Database password (encrypted storage)
- **SSL Mode**: Connection security level
- **Pool Settings**: Connection pooling configuration

### SMTP Configuration

#### Environment Variables
```bash
SMTP_HOST=smtp.company.com         # SMTP server hostname
SMTP_PORT=587                      # SMTP server port (25, 465, 587)
SMTP_USERNAME=user@company.com     # SMTP authentication username
SMTP_PASSWORD=smtp_password        # SMTP authentication password
SMTP_FROM=marchproxy@company.com   # Default sender address
SMTP_USE_TLS=true                  # Enable STARTTLS
SMTP_USE_SSL=false                 # Enable SSL/TLS from start
```

#### Control Panel Settings
Access via: **Settings → Email Configuration**

- **SMTP Server**: Mail server hostname
- **Port**: Mail server port
- **Security**: None, STARTTLS, or SSL/TLS
- **Authentication**: Username and password
- **From Address**: Default sender email
- **Test Configuration**: Send test email

### Syslog Configuration

#### Environment Variables
```bash
SYSLOG_ENABLED=true                # Enable syslog forwarding
SYSLOG_HOST=syslog.company.com     # Syslog server hostname
SYSLOG_PORT=514                    # Syslog server port
SYSLOG_PROTOCOL=udp                # Protocol: udp, tcp, tls
SYSLOG_FACILITY=local0             # Syslog facility
SYSLOG_TAG=marchproxy              # Log tag prefix
```

#### Control Panel Settings
Access via: **Settings → Logging Configuration**

- **Enable Syslog**: Toggle syslog forwarding
- **Server**: Syslog server hostname or IP
- **Port**: Syslog server port
- **Protocol**: UDP, TCP, or TLS
- **Facility**: Syslog facility (local0-local7, etc.)
- **Tag**: Log message tag

### Redis Configuration

#### Environment Variables
```bash
# Primary Redis connection
REDIS_URL=redis://:password@host:port/db

# Individual components (fallbacks)
REDIS_HOST=redis                   # Redis hostname
REDIS_PORT=6379                    # Redis port
REDIS_PASSWORD=redis_password      # Redis password
REDIS_DATABASE=0                   # Redis database number
REDIS_SSL=false                    # Enable SSL/TLS
REDIS_POOL_SIZE=10                 # Connection pool size
```

### License Configuration

#### Environment Variables
```bash
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD  # Enterprise license key
LICENSE_SERVER_URL=https://license.penguintech.io  # License server
LICENSE_CHECK_INTERVAL=24          # Check interval (hours)
LICENSE_OFFLINE_GRACE=7            # Offline grace period (days)
```

#### Control Panel Settings
Access via: **Settings → License Management**

- **License Key**: Enterprise license key (format: PENG-XXXX-XXXX-XXXX-XXXX-ABCD)
- **Server URL**: License validation server
- **Check Interval**: How often to validate license
- **Offline Grace**: Grace period for offline validation

### Application Settings

#### Environment Variables
```bash
# Core application
SECRET_KEY=your-secret-key-change-this  # Session encryption key
DEBUG=false                        # Enable debug mode
LOG_LEVEL=info                     # Logging level: debug, info, warn, error
MARCHPROXY_ENV=production          # Environment: development, staging, production

# Web interface
WEB_PORT=8000                      # Web interface port
WEB_HOST=0.0.0.0                   # Web interface bind address
WEB_WORKERS=4                      # Number of web workers

# API settings
API_RATE_LIMIT=1000                # API requests per minute per IP
API_TIMEOUT=30                     # API request timeout (seconds)
API_MAX_PAYLOAD=10485760           # Max API payload size (bytes)
```

## Proxy Configuration

### Connection Settings

#### Environment Variables
```bash
# Manager connection
MANAGER_URL=http://manager:8000    # Manager API URL
MANAGER_HOST=manager               # Manager hostname
MANAGER_PORT=8000                  # Manager port
CLUSTER_API_KEY=your-api-key       # Cluster authentication key

# Proxy identity
PROXY_ID=proxy-1                   # Unique proxy identifier
CLUSTER_ID=default                 # Cluster assignment
PROXY_HOSTNAME=proxy-1.company.com # Proxy hostname
```

### Network Configuration

#### Environment Variables
```bash
# Listen ports
PROXY_HTTP_PORT=80                 # HTTP proxy port
PROXY_HTTPS_PORT=443               # HTTPS proxy port
ADMIN_PORT=8080                    # Admin/health port
METRICS_PORT=8081                  # Metrics port

# Network interfaces
PROXY_INTERFACE=eth0               # Primary network interface
ADMIN_INTERFACE=lo                 # Admin interface
BIND_ADDRESS=0.0.0.0               # Bind address for all ports

# Buffer sizes
RECV_BUFFER_SIZE=262144            # Receive buffer size
SEND_BUFFER_SIZE=262144            # Send buffer size
MAX_CONNECTIONS=10000              # Maximum concurrent connections
```

### Acceleration Configuration

#### Environment Variables
```bash
# Acceleration technologies
ENABLE_XDP=true                    # Enable XDP acceleration
ENABLE_EBPF=true                   # Enable eBPF filtering
ENABLE_DPDK=false                  # Enable DPDK (Enterprise)
ENABLE_AF_XDP=false                # Enable AF_XDP (Enterprise)
ENABLE_SR_IOV=false                # Enable SR-IOV (Enterprise)

# XDP settings
XDP_MODE=native                    # XDP mode: native, skb, hw
XDP_FLAGS=0                        # XDP flags
XDP_QUEUE_SIZE=1024                # XDP queue size

# eBPF settings
EBPF_LOG_LEVEL=1                   # eBPF log level (0-4)
EBPF_MAPS_SIZE=65536               # eBPF map size
```

### TLS Configuration

#### Environment Variables
```bash
# TLS certificates
TLS_CERT_PATH=/app/certs/server.crt    # TLS certificate path
TLS_KEY_PATH=/app/certs/server.key     # TLS private key path
TLS_CA_PATH=/app/certs/ca.crt          # CA certificate path

# TLS settings
TLS_MIN_VERSION=1.2                # Minimum TLS version
TLS_CIPHER_SUITES=ECDHE-RSA-AES256-GCM-SHA384,...  # Allowed cipher suites
TLS_PREFER_SERVER_CIPHERS=true     # Prefer server cipher order

# Certificate management
CERT_AUTO_RELOAD=true              # Auto-reload certificates
CERT_CHECK_INTERVAL=3600           # Certificate check interval (seconds)
```

### Performance Tuning

#### Environment Variables
```bash
# Worker configuration
WORKER_THREADS=0                   # Worker threads (0 = auto)
IO_THREADS=4                       # I/O threads
MAX_REQUESTS_PER_WORKER=10000      # Max requests per worker

# Memory settings
MAX_MEMORY_MB=1024                 # Maximum memory usage (MB)
GC_TARGET_PERCENT=100              # Go GC target percentage
GOGC=100                           # Go GC percentage

# Connection settings
KEEP_ALIVE_TIMEOUT=75              # Keep-alive timeout (seconds)
READ_TIMEOUT=30                    # Read timeout (seconds)
WRITE_TIMEOUT=30                   # Write timeout (seconds)
IDLE_TIMEOUT=180                   # Idle timeout (seconds)
```

### Monitoring Configuration

#### Environment Variables
```bash
# Metrics
METRICS_ENABLED=true               # Enable metrics collection
METRICS_ENDPOINT=/metrics          # Metrics endpoint path
METRICS_INTERVAL=15                # Metrics collection interval (seconds)

# Health checks
HEALTH_ENABLED=true                # Enable health checks
HEALTH_ENDPOINT=/healthz           # Health check endpoint
HEALTH_TIMEOUT=10                  # Health check timeout (seconds)

# Tracing
TRACING_ENABLED=true               # Enable distributed tracing
JAEGER_ENDPOINT=http://jaeger:14268/api/traces  # Jaeger endpoint
TRACE_SAMPLE_RATE=0.1              # Trace sampling rate (0.0-1.0)

# Logging
LOG_LEVEL=info                     # Log level: debug, info, warn, error
LOG_FORMAT=json                    # Log format: json, text
LOG_OUTPUT=stdout                  # Log output: stdout, file, syslog
```

## Service Configuration

### Service Definition

#### Required Fields
```yaml
name: "web-service"                # Service name (unique)
description: "Web application service"  # Service description
ip_address: "10.0.1.100"          # Backend IP address
port: 8080                        # Backend port
protocol: "tcp"                    # Protocol: tcp, udp, icmp
cluster_id: "production"           # Cluster assignment (Enterprise)
```

#### Optional Fields
```yaml
# Authentication
auth_type: "jwt"                   # Authentication: none, base64, jwt
auth_config:                       # Authentication configuration
  jwt_secret: "secret"
  jwt_expiry: 3600

# Load balancing
load_balancer:                     # Load balancer configuration
  algorithm: "round_robin"         # Algorithm: round_robin, least_conn, hash
  health_check: true

# TLS settings
tls_enabled: true                  # Enable TLS termination
tls_cert: "web-service-cert"       # Certificate name
tls_redirect: true                 # Redirect HTTP to HTTPS

# Rate limiting
rate_limit:                        # Rate limiting configuration
  requests_per_minute: 1000
  burst_size: 100

# Caching
cache_enabled: true                # Enable response caching
cache_ttl: 300                     # Cache TTL (seconds)
```

### Port Configuration

MarchProxy supports flexible port configuration:

#### Single Port
```yaml
port: 8080
```

#### Port Range
```yaml
port: "8080-8090"
```

#### Multiple Ports
```yaml
port: "80,443,8080"
```

#### Complex Configuration
```yaml
port: "80,443,8080-8090,9000"
```

## Environment File Example

Create a `.env` file for docker-compose:

```bash
# Database
POSTGRES_PASSWORD=secure_postgres_password
DB_HOST=postgres
DB_PORT=5432

# Redis
REDIS_PASSWORD=secure_redis_password

# Security
SECRET_KEY=your-very-secure-secret-key-change-this

# SMTP (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=marchproxy@company.com

# Syslog (optional)
SYSLOG_HOST=syslog.company.com
SYSLOG_PORT=514

# License (Enterprise)
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD

# Clustering
CLUSTER_API_KEY=your-cluster-api-key

# Monitoring
GRAFANA_PASSWORD=secure_grafana_password
ALERT_EMAIL_DEFAULT=ops@company.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# Performance
ENABLE_XDP=true
ENABLE_DPDK=false
```

## Configuration Validation

### Manager Validation
- Database connectivity test
- SMTP configuration test
- License validation
- Redis connectivity test

### Proxy Validation
- Manager connectivity test
- Network interface validation
- Certificate validation
- Acceleration capability detection

### Health Checks
- `/healthz` endpoint for basic health
- `/healthz/detailed` for comprehensive status
- `/metrics` for Prometheus metrics

## Troubleshooting Configuration

### Common Issues

1. **Database Connection Errors**
   ```bash
   # Check environment variables
   docker-compose exec manager env | grep DB_

   # Test database connection
   curl http://localhost:8000/healthz/detailed
   ```

2. **SMTP Configuration Issues**
   ```bash
   # Test SMTP settings
   curl -X POST http://localhost:8000/api/v1/config/smtp/test \
     -H "Content-Type: application/json" \
     -d '{"test_email": "admin@company.com"}'
   ```

3. **License Validation Problems**
   ```bash
   # Check license status
   curl http://localhost:8000/api/v1/license/status
   ```

4. **Proxy Registration Issues**
   ```bash
   # Check proxy status
   curl http://localhost:8080/healthz

   # Verify manager connectivity
   curl http://localhost:8080/admin/manager-status
   ```

### Configuration API

Access configuration programmatically:

```bash
# Get all configuration
curl http://localhost:8000/api/v1/config/system

# Get specific category
curl http://localhost:8000/api/v1/config/system?category=smtp

# Update configuration
curl -X POST http://localhost:8000/api/v1/config/system \
  -H "Content-Type: application/json" \
  -d '{
    "smtp_host": {"value": "new-smtp.company.com", "category": "smtp"},
    "smtp_port": {"value": 587, "category": "smtp"}
  }'
```

---

Next: [API Documentation](api.md)