# Installation Guide

This guide covers the installation and initial setup of MarchProxy in various deployment scenarios.

## Table of Contents

- [Quick Start (Docker Compose)](#quick-start-docker-compose)
- [Production Deployment](#production-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Manual Installation](#manual-installation)
- [Configuration](#configuration)
- [Verification](#verification)

## Quick Start (Docker Compose)

The fastest way to get MarchProxy running for development or testing.

### Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- Linux kernel 4.18+ (for eBPF support)
- 4GB RAM, 2 CPU cores minimum
- 20GB free disk space

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/marchproxy.git
   cd marchproxy
   ```

2. **Copy environment template:**
   ```bash
   cp .env.example .env
   ```

3. **Configure environment variables:**
   ```bash
   # Edit .env file with your settings
   nano .env
   ```

   Key variables to set:
   ```bash
   # Database
   POSTGRES_PASSWORD=your_secure_password
   REDIS_PASSWORD=your_redis_password

   # Security
   SECRET_KEY=your-secret-key-change-this-to-something-secure

   # Monitoring
   GRAFANA_PASSWORD=your_grafana_password

   # Clustering (Enterprise)
   CLUSTER_API_KEY=your-cluster-api-key

   # License (Enterprise)
   LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD
   ```

4. **Start the services:**
   ```bash
   # Start all services
   docker-compose up -d

   # Check status
   docker-compose ps
   ```

5. **Wait for services to initialize:**
   ```bash
   # Watch logs for startup completion
   docker-compose logs -f manager
   ```

6. **Access the web interface:**
   - Manager: http://localhost:8000
   - Grafana: http://localhost:3000 (admin/your_grafana_password)
   - Prometheus: http://localhost:9090

### Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: destroys data)
docker-compose down -v
```

## Production Deployment

For production environments, additional considerations are required.

### Production Prerequisites

- Linux kernel 5.4+ (recommended for advanced features)
- 8+ CPU cores, 16GB+ RAM
- SSD storage, 100GB+
- Dedicated network interfaces
- Load balancer (for HA setup)
- SSL certificates

### Production Environment File

Create a production-specific environment file:

```bash
# .env.production
MARCHPROXY_ENV=production
DEBUG=false
LOG_LEVEL=info

# Strong passwords
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
SECRET_KEY=$(openssl rand -base64 64)
GRAFANA_PASSWORD=$(openssl rand -base64 16)

# Database
DATABASE_URL=postgresql://marchproxy:${POSTGRES_PASSWORD}@postgres:5432/marchproxy

# Networking
PROXY_LISTEN_PORT=80
PROXY_TLS_PORT=443
PROXY_ADMIN_PORT=8080

# Enterprise features
LICENSE_KEY=your-enterprise-license-key
CLUSTER_API_KEY=$(openssl rand -base64 32)

# External integrations
SAML_IDP_URL=https://your-idp.example.com
VAULT_ADDR=https://vault.example.com
JAEGER_ENDPOINT=https://jaeger.example.com:14268/api/traces

# TLS
TLS_CERT_PATH=/app/certs/server.crt
TLS_KEY_PATH=/app/certs/server.key
```

### SSL Certificate Setup

```bash
# Create certificates directory
mkdir -p certs

# Option 1: Use existing certificates
cp your-server.crt certs/server.crt
cp your-server.key certs/server.key

# Option 2: Generate self-signed (development only)
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
  -out certs/server.crt -days 365 -nodes \
  -subj "/CN=marchproxy.example.com"

# Set proper permissions
chmod 600 certs/server.key
chmod 644 certs/server.crt
```

### Production Docker Compose

For production, use the production compose file:

```bash
# Start with production configuration
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### High Availability Setup

For HA deployment, run multiple proxy instances:

```bash
# Scale proxy instances
docker-compose up -d --scale proxy=3

# Or use specific instance configurations
docker-compose -f docker-compose.yml -f docker-compose.ha.yml up -d
```

## Kubernetes Deployment

Deploy MarchProxy on Kubernetes for container orchestration.

### Prerequisites

- Kubernetes 1.20+
- kubectl configured
- Helm 3.0+ (optional but recommended)
- Persistent volume support
- LoadBalancer or Ingress controller

### Using Helm (Recommended)

```bash
# Add MarchProxy Helm repository
helm repo add marchproxy https://charts.marchproxy.io
helm repo update

# Install with custom values
helm install marchproxy marchproxy/marchproxy \
  --namespace marchproxy \
  --create-namespace \
  --values values.yaml
```

### Manual Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/manager.yaml
kubectl apply -f k8s/proxy.yaml
kubectl apply -f k8s/monitoring.yaml
```

### Kubernetes Configuration

Example values.yaml for Helm:

```yaml
# values.yaml
replicaCount:
  manager: 2
  proxy: 3

image:
  repository: marchproxy/marchproxy
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  port: 80
  tlsPort: 443

ingress:
  enabled: true
  className: nginx
  host: marchproxy.example.com
  tls:
    enabled: true
    secretName: marchproxy-tls

postgresql:
  enabled: true
  auth:
    database: marchproxy
    username: marchproxy
    password: changeme

redis:
  enabled: true
  auth:
    enabled: true
    password: changeme

monitoring:
  prometheus:
    enabled: true
  grafana:
    enabled: true
    adminPassword: changeme

enterprise:
  enabled: false
  licenseKey: ""
```

## Manual Installation

For custom installations without Docker.

### System Requirements

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y \
  build-essential \
  python3 \
  python3-pip \
  python3-venv \
  postgresql \
  redis-server \
  golang-go \
  clang \
  llvm \
  libbpf-dev \
  linux-headers-$(uname -r)

# Install dependencies (RHEL/CentOS)
sudo dnf install -y \
  gcc \
  python3 \
  python3-pip \
  postgresql-server \
  redis \
  golang \
  clang \
  llvm \
  libbpf-devel \
  kernel-devel
```

### Database Setup

```bash
# PostgreSQL setup
sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo -u postgres createuser -s marchproxy
sudo -u postgres createdb marchproxy

# Redis setup
sudo systemctl enable redis
sudo systemctl start redis
```

### Manager Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
cd manager
pip install -r requirements.txt

# Initialize database
python3 -m py4web setup

# Start manager
python3 -m py4web run -p 8000
```

### Proxy Installation

```bash
# Build proxy
cd proxy
go mod tidy
go build -o marchproxy-proxy ./cmd/proxy

# Install eBPF programs
sudo ./marchproxy-proxy install-ebpf

# Start proxy
sudo ./marchproxy-proxy
```

## Configuration

### Initial Setup

1. **Access the manager interface:**
   ```
   http://localhost:8000
   ```

2. **Complete initial setup wizard:**
   - Create admin account
   - Configure database connection
   - Set up licensing (Enterprise)
   - Configure authentication

3. **Create first cluster:**
   - Default cluster (Community)
   - Named cluster with API key (Enterprise)

4. **Add proxy instances:**
   - Register proxies with cluster API key
   - Configure network interfaces
   - Enable acceleration features

### Network Configuration

Configure network settings for optimal performance:

```bash
# Increase receive buffer sizes
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.rmem_default = 65536' >> /etc/sysctl.conf

# Increase send buffer sizes
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 65536' >> /etc/sysctl.conf

# Increase connection tracking table size
echo 'net.netfilter.nf_conntrack_max = 1048576' >> /etc/sysctl.conf

# Apply settings
sysctl -p
```

### Firewall Configuration

```bash
# Allow required ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 8080/tcp

# For monitoring (optional)
sudo ufw allow 3000/tcp
sudo ufw allow 9090/tcp
```

## Verification

### Health Checks

```bash
# Check manager health
curl http://localhost:8000/health

# Check proxy health
curl http://localhost:8080/health

# Check metrics
curl http://localhost:8080/metrics
```

### Service Status

```bash
# Docker Compose
docker-compose ps
docker-compose logs

# Kubernetes
kubectl get pods -n marchproxy
kubectl logs -n marchproxy deployment/marchproxy-manager

# Manual installation
systemctl status marchproxy-manager
systemctl status marchproxy-proxy
```

### Performance Testing

```bash
# Run built-in benchmark
curl -X POST http://localhost:8080/admin/benchmark

# Check acceleration status
curl http://localhost:8080/admin/acceleration
```

## Troubleshooting

### Common Issues

1. **eBPF compilation errors:**
   ```bash
   # Install required headers
   sudo apt install linux-headers-$(uname -r)

   # Verify kernel version
   uname -r
   ```

2. **Permission issues:**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER

   # Restart session or run:
   newgrp docker
   ```

3. **Database connection errors:**
   ```bash
   # Check PostgreSQL status
   docker-compose logs postgres

   # Verify connection string
   docker-compose exec manager env | grep DATABASE_URL
   ```

4. **Memory issues:**
   ```bash
   # Increase Docker memory limits
   # Edit Docker Desktop settings or add to daemon.json:
   {
     "default-runtime": "runc",
     "default-memory": "4g"
   }
   ```

### Log Locations

- Manager logs: `/var/log/marchproxy/manager/`
- Proxy logs: `/var/log/marchproxy/proxy/`
- Docker logs: `docker-compose logs <service>`
- Kubernetes logs: `kubectl logs <pod> -n marchproxy`

### Support

If you encounter issues:

1. Check the [troubleshooting guide](troubleshooting.md)
2. Review logs for error messages
3. Verify system requirements
4. Check GitHub issues
5. Contact support (Enterprise customers)

---

Next: [Configuration Reference](configuration.md)