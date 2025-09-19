# Docker Installation Guide

This guide covers installing MarchProxy using Docker and Docker Compose.

## Prerequisites

- Docker 20.10+ or Docker Desktop
- Docker Compose 1.28+ or `docker compose` (v2)
- 4 GB RAM minimum (8 GB recommended)
- 10 GB available disk space

## Quick Start with Docker Compose

The fastest way to get MarchProxy running is with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/marchproxy/marchproxy.git
cd marchproxy

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Access the management interface
open http://localhost:8000
```

## Production Docker Compose Setup

For production environments, use the production compose file:

```bash
# Download production compose file
curl -sSL https://raw.githubusercontent.com/marchproxy/marchproxy/main/docker-compose.prod.yml > docker-compose.yml

# Configure environment variables
cp .env.example .env
vim .env

# Start services
docker-compose up -d
```

### Environment Configuration

Edit `.env` file:

```bash
# Database configuration
POSTGRES_DB=marchproxy
POSTGRES_USER=marchproxy
POSTGRES_PASSWORD=secure_password_here

# Redis configuration
REDIS_PASSWORD=redis_password_here

# JWT secret
JWT_SECRET=your_jwt_secret_here

# License key (Enterprise only)
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD

# Cluster API key
CLUSTER_API_KEY=your_cluster_api_key_here

# External URLs
MANAGER_URL=https://manager.your-domain.com
PROXY_URL=https://proxy.your-domain.com
```

## Individual Container Deployment

### Manager Container

```bash
# Run PostgreSQL
docker run -d \
  --name marchproxy-postgres \
  -e POSTGRES_DB=marchproxy \
  -e POSTGRES_USER=marchproxy \
  -e POSTGRES_PASSWORD=your_password \
  -v postgres_data:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:15

# Run Redis
docker run -d \
  --name marchproxy-redis \
  -v redis_data:/data \
  -p 6379:6379 \
  redis:7-alpine

# Run Manager
docker run -d \
  --name marchproxy-manager \
  -e DATABASE_URL=postgresql://marchproxy:your_password@localhost:5432/marchproxy \
  -e REDIS_URL=redis://localhost:6379/0 \
  -e JWT_SECRET=your_jwt_secret \
  -p 8000:8000 \
  -p 9090:9090 \
  --network host \
  marchproxy/manager:latest
```

### Proxy Container

```bash
# Run Proxy
docker run -d \
  --name marchproxy-proxy \
  -e MANAGER_URL=http://localhost:8000 \
  -e CLUSTER_API_KEY=your_cluster_api_key \
  -p 8080:8080 \
  -p 8888:8888 \
  --privileged \
  --network host \
  marchproxy/proxy:latest
```

## Docker Build from Source

### Build Manager Image

```bash
cd manager
docker build -t marchproxy/manager:dev .
```

### Build Proxy Image

```bash
cd proxy
docker build -t marchproxy/proxy:dev .
```

### Multi-arch Build

```bash
# Enable buildx
docker buildx create --use

# Build multi-architecture images
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t marchproxy/manager:latest \
  --push \
  manager/

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t marchproxy/proxy:latest \
  --push \
  proxy/
```

## Docker Networks

### Custom Network Setup

```bash
# Create custom network
docker network create marchproxy-net

# Run containers with custom network
docker run -d \
  --name marchproxy-postgres \
  --network marchproxy-net \
  -e POSTGRES_DB=marchproxy \
  postgres:15

docker run -d \
  --name marchproxy-manager \
  --network marchproxy-net \
  -e DATABASE_URL=postgresql://marchproxy:password@marchproxy-postgres:5432/marchproxy \
  -p 8000:8000 \
  marchproxy/manager:latest
```

## Persistent Data

### Volume Management

```bash
# Create named volumes
docker volume create postgres_data
docker volume create redis_data
docker volume create manager_config
docker volume create proxy_config

# Use volumes in containers
docker run -d \
  --name marchproxy-postgres \
  -v postgres_data:/var/lib/postgresql/data \
  postgres:15

docker run -d \
  --name marchproxy-manager \
  -v manager_config:/app/config \
  marchproxy/manager:latest
```

### Backup and Restore

```bash
# Backup PostgreSQL
docker exec marchproxy-postgres pg_dump -U marchproxy marchproxy > backup.sql

# Restore PostgreSQL
docker exec -i marchproxy-postgres psql -U marchproxy marchproxy < backup.sql

# Backup Redis
docker exec marchproxy-redis redis-cli BGSAVE
docker cp marchproxy-redis:/data/dump.rdb ./redis-backup.rdb

# Restore Redis
docker cp ./redis-backup.rdb marchproxy-redis:/data/dump.rdb
docker restart marchproxy-redis
```

## Security Considerations

### Container Security

```bash
# Run with non-root user
docker run -d \
  --name marchproxy-manager \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  marchproxy/manager:latest

# Limit resources
docker run -d \
  --name marchproxy-proxy \
  --memory=2g \
  --cpus=2 \
  --pids-limit=1000 \
  marchproxy/proxy:latest
```

### Secrets Management

```bash
# Use Docker secrets
echo "your_jwt_secret" | docker secret create jwt_secret -
echo "your_db_password" | docker secret create db_password -

# Reference secrets in compose
version: '3.8'
services:
  manager:
    image: marchproxy/manager:latest
    secrets:
      - jwt_secret
      - db_password
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - DB_PASSWORD_FILE=/run/secrets/db_password

secrets:
  jwt_secret:
    external: true
  db_password:
    external: true
```

## Monitoring and Logging

### Container Monitoring

```bash
# View container stats
docker stats marchproxy-manager marchproxy-proxy

# Monitor resource usage
docker exec marchproxy-manager ps aux
docker exec marchproxy-manager free -h
docker exec marchproxy-manager df -h
```

### Centralized Logging

```bash
# Configure logging driver
docker run -d \
  --name marchproxy-manager \
  --log-driver=syslog \
  --log-opt syslog-address=udp://loghost:514 \
  --log-opt tag="marchproxy-manager" \
  marchproxy/manager:latest

# Use JSON file logging
docker run -d \
  --name marchproxy-proxy \
  --log-driver=json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  marchproxy/proxy:latest
```

## Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check logs
docker logs marchproxy-manager
docker logs marchproxy-proxy

# Check container status
docker inspect marchproxy-manager

# Verify environment variables
docker exec marchproxy-manager env
```

#### Database Connection Issues

```bash
# Test database connectivity
docker exec marchproxy-manager nc -zv localhost 5432

# Check PostgreSQL logs
docker logs marchproxy-postgres

# Verify database exists
docker exec marchproxy-postgres psql -U marchproxy -l
```

#### Network Connectivity

```bash
# Test manager connectivity
docker exec marchproxy-proxy curl -v http://manager:8000/healthz

# Check DNS resolution
docker exec marchproxy-proxy nslookup manager

# Verify port binding
docker port marchproxy-manager
```

### Performance Tuning

```bash
# Increase shared memory for PostgreSQL
docker run -d \
  --name marchproxy-postgres \
  --shm-size=1g \
  postgres:15

# Optimize for high connection count
docker run -d \
  --name marchproxy-proxy \
  --ulimit nofile=65536:65536 \
  --sysctl net.core.somaxconn=32768 \
  marchproxy/proxy:latest
```

## Health Checks

### Built-in Health Checks

```yaml
# docker-compose.yml
version: '3.8'
services:
  manager:
    image: marchproxy/manager:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  proxy:
    image: marchproxy/proxy:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8888/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### External Health Monitoring

```bash
# Monitor health endpoints
curl http://localhost:8000/healthz
curl http://localhost:8888/healthz

# Check metrics
curl http://localhost:9090/metrics
```

## Upgrade Procedures

### Rolling Updates

```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d

# Check upgrade status
docker-compose ps
docker-compose logs
```

### Zero-Downtime Upgrades

```bash
# Scale up with new version
docker-compose up -d --scale manager=2

# Wait for health checks
sleep 30

# Scale down old version
docker stop marchproxy_manager_1

# Verify everything works
curl http://localhost:8000/healthz

# Remove old container
docker rm marchproxy_manager_1
```

For more advanced deployment scenarios, see the [Kubernetes Installation Guide](kubernetes.md).