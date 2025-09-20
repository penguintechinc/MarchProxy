# MarchProxy Documentation

MarchProxy is a high-performance, enterprise-grade egress proxy solution designed for data center environments. It provides intelligent traffic routing, advanced authentication, and optional hardware acceleration for maximum throughput.

## Quick Links

- **[Installation Guide](installation.md)** - Get started with MarchProxy
- **[Architecture Overview](architecture.md)** - System design and components
- **[Configuration Reference](configuration.md)** - Complete configuration options
- **[API Documentation](api.md)** - REST API reference
- **[Performance Guide](performance.md)** - Hardware acceleration and tuning
- **[Security Guide](security.md)** - Authentication and access control
- **[Monitoring Guide](monitoring.md)** - Metrics, logging, and alerting
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions
- **[Development Guide](development.md)** - Contributing and building from source

## Product Tiers

### Community Edition (Open Source)
- ✅ Up to 3 proxy servers
- ✅ Single default cluster
- ✅ Basic authentication (Base64 tokens)
- ✅ Core protocol support (TCP/UDP/ICMP/HTTP/HTTPS)
- ✅ eBPF acceleration
- ✅ PostgreSQL database
- ✅ Web management interface

### Enterprise Edition (Licensed)
- ✅ Unlimited proxy servers (license-based)
- ✅ Multi-cluster support with isolation
- ✅ Advanced authentication (SAML/SCIM/OAuth2/2FA)
- ✅ JWT token authentication with rotation
- ✅ Hardware acceleration (DPDK/XDP/AF_XDP/SR-IOV)
- ✅ TLS certificate management (Vault/Infisical integration)
- ✅ Advanced monitoring and alerting
- ✅ WebSocket and HTTP3/QUIC support
- ✅ Role-based access control
- ✅ Enterprise support

## Architecture Overview

MarchProxy consists of two main components:

### Manager (Python/py4web)
- Web-based management interface
- Configuration and policy management
- User authentication and authorization
- License validation and cluster management
- RESTful API for automation
- PostgreSQL database with pydal ORM

### Proxy (Go/eBPF)
- High-performance packet processing
- Multi-tier acceleration (Hardware → eBPF → Go → Standard)
- Protocol support: TCP, UDP, ICMP, HTTP/HTTPS, WebSocket, HTTP3/QUIC
- Real-time metrics and health monitoring
- Horizontal scaling with stateless design

## Performance Tiers

MarchProxy implements a multi-tier performance architecture:

1. **Hardware Acceleration** (Enterprise)
   - DPDK for kernel bypass (~40 Gbps+)
   - XDP for driver-level processing (~25 Gbps)
   - AF_XDP for zero-copy operations (~15 Gbps)
   - SR-IOV for virtualized environments (~10 Gbps)

2. **eBPF Fast-path**
   - Kernel-level packet filtering (~5 Gbps)
   - Simple rule matching and statistics
   - Automatic fast/slow path classification

3. **Go Application Logic**
   - Complex authentication and routing (~1 Gbps)
   - TLS termination and WebSocket handling
   - Full protocol feature support

4. **Standard Networking**
   - Traditional kernel socket processing (~100 Mbps)
   - Fallback for unsupported scenarios

## Key Features

### Traffic Management
- Service-to-service mapping with cluster isolation
- Port configuration: single, ranges, comma-separated lists
- Protocol support with automatic detection
- Load balancing and failover

### Security & Authentication
- Multi-factor authentication (Enterprise)
- SAML/SCIM/OAuth2 integration (Enterprise)
- Base64 tokens or JWT with rotation
- Role-based access control
- TLS certificate management

### Monitoring & Observability
- Prometheus metrics with custom dashboards
- Structured logging with Loki aggregation
- Health check endpoints (/healthz, /metrics)
- UDP syslog integration
- Distributed tracing with Jaeger

### Clustering & Scaling
- Multi-cluster support (Enterprise)
- Horizontal proxy scaling
- Cluster-specific API keys
- License-based capacity management

## System Requirements

### Minimum Requirements
- Linux kernel 4.18+ (for eBPF support)
- 2 CPU cores, 4GB RAM
- 20GB storage space
- Docker and Docker Compose

### Recommended (Production)
- Linux kernel 5.4+ (for advanced eBPF features)
- 8+ CPU cores, 16GB+ RAM
- SSD storage, 100GB+
- Dedicated network interfaces
- Hardware acceleration support (Enterprise)

### Network Requirements
- Outbound internet connectivity for licensing
- Administrative access to network configuration
- Support for custom routing tables

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/marchproxy.git
   cd marchproxy
   ```

2. **Set up environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start services:**
   ```bash
   docker-compose up -d
   ```

4. **Access web interface:**
   - Manager: http://localhost:8000
   - Grafana: http://localhost:3000
   - Prometheus: http://localhost:9090

5. **Configure your first service:**
   - Log into the manager interface
   - Create a new cluster (Enterprise) or use default
   - Add service mappings
   - Deploy proxy configuration

## Support & Community

- **Documentation**: [docs/](./README.md)
- **Issues**: [GitHub Issues](https://github.com/your-org/marchproxy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/marchproxy/discussions)
- **Enterprise Support**: Contact sales@penguintech.io

## License

- **Community Edition**: Apache 2.0 License
- **Enterprise Edition**: Commercial license required

See [LICENSE](../LICENSE) for details.

---

For detailed information on any topic, please refer to the specific documentation files linked above.