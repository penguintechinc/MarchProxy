# Architecture Overview

MarchProxy is designed as a high-performance, scalable proxy solution with a hybrid architecture combining centralized management with distributed packet processing.

## System Components

### Manager (Python/py4web)
- **Role**: Centralized configuration and management
- **Technology**: Python 3.11+, py4web framework, pydal ORM
- **Database**: PostgreSQL (configurable to any pydal-supported DB)
- **Features**:
  - Web-based management interface
  - RESTful API for automation
  - User authentication and authorization
  - License validation and enforcement
  - Cluster and proxy management
  - Configuration distribution

### Proxy (Go/eBPF)
- **Role**: High-performance packet processing
- **Technology**: Go 1.21+, eBPF/XDP, optional hardware acceleration
- **Features**:
  - Multi-tier performance architecture
  - Protocol support: TCP, UDP, ICMP, HTTP/HTTPS, WebSocket, HTTP3/QUIC
  - Stateless design for horizontal scaling
  - Real-time metrics and health monitoring
  - Dynamic configuration updates

## Performance Architecture

MarchProxy implements a multi-tier packet processing pipeline for optimal performance:

### Tier 1: Hardware Acceleration (Enterprise)
**Performance**: 10-40+ Gbps depending on technology

- **DPDK (Data Plane Development Kit)**
  - Kernel bypass for maximum throughput
  - Direct NIC hardware access
  - Zero-copy packet processing
  - Best for: Ultra-high throughput scenarios

- **XDP (eXpress Data Path)**
  - Driver-level packet processing
  - Programmable with eBPF
  - Early packet drop/redirect
  - Best for: DDoS protection, simple filtering

- **AF_XDP (Address Family XDP)**
  - Zero-copy socket interface
  - Userspace packet processing
  - Lower CPU overhead than standard sockets
  - Best for: High-performance userspace apps

- **SR-IOV (Single Root I/O Virtualization)**
  - Hardware-assisted virtualization
  - Direct device assignment to VMs
  - Reduced hypervisor overhead
  - Best for: Virtualized environments

### Tier 2: eBPF Fast-path
**Performance**: ~5 Gbps

- Kernel-level packet filtering
- Simple rule matching and statistics
- Connection tracking
- Automatic classification for fast/slow path
- Direct integration with XDP

### Tier 3: Go Application Logic
**Performance**: ~1 Gbps

- Complex authentication (JWT, Base64 tokens)
- TLS termination and certificate management
- WebSocket upgrade handling
- Advanced routing and load balancing
- Full protocol feature support

### Tier 4: Standard Networking
**Performance**: ~100 Mbps

- Traditional kernel socket processing
- Fallback for unsupported scenarios
- Compatibility mode for older systems

## Rule Classification System

The system automatically classifies rules for optimal processing:

### Fast-path Rules (XDP/eBPF)
- Simple allow/drop/redirect actions
- Basic IP/port matching
- Connection counting
- Statistics collection
- No authentication required

### Slow-path Rules (Go Application)
- Authentication required (JWT/Base64)
- TLS termination needed
- WebSocket upgrade required
- Complex routing logic
- Advanced protocol features

## Data Flow

```
[Client] → [Hardware/XDP] → [eBPF Filter] → [Go Proxy] → [Backend Service]
    ↓           ↓               ↓               ↓
 Capture    Fast Filter    Slow Path      Full Features
           (~40Gbps)      (~5Gbps)       (~1Gbps)
```

### Packet Processing Flow

1. **Packet Arrival**: Network interface receives packet
2. **Hardware Acceleration**: DPDK/XDP/AF_XDP processing (if available)
3. **eBPF Classification**: Determine fast-path vs slow-path
4. **Fast-path Processing**: Simple rules handled in kernel/hardware
5. **Slow-path Processing**: Complex rules handled by Go application
6. **Backend Routing**: Forward to appropriate backend service

## Clustering Architecture

### Community Edition
- Single "default" cluster
- Maximum 3 proxy servers
- Shared configuration namespace

### Enterprise Edition
- Multiple named clusters with isolation
- Unlimited proxies (license-based)
- Cluster-specific API keys
- Independent configuration and policies

### Cluster Communication
```
[Manager] ←→ [Proxy-1] [Proxy-2] [Proxy-3] ... [Proxy-N]
    ↓              ↓        ↓        ↓           ↓
[Database]    [Local      [Local   [Local    [Local
              Config]     Config]  Config]   Config]
```

## Security Architecture

### Authentication Layers
1. **Management Interface**: SAML/SCIM/OAuth2/2FA (Enterprise) or local auth
2. **API Access**: Cluster-specific API keys via py4web native system
3. **Service Authentication**: Base64 tokens OR JWT (mutually exclusive)
4. **TLS Management**: Infisical/Vault integration or direct upload

### Role-based Access Control
- **Administrator**: Full system access, all clusters
- **Service Owner**: Limited to assigned clusters and services
- **Cluster Isolation**: Enterprise multi-cluster security boundaries

## Database Schema

### Core Tables
- **Users**: Authentication and authorization
- **Clusters**: Cluster definitions and API keys (Enterprise)
- **Services**: Service definitions and mappings
- **Proxy Registration**: Active proxy instances
- **System Config**: Dynamic configuration storage

### Configuration Hierarchy
1. **Control Panel Settings** (Database) - Highest priority
2. **Environment Variables** - Fallback for initial setup
3. **Default Values** - System defaults

## Monitoring Architecture

### Metrics Collection
- **Prometheus**: Time-series metrics storage
- **Custom Metrics**: MarchProxy-specific performance data
- **System Metrics**: CPU, memory, network, disk usage

### Log Aggregation
- **Loki**: Centralized log storage
- **Promtail**: Log collection and forwarding
- **Structured Logging**: JSON format with contextual data

### Alerting
- **AlertManager**: Alert routing and notification
- **Dynamic Configuration**: Manager-driven alert settings
- **Multi-channel**: Email, Slack, PagerDuty integration

### Visualization
- **Grafana**: Real-time dashboards
- **Custom Dashboards**: MarchProxy-specific views
- **Performance Analytics**: Acceleration technology comparison

## Scalability Patterns

### Horizontal Scaling
- **Stateless Proxies**: No shared state between instances
- **Load Balancing**: Round-robin, least-connections, or custom
- **Auto-scaling**: Container orchestration integration

### Vertical Scaling
- **Hardware Acceleration**: Leverage available technologies
- **Resource Allocation**: CPU/memory tuning per workload
- **Performance Monitoring**: Real-time optimization

### Geographic Distribution
- **Multi-region Clusters**: Enterprise cluster separation
- **Latency Optimization**: Regional proxy deployment
- **Failover**: Cross-region redundancy

## Integration Points

### Container Orchestration
- **Docker Compose**: Development and small deployments
- **Kubernetes**: Production container orchestration
- **Helm Charts**: Kubernetes package management

### Service Mesh
- **Istio Integration**: Service mesh compatibility
- **Envoy Proxy**: Protocol translation layer
- **OpenTelemetry**: Distributed tracing

### CI/CD Pipeline
- **GitHub Actions**: Automated testing and deployment
- **Multi-architecture**: amd64 and arm64 support
- **Quality Gates**: Security scanning, performance testing

## Deployment Patterns

### Development
- Docker Compose with local storage
- Single-node deployment
- Hot-reload for development

### Staging
- Kubernetes with shared storage
- Multi-node testing
- Performance validation

### Production
- Kubernetes with persistent storage
- High availability configuration
- Hardware acceleration enabled
- Comprehensive monitoring

---

Next: [Configuration Reference](configuration.md)