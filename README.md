# MarchProxy

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/marchproxy/marchproxy)](https://goreportcard.com/report/github.com/marchproxy/marchproxy)
[![Docker Pulls](https://img.shields.io/docker/pulls/marchproxy/manager)](https://hub.docker.com/r/marchproxy/manager)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-brightgreen)](https://kubernetes.io/)

**A high-performance, enterprise-grade proxy suite for managing egress traffic in data center environments.**

MarchProxy provides comprehensive egress traffic management with advanced features including eBPF acceleration, multi-cluster support, and enterprise authentication integrations. Available in Community (open source) and Enterprise (licensed) editions.

## 🚀 Quick Start

### Docker Compose (Recommended for Testing)

```bash
# Clone the repository
git clone https://github.com/marchproxy/marchproxy.git
cd marchproxy

# Start with Docker Compose
docker-compose up -d

# Access the management interface
open http://localhost:8000
```

### Kubernetes with Helm

```bash
# Add Helm repository
helm repo add marchproxy https://charts.marchproxy.io
helm repo update

# Install MarchProxy
helm install marchproxy marchproxy/marchproxy \
  --namespace marchproxy \
  --create-namespace
```

### Kubernetes with Operator

```bash
# Install the operator
kubectl apply -f https://raw.githubusercontent.com/marchproxy/marchproxy/main/operator/config/crd/marchproxy.yaml
kubectl apply -f https://raw.githubusercontent.com/marchproxy/marchproxy/main/operator/config/manager/manager.yaml

# Deploy MarchProxy instance
kubectl apply -f examples/simple-marchproxy.yaml
```

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Performance](#-performance)
- [Security](#-security)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

## ✨ Features

### Core Features
- **High-Performance Proxy**: Multi-protocol support (TCP, UDP, ICMP, HTTP/HTTPS, WebSocket, QUIC/HTTP3)
- **eBPF Acceleration**: Kernel-level packet processing for maximum performance
- **Service-to-Service Mapping**: Granular traffic routing and access control
- **Multi-Cluster Support**: Enterprise-grade cluster management and isolation
- **Real-time Configuration**: Hot-reload configuration without downtime
- **Comprehensive Monitoring**: Prometheus metrics, health checks, and observability

### Performance Acceleration
- **eBPF Fast-path**: Programmable kernel-level packet filtering
- **Hardware Acceleration**: Optional DPDK, XDP, AF_XDP, and SR-IOV support
- **Advanced Caching**: Redis-backed and in-memory caching with multiple eviction policies
- **Circuit Breaker**: Automatic failure detection and recovery
- **Content Compression**: Gzip, Brotli, Zstandard, and Deflate support

### Security & Authentication
- **Multiple Auth Methods**: Base64 tokens, JWT, 2FA/TOTP
- **Enterprise Authentication**: SAML, SCIM, OAuth2 (Google, Microsoft, etc.)
- **TLS Management**: Automatic certificate management via Infisical/Vault or manual upload
- **Web Application Firewall**: SQL injection, XSS, and command injection protection
- **Rate Limiting & DDoS Protection**: Advanced traffic shaping and attack mitigation

### Enterprise Features
- **Multi-Cluster Management**: Unlimited clusters with separate API keys and configurations
- **Advanced Authentication**: SAML SSO, SCIM provisioning, OAuth2 integration
- **Centralized Logging**: Per-cluster syslog configuration and structured logging
- **License Management**: Integration with license.penguintech.io
- **High Availability**: Auto-scaling, load balancing, and fault tolerance

## 🏗️ Architecture

MarchProxy consists of two main components:

### Manager (Python/py4web)
- **Configuration Management**: Centralized service and mapping configuration
- **Authentication & Authorization**: User management and access control
- **Cluster Management**: Multi-cluster support with API key management
- **License Validation**: Enterprise license checking and feature enforcement
- **Web Interface**: Comprehensive management dashboard
- **API Server**: RESTful API for proxy registration and configuration

### Proxy (Go/eBPF)
- **High-Performance Networking**: Multi-protocol proxy with advanced features
- **eBPF Integration**: Kernel-level packet processing and filtering
- **Configuration Sync**: Automatic configuration updates from manager
- **Health Monitoring**: Comprehensive health checks and metrics
- **Security Enforcement**: Authentication, rate limiting, and WAF protection

### Performance Tiers
1. **Standard Networking**: Traditional kernel socket processing
2. **eBPF Acceleration**: Programmable kernel-level packet filtering
3. **XDP/AF_XDP**: Driver-level processing and zero-copy I/O
4. **DPDK**: Kernel bypass for ultra-high performance (10+ Gbps)

## 💼 Edition Comparison

| Feature | Community | Enterprise |
|---------|-----------|------------|
| **Proxy Instances** | Up to 3 | Unlimited* |
| **Clusters** | Single default | Multiple with isolation |
| **Authentication** | Basic, 2FA | + SAML, SCIM, OAuth2 |
| **Performance** | Standard + eBPF | + Hardware acceleration |
| **Monitoring** | Basic metrics | + Advanced analytics |
| **Support** | Community | 24/7 enterprise support |
| **License** | AGPL v3 | Commercial license available |

*Based on license entitlements

## 🚀 Installation

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores
- **Memory**: 4 GB RAM
- **Storage**: 10 GB available space
- **Network**: 1 Gbps network interface
- **OS**: Linux kernel 4.18+ (for eBPF support)

#### Recommended for Production
- **CPU**: 8+ cores
- **Memory**: 16+ GB RAM
- **Storage**: 100+ GB SSD
- **Network**: 10+ Gbps network interface
- **OS**: Ubuntu 20.04+ or RHEL 8+

### Installation Methods

#### 1. Docker Compose (Quickest)
```bash
curl -sSL https://raw.githubusercontent.com/marchproxy/marchproxy/main/docker-compose.yml | \
  docker-compose -f - up -d
```

#### 2. Kubernetes with Helm
```bash
helm repo add marchproxy https://charts.marchproxy.io
helm install marchproxy marchproxy/marchproxy
```

#### 3. Kubernetes with Operator
```bash
kubectl apply -f https://github.com/marchproxy/marchproxy/releases/latest/download/operator.yaml
```

## ⚙️ Configuration

### Basic Configuration

Create a service and mapping:

```yaml
# Service definition
services:
  - name: "web-backend"
    ip_fqdn: "backend.internal.com"
    collection: "web-services"
    auth_type: "jwt"
    cluster_id: 1

# Mapping definition
mappings:
  - source_services: ["web-frontend"]
    dest_services: ["web-backend"]
    protocols: ["tcp", "http"]
    ports: [80, 443]
    auth_required: true
    cluster_id: 1
```

## 🔧 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/marchproxy/marchproxy.git
cd marchproxy

# Build manager
cd manager
pip install -r requirements.txt

# Build proxy
cd ../proxy
go build -o proxy ./cmd/proxy

# Run tests
cd ..
./test/run_tests.sh --all
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/development/contributing.md) for details.

### Quick Start for Contributors

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## 📄 License

### Community Edition
MarchProxy Community Edition is licensed under the [GNU Affero General Public License v3.0](LICENSE).

### Enterprise Edition
Enterprise features require a commercial license. Contact [sales@marchproxy.io](mailto:sales@marchproxy.io) for licensing information.

## 🆘 Support

### Community Support
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community Q&A and discussions

### Enterprise Support
- **24/7 Support**: Emergency response and critical issue resolution
- **Professional Services**: Implementation assistance and consulting

---

**Made with ❤️ by the MarchProxy team**
