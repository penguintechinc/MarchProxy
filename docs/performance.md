# Performance Guide

This guide covers performance optimization, hardware acceleration, and benchmarking for MarchProxy.

## Performance Architecture Overview

MarchProxy implements a multi-tier performance architecture designed to maximize throughput while maintaining feature compatibility.

### Performance Tiers

| Tier | Technology | Throughput | Use Case |
|------|------------|------------|----------|
| 1 | DPDK | 40+ Gbps | Ultra-high throughput |
| 2 | XDP | 25 Gbps | DDoS protection, simple filtering |
| 3 | AF_XDP | 15 Gbps | Zero-copy userspace |
| 4 | SR-IOV | 10 Gbps | Virtualized environments |
| 5 | eBPF | 5 Gbps | Kernel-level filtering |
| 6 | Go Application | 1 Gbps | Full feature support |
| 7 | Standard Sockets | 100 Mbps | Compatibility mode |

## Hardware Acceleration

### DPDK (Data Plane Development Kit)

**Enterprise Feature** - Highest performance option

#### Requirements
- Intel or AMD x86_64 processor
- DPDK-compatible NIC (Intel 82599, X710, Mellanox ConnectX, etc.)
- Hugepages support
- Linux kernel 4.4+
- Root privileges or capabilities

#### Configuration
```bash
# Enable DPDK
ENABLE_DPDK=true
DPDK_DRIVER=vfio-pci
DPDK_HUGEPAGES=2048
DPDK_CORES=4-7
DPDK_MEMORY_CHANNELS=4

# NIC configuration
DPDK_PCI_DEVICES=0000:02:00.0,0000:02:00.1
DPDK_PORT_MASK=0x3
```

#### Setup Steps
1. **Install DPDK dependencies**:
   ```bash
   apt-get install dpdk dpdk-dev
   ```

2. **Configure hugepages**:
   ```bash
   echo 2048 > /proc/sys/vm/nr_hugepages
   ```

3. **Bind NICs to DPDK driver**:
   ```bash
   dpdk-devbind --bind=vfio-pci 0000:02:00.0
   ```

4. **Verify setup**:
   ```bash
   curl http://localhost:8080/admin/acceleration
   ```

### XDP (eXpress Data Path)

**Community + Enterprise** - Driver-level packet processing

#### Requirements
- Linux kernel 4.18+ (5.4+ recommended)
- XDP-compatible NIC driver
- eBPF support in kernel
- libbpf development libraries

#### Configuration
```bash
# Enable XDP
ENABLE_XDP=true
XDP_MODE=native        # native, skb, hw
XDP_INTERFACE=eth0
XDP_QUEUE_SIZE=1024

# eBPF settings
EBPF_LOG_LEVEL=1
EBPF_MAPS_SIZE=65536
```

#### Modes
- **Native Mode**: Fastest, direct driver integration
- **SKB Mode**: Compatibility mode, slower but works with all drivers
- **Hardware Mode**: Offload to NIC hardware (limited NICs)

#### Verification
```bash
# Check XDP status
ip link show eth0

# Monitor XDP statistics
bpftool prog show
bpftool map show
```

### AF_XDP (Address Family XDP)

**Enterprise Feature** - Zero-copy userspace processing

#### Requirements
- Linux kernel 4.18+
- XDP-compatible driver with AF_XDP support
- libbpf with AF_XDP support

#### Configuration
```bash
# Enable AF_XDP
ENABLE_AF_XDP=true
AF_XDP_MODE=zero_copy
AF_XDP_QUEUE_SIZE=2048
AF_XDP_BATCH_SIZE=64
```

#### Benefits
- Zero-copy packet processing
- Lower CPU overhead than standard sockets
- Userspace flexibility with kernel performance

### SR-IOV (Single Root I/O Virtualization)

**Enterprise Feature** - Hardware virtualization acceleration

#### Requirements
- SR-IOV capable NIC
- IOMMU support (Intel VT-d or AMD-Vi)
- Virtualization environment (KVM, VMware, etc.)

#### Configuration
```bash
# Enable SR-IOV
ENABLE_SR_IOV=true
SR_IOV_VF_COUNT=8
SR_IOV_PF_DEVICE=eth0
```

#### Setup
1. **Enable SR-IOV in BIOS/UEFI**
2. **Configure kernel parameters**:
   ```bash
   # Add to GRUB_CMDLINE_LINUX
   intel_iommu=on iommu=pt
   ```
3. **Create virtual functions**:
   ```bash
   echo 8 > /sys/class/net/eth0/device/sriov_numvfs
   ```

## Performance Tuning

### System-level Optimization

#### CPU Affinity
```bash
# Isolate CPUs for proxy
PROXY_CPU_AFFINITY=4-7
ADMIN_CPU_AFFINITY=0-3

# Set in systemd service
CPUAffinity=4-7
```

#### Memory Configuration
```bash
# Hugepages for DPDK
echo 2048 > /proc/sys/vm/nr_hugepages

# Memory limits
MAX_MEMORY_MB=8192
GOGC=50

# Buffer sizes
RECV_BUFFER_SIZE=262144
SEND_BUFFER_SIZE=262144
```

#### Network Tuning
```bash
# Increase buffer sizes
net.core.rmem_max = 134217728
net.core.rmem_default = 65536
net.core.wmem_max = 134217728
net.core.wmem_default = 65536

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.core.netdev_max_backlog = 30000

# TCP optimization
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 4096 131072 134217728
net.ipv4.tcp_wmem = 4096 131072 134217728
```

#### IRQ Balancing
```bash
# Disable irqbalance for dedicated CPUs
systemctl stop irqbalance

# Manual IRQ affinity
echo 4 > /proc/irq/24/smp_affinity_list
echo 5 > /proc/irq/25/smp_affinity_list
```

### Application-level Optimization

#### Worker Configuration
```bash
# Worker threads (0 = auto-detect)
WORKER_THREADS=0

# I/O threads
IO_THREADS=4

# Go runtime
GOMAXPROCS=8
GOGC=100
```

#### Connection Settings
```bash
# Connection limits
MAX_CONNECTIONS=10000
KEEP_ALIVE_TIMEOUT=75
READ_TIMEOUT=30
WRITE_TIMEOUT=30
IDLE_TIMEOUT=180

# Request handling
MAX_REQUESTS_PER_WORKER=10000
REQUEST_TIMEOUT=30
```

## Benchmarking

### Built-in Benchmarks

MarchProxy includes comprehensive benchmarking tools:

```bash
# Run full benchmark suite
curl -X POST http://localhost:8080/admin/benchmark

# Specific benchmark types
curl -X POST http://localhost:8080/admin/benchmark/throughput
curl -X POST http://localhost:8080/admin/benchmark/latency
curl -X POST http://localhost:8080/admin/benchmark/connections
curl -X POST http://localhost:8080/admin/benchmark/mixed
```

### Benchmark Configuration

```json
{
  "duration": "30s",
  "packet_size": 1400,
  "connections": 1000,
  "workers": 8,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "protocol": "tcp"
}
```

### External Benchmarks

#### iperf3 Testing
```bash
# Server mode
iperf3 -s -p 8080

# Client testing
iperf3 -c proxy-host -p 8080 -t 60 -P 10
```

#### wrk HTTP Benchmarking
```bash
# HTTP throughput test
wrk -t12 -c400 -d30s http://proxy-host:80/

# HTTPS throughput test
wrk -t12 -c400 -d30s https://proxy-host:443/
```

#### netperf Testing
```bash
# TCP throughput
netperf -H proxy-host -t TCP_STREAM -l 60

# UDP throughput
netperf -H proxy-host -t UDP_STREAM -l 60

# Latency testing
netperf -H proxy-host -t TCP_RR -l 60
```

### Performance Monitoring

#### Real-time Metrics

Monitor performance through Grafana dashboards:

- **Request Rate**: Requests per second
- **Latency Distribution**: P50, P95, P99 latency
- **Throughput**: Bytes per second, Gbps
- **Connection Statistics**: Active connections, new connections/sec
- **Acceleration Metrics**: XDP packets, eBPF hits, hardware stats
- **Resource Usage**: CPU, memory, network utilization

#### Key Performance Indicators

```promql
# Request rate
rate(marchproxy_requests_total[5m])

# Latency percentiles
histogram_quantile(0.95, rate(marchproxy_request_duration_seconds_bucket[5m]))

# Throughput
rate(marchproxy_bytes_transferred_total[5m]) * 8 / 1e9

# XDP performance
rate(marchproxy_xdp_total_packets_total[5m])

# Connection rate
rate(marchproxy_connections_opened_total[5m])
```

## Performance Optimization Strategies

### Rule Optimization

#### Fast-path Classification
Ensure simple rules use fast-path processing:

```yaml
# Fast-path rule (XDP/eBPF)
- service: "simple-tcp"
  ip: "10.0.1.100"
  port: 8080
  protocol: "tcp"
  auth_type: "none"          # No authentication
  tls_enabled: false         # No TLS termination

# Slow-path rule (Go application)
- service: "complex-web"
  ip: "10.0.1.200"
  port: 443
  protocol: "tcp"
  auth_type: "jwt"           # Requires authentication
  tls_enabled: true          # TLS termination
  websocket: true            # WebSocket support
```

#### Rule Ordering
Place high-traffic rules first in configuration for better performance.

### Connection Optimization

#### Connection Pooling
```bash
# Backend connection pooling
BACKEND_POOL_SIZE=100
BACKEND_POOL_TIMEOUT=30
BACKEND_KEEP_ALIVE=true
```

#### Connection Limits
```bash
# Per-service limits
SERVICE_MAX_CONNECTIONS=1000
SERVICE_CONNECTION_RATE=100

# Global limits
GLOBAL_MAX_CONNECTIONS=10000
GLOBAL_CONNECTION_RATE=1000
```

### Cache Optimization

#### Response Caching
```yaml
services:
  - name: "cached-api"
    cache_enabled: true
    cache_ttl: 300
    cache_vary: ["Authorization", "Content-Type"]
```

#### Connection State Caching
```bash
# eBPF map sizes
EBPF_CONN_MAP_SIZE=65536
EBPF_SERVICE_MAP_SIZE=1024
EBPF_STATS_MAP_SIZE=1024
```

## Hardware Recommendations

### Development Environment
- **CPU**: 4+ cores, 2.4+ GHz
- **Memory**: 8GB+ RAM
- **Network**: 1 Gbps NIC
- **Storage**: SSD recommended

### Production Environment
- **CPU**: 16+ cores, 3.0+ GHz, dedicated cores for DPDK
- **Memory**: 32GB+ RAM, hugepage support
- **Network**: 10/25/40 Gbps NICs with hardware acceleration
- **Storage**: NVMe SSD for logs and temporary data

### High-Performance Environment
- **CPU**: 32+ cores, 3.5+ GHz, NUMA awareness
- **Memory**: 64GB+ RAM, 1GB hugepages
- **Network**: 100 Gbps NICs with SR-IOV, DPDK support
- **Storage**: NVMe SSD array with high IOPS

## Troubleshooting Performance Issues

### Common Performance Problems

1. **Low Throughput**
   ```bash
   # Check acceleration status
   curl http://localhost:8080/admin/acceleration

   # Monitor CPU usage
   top -p $(pgrep marchproxy-proxy)

   # Check network utilization
   iftop -i eth0
   ```

2. **High Latency**
   ```bash
   # Check rule classification
   curl http://localhost:8080/admin/rules/classification

   # Monitor queue depths
   ss -i

   # Check backend connectivity
   curl http://localhost:8080/admin/backends/health
   ```

3. **Connection Issues**
   ```bash
   # Check connection limits
   ulimit -n

   # Monitor connection states
   ss -s

   # Check file descriptor usage
   lsof -p $(pgrep marchproxy-proxy) | wc -l
   ```

### Performance Debugging

#### Enable Debug Logging
```bash
LOG_LEVEL=debug
PROXY_DEBUG=true
```

#### Profile Application
```bash
# CPU profiling
curl http://localhost:8080/debug/pprof/profile?seconds=30

# Memory profiling
curl http://localhost:8080/debug/pprof/heap

# Goroutine profiling
curl http://localhost:8080/debug/pprof/goroutine
```

#### Monitor System Resources
```bash
# System statistics
iostat -x 1
vmstat 1
sar -u 1

# Network statistics
netstat -i
ip -s link show
```

---

Next: [Security Guide](security.md)