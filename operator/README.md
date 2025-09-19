# MarchProxy Kubernetes Operator

A Kubernetes operator for managing MarchProxy deployments, providing a declarative way to deploy and manage MarchProxy clusters without Helm.

## Overview

The MarchProxy Operator provides:
- Declarative MarchProxy deployment management
- Automatic rolling updates and health monitoring
- Integration with Kubernetes-native tools and GitOps workflows
- Fine-grained control over proxy configurations
- Multi-cluster support for Enterprise deployments

## Installation

### Prerequisites

- Kubernetes 1.19+
- Cluster admin privileges for CRD installation

### Quick Start

1. Install the Custom Resource Definitions:
```bash
kubectl apply -f config/crd/
```

2. Install the operator:
```bash
kubectl apply -f config/manager/
```

3. Create a MarchProxy instance:
```bash
kubectl apply -f examples/simple-marchproxy.yaml
```

## Custom Resources

### MarchProxy

The `MarchProxy` custom resource defines a complete MarchProxy deployment:

```yaml
apiVersion: proxy.marchproxy.io/v1
kind: MarchProxy
metadata:
  name: marchproxy-sample
  namespace: marchproxy
spec:
  manager:
    replicas: 2
    image:
      repository: marchproxy/manager
      tag: v1.0.0
      pullPolicy: IfNotPresent
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"
    config:
      logLevel: "info"
      clusterMode: "enterprise"
  proxy:
    replicas: 3
    image:
      repository: marchproxy/proxy
      tag: v1.0.0
      pullPolicy: IfNotPresent
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "1Gi"
        cpu: "1000m"
    config:
      enableEBPF: true
      enableHardwareAcceleration: false
  database:
    postgresql:
      enabled: true
      persistence:
        enabled: true
        size: 20Gi
  redis:
    internal:
      enabled: true
      persistence:
        enabled: true
        size: 8Gi
  monitoring:
    prometheus:
      enabled: true
    grafana:
      enabled: true
  security:
    networkPolicy:
      enabled: true
    rbac:
      create: true
  tls:
    enabled: true
    certManager:
      enabled: true
      clusterIssuer: "letsencrypt-prod"
```

## Examples

### Community Edition Deployment

```yaml
apiVersion: proxy.marchproxy.io/v1
kind: MarchProxy
metadata:
  name: marchproxy-community
  namespace: marchproxy
spec:
  manager:
    replicas: 1
    image:
      repository: marchproxy/manager
      tag: v1.0.0
    config:
      clusterMode: "community"
  proxy:
    replicas: 2  # Community limit: 3 proxies max
    image:
      repository: marchproxy/proxy
      tag: v1.0.0
    config:
      enableEBPF: true
  database:
    postgresql:
      enabled: true
  redis:
    internal:
      enabled: true
```

### Enterprise Multi-Cluster Deployment

```yaml
apiVersion: proxy.marchproxy.io/v1
kind: MarchProxy
metadata:
  name: marchproxy-enterprise
  namespace: marchproxy
spec:
  manager:
    replicas: 3
    image:
      repository: marchproxy/manager
      tag: v1.0.0
    config:
      clusterMode: "enterprise"
  proxy:
    replicas: 10  # Enterprise: unlimited based on license
    image:
      repository: marchproxy/proxy
      tag: v1.0.0
    config:
      enableEBPF: true
      enableHardwareAcceleration: true
  license:
    keySecret: "marchproxy-license"
    serverURL: "https://license.penguintech.io"
    product: "marchproxy"
  monitoring:
    prometheus:
      enabled: true
      server:
        retention: "30d"
        persistentVolume:
          size: 100Gi
    grafana:
      enabled: true
```

### High-Performance Deployment with Hardware Acceleration

```yaml
apiVersion: proxy.marchproxy.io/v1
kind: MarchProxy
metadata:
  name: marchproxy-highperf
  namespace: marchproxy
spec:
  proxy:
    replicas: 5
    image:
      repository: marchproxy/proxy
      tag: v1.0.0
    config:
      enableEBPF: true
      enableHardwareAcceleration: true
    resources:
      requests:
        memory: "2Gi"
        cpu: "2000m"
      limits:
        memory: "4Gi"
        cpu: "4000m"
    nodeSelector:
      marchproxy/hardware-acceleration: "enabled"
    tolerations:
    - key: "marchproxy/performance"
      operator: "Equal"
      value: "high"
      effect: "NoSchedule"
```

## Operator Features

### Declarative Management
- Full lifecycle management through Kubernetes manifests
- GitOps-friendly declarative configuration
- Automatic drift detection and remediation

### Health Monitoring
- Automatic health checks and readiness probes
- Integration with Kubernetes health monitoring
- Automatic restart and recovery on failures

### Rolling Updates
- Zero-downtime rolling updates
- Configurable update strategies
- Automatic rollback on failures

### Resource Management
- Automatic resource scaling based on configuration
- Integration with Horizontal Pod Autoscaler
- Resource limit enforcement

### Security Integration
- Network policy automatic creation
- RBAC integration
- Pod security policy support
- TLS certificate management

## Monitoring

The operator exposes metrics compatible with Prometheus:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: marchproxy-operator
spec:
  selector:
    matchLabels:
      app: marchproxy-operator
  endpoints:
  - port: metrics
```

## Status and Conditions

The operator maintains detailed status information:

```bash
kubectl get marchproxy -o wide
NAME                 PHASE     MANAGER READY   PROXY READY   AGE
marchproxy-sample   Running   2               3             5m
```

Detailed status:
```bash
kubectl describe marchproxy marchproxy-sample
```

## Troubleshooting

### Common Issues

1. **CRD Installation Failures**
   ```bash
   kubectl get crd marchproxies.proxy.marchproxy.io
   ```

2. **Operator Pod Issues**
   ```bash
   kubectl logs -n marchproxy-operator-system deployment/marchproxy-operator-controller-manager
   ```

3. **Resource Status**
   ```bash
   kubectl get marchproxy marchproxy-sample -o yaml
   ```

### Debug Mode

Enable debug logging:
```yaml
spec:
  manager:
    config:
      logLevel: "debug"
  proxy:
    config:
      logLevel: "debug"
```

## Development

### Building the Operator

```bash
make docker-build IMG=marchproxy/operator:dev
```

### Running Tests

```bash
make test
```

### Generating CRDs

```bash
make manifests
```

## License

This operator is licensed under the GNU Affero General Public License v3.0. See [LICENSE](../LICENSE) for details.

## Contributing

Please read our [contributing guidelines](../docs/development/) before submitting pull requests.

## Support

- GitHub Issues: https://github.com/marchproxy/marchproxy/issues
- Documentation: https://docs.marchproxy.io
- Community: https://community.marchproxy.io