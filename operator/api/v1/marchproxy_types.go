/*
Copyright (C) 2025 MarchProxy Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// MarchProxySpec defines the desired state of MarchProxy
type MarchProxySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Manager configuration
	Manager ManagerSpec `json:"manager"`

	// Proxy configuration
	Proxy ProxySpec `json:"proxy"`

	// Database configuration
	Database DatabaseSpec `json:"database,omitempty"`

	// Redis configuration
	Redis RedisSpec `json:"redis,omitempty"`

	// Monitoring configuration
	Monitoring MonitoringSpec `json:"monitoring,omitempty"`

	// Security configuration
	Security SecuritySpec `json:"security,omitempty"`

	// TLS configuration
	TLS TLSSpec `json:"tls,omitempty"`

	// License configuration for Enterprise features
	License LicenseSpec `json:"license,omitempty"`
}

// ManagerSpec defines the manager component configuration
type ManagerSpec struct {
	// Number of manager replicas
	Replicas *int32 `json:"replicas,omitempty"`

	// Manager container image
	Image ImageSpec `json:"image"`

	// Manager service configuration
	Service ServiceSpec `json:"service,omitempty"`

	// Manager ingress configuration
	Ingress IngressSpec `json:"ingress,omitempty"`

	// Resource requirements
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Manager configuration
	Config ManagerConfig `json:"config,omitempty"`

	// Environment variables
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Volume mounts
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`

	// Volumes
	Volumes []corev1.Volume `json:"volumes,omitempty"`

	// Node selector
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
}

// ProxySpec defines the proxy component configuration
type ProxySpec struct {
	// Number of proxy replicas
	Replicas *int32 `json:"replicas,omitempty"`

	// Proxy container image
	Image ImageSpec `json:"image"`

	// Proxy service configuration
	Service ServiceSpec `json:"service,omitempty"`

	// Resource requirements
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Proxy configuration
	Config ProxyConfig `json:"config,omitempty"`

	// Environment variables
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Volume mounts
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`

	// Volumes
	Volumes []corev1.Volume `json:"volumes,omitempty"`

	// Security context
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`

	// Node selector
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
}

// ImageSpec defines container image configuration
type ImageSpec struct {
	// Image repository
	Repository string `json:"repository"`

	// Image tag
	Tag string `json:"tag,omitempty"`

	// Image pull policy
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`

	// Image pull secrets
	PullSecrets []corev1.LocalObjectReference `json:"pullSecrets,omitempty"`
}

// ServiceSpec defines service configuration
type ServiceSpec struct {
	// Service type
	Type corev1.ServiceType `json:"type,omitempty"`

	// Service ports
	Ports []corev1.ServicePort `json:"ports,omitempty"`

	// Service annotations
	Annotations map[string]string `json:"annotations,omitempty"`

	// Load balancer source ranges
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// Session affinity
	SessionAffinity corev1.ServiceAffinity `json:"sessionAffinity,omitempty"`
}

// IngressSpec defines ingress configuration
type IngressSpec struct {
	// Enable ingress
	Enabled bool `json:"enabled,omitempty"`

	// Ingress class name
	ClassName *string `json:"className,omitempty"`

	// Ingress annotations
	Annotations map[string]string `json:"annotations,omitempty"`

	// Ingress hosts
	Hosts []IngressHost `json:"hosts,omitempty"`

	// TLS configuration
	TLS []IngressTLS `json:"tls,omitempty"`
}

// IngressHost defines ingress host configuration
type IngressHost struct {
	// Host name
	Host string `json:"host"`

	// Paths
	Paths []IngressPath `json:"paths"`
}

// IngressPath defines ingress path configuration
type IngressPath struct {
	// Path
	Path string `json:"path"`

	// Path type
	PathType string `json:"pathType,omitempty"`

	// Backend service
	Backend IngressBackend `json:"backend"`
}

// IngressBackend defines ingress backend configuration
type IngressBackend struct {
	// Service name
	ServiceName string `json:"serviceName"`

	// Service port
	ServicePort int32 `json:"servicePort"`
}

// IngressTLS defines ingress TLS configuration
type IngressTLS struct {
	// Secret name
	SecretName string `json:"secretName,omitempty"`

	// Hosts
	Hosts []string `json:"hosts,omitempty"`
}

// DatabaseSpec defines database configuration
type DatabaseSpec struct {
	// External database configuration
	External *ExternalDatabaseSpec `json:"external,omitempty"`

	// Internal PostgreSQL configuration
	PostgreSQL *PostgreSQLSpec `json:"postgresql,omitempty"`
}

// ExternalDatabaseSpec defines external database configuration
type ExternalDatabaseSpec struct {
	// Database host
	Host string `json:"host"`

	// Database port
	Port int32 `json:"port,omitempty"`

	// Database name
	Database string `json:"database"`

	// Database username
	Username string `json:"username"`

	// Database password secret
	PasswordSecret string `json:"passwordSecret"`

	// SSL mode
	SSLMode string `json:"sslMode,omitempty"`
}

// PostgreSQLSpec defines internal PostgreSQL configuration
type PostgreSQLSpec struct {
	// Enable internal PostgreSQL
	Enabled bool `json:"enabled,omitempty"`

	// PostgreSQL image
	Image ImageSpec `json:"image,omitempty"`

	// Resource requirements
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Persistence configuration
	Persistence PersistenceSpec `json:"persistence,omitempty"`

	// PostgreSQL configuration
	Config map[string]string `json:"config,omitempty"`
}

// RedisSpec defines Redis configuration
type RedisSpec struct {
	// External Redis configuration
	External *ExternalRedisSpec `json:"external,omitempty"`

	// Internal Redis configuration
	Internal *InternalRedisSpec `json:"internal,omitempty"`
}

// ExternalRedisSpec defines external Redis configuration
type ExternalRedisSpec struct {
	// Redis host
	Host string `json:"host"`

	// Redis port
	Port int32 `json:"port,omitempty"`

	// Redis password secret
	PasswordSecret string `json:"passwordSecret,omitempty"`

	// Redis database number
	Database int32 `json:"database,omitempty"`
}

// InternalRedisSpec defines internal Redis configuration
type InternalRedisSpec struct {
	// Enable internal Redis
	Enabled bool `json:"enabled,omitempty"`

	// Redis image
	Image ImageSpec `json:"image,omitempty"`

	// Resource requirements
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Persistence configuration
	Persistence PersistenceSpec `json:"persistence,omitempty"`
}

// PersistenceSpec defines persistence configuration
type PersistenceSpec struct {
	// Enable persistence
	Enabled bool `json:"enabled,omitempty"`

	// Storage class
	StorageClass *string `json:"storageClass,omitempty"`

	// Access modes
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// Size
	Size string `json:"size,omitempty"`
}

// MonitoringSpec defines monitoring configuration
type MonitoringSpec struct {
	// Prometheus configuration
	Prometheus *PrometheusSpec `json:"prometheus,omitempty"`

	// Grafana configuration
	Grafana *GrafanaSpec `json:"grafana,omitempty"`

	// ServiceMonitor configuration
	ServiceMonitor *ServiceMonitorSpec `json:"serviceMonitor,omitempty"`
}

// PrometheusSpec defines Prometheus configuration
type PrometheusSpec struct {
	// Enable Prometheus
	Enabled bool `json:"enabled,omitempty"`

	// Prometheus image
	Image ImageSpec `json:"image,omitempty"`

	// Resource requirements
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Persistence configuration
	Persistence PersistenceSpec `json:"persistence,omitempty"`

	// Retention
	Retention string `json:"retention,omitempty"`
}

// GrafanaSpec defines Grafana configuration
type GrafanaSpec struct {
	// Enable Grafana
	Enabled bool `json:"enabled,omitempty"`

	// Grafana image
	Image ImageSpec `json:"image,omitempty"`

	// Resource requirements
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Persistence configuration
	Persistence PersistenceSpec `json:"persistence,omitempty"`

	// Admin password secret
	AdminPasswordSecret string `json:"adminPasswordSecret,omitempty"`
}

// ServiceMonitorSpec defines ServiceMonitor configuration
type ServiceMonitorSpec struct {
	// Enable ServiceMonitor
	Enabled bool `json:"enabled,omitempty"`

	// Additional labels
	AdditionalLabels map[string]string `json:"additionalLabels,omitempty"`

	// Scrape interval
	ScrapeInterval string `json:"scrapeInterval,omitempty"`
}

// SecuritySpec defines security configuration
type SecuritySpec struct {
	// Network policy configuration
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`

	// Pod security policy configuration
	PodSecurityPolicy *PodSecurityPolicySpec `json:"podSecurityPolicy,omitempty"`

	// Service account configuration
	ServiceAccount *ServiceAccountSpec `json:"serviceAccount,omitempty"`

	// RBAC configuration
	RBAC *RBACSpec `json:"rbac,omitempty"`
}

// NetworkPolicySpec defines network policy configuration
type NetworkPolicySpec struct {
	// Enable network policy
	Enabled bool `json:"enabled,omitempty"`

	// Ingress rules
	Ingress []NetworkPolicyIngressRule `json:"ingress,omitempty"`

	// Egress rules
	Egress []NetworkPolicyEgressRule `json:"egress,omitempty"`
}

// NetworkPolicyIngressRule defines network policy ingress rule
type NetworkPolicyIngressRule struct {
	// From
	From []NetworkPolicyPeer `json:"from,omitempty"`

	// Ports
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyEgressRule defines network policy egress rule
type NetworkPolicyEgressRule struct {
	// To
	To []NetworkPolicyPeer `json:"to,omitempty"`

	// Ports
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyPeer defines network policy peer
type NetworkPolicyPeer struct {
	// Namespace selector
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Pod selector
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// IP block
	IPBlock *NetworkPolicyIPBlock `json:"ipBlock,omitempty"`
}

// NetworkPolicyIPBlock defines network policy IP block
type NetworkPolicyIPBlock struct {
	// CIDR
	CIDR string `json:"cidr"`

	// Except
	Except []string `json:"except,omitempty"`
}

// NetworkPolicyPort defines network policy port
type NetworkPolicyPort struct {
	// Protocol
	Protocol *corev1.Protocol `json:"protocol,omitempty"`

	// Port
	Port *int32 `json:"port,omitempty"`

	// End port
	EndPort *int32 `json:"endPort,omitempty"`
}

// PodSecurityPolicySpec defines pod security policy configuration
type PodSecurityPolicySpec struct {
	// Enable pod security policy
	Enabled bool `json:"enabled,omitempty"`
}

// ServiceAccountSpec defines service account configuration
type ServiceAccountSpec struct {
	// Create service account
	Create bool `json:"create,omitempty"`

	// Service account name
	Name string `json:"name,omitempty"`

	// Annotations
	Annotations map[string]string `json:"annotations,omitempty"`
}

// RBACSpec defines RBAC configuration
type RBACSpec struct {
	// Create RBAC resources
	Create bool `json:"create,omitempty"`
}

// TLSSpec defines TLS configuration
type TLSSpec struct {
	// Enable TLS
	Enabled bool `json:"enabled,omitempty"`

	// Certificate manager configuration
	CertManager *CertManagerSpec `json:"certManager,omitempty"`

	// Manual certificate configuration
	Manual *ManualTLSSpec `json:"manual,omitempty"`
}

// CertManagerSpec defines cert-manager configuration
type CertManagerSpec struct {
	// Enable cert-manager
	Enabled bool `json:"enabled,omitempty"`

	// Cluster issuer
	ClusterIssuer string `json:"clusterIssuer,omitempty"`

	// Issuer
	Issuer string `json:"issuer,omitempty"`
}

// ManualTLSSpec defines manual TLS configuration
type ManualTLSSpec struct {
	// Certificate secret name
	SecretName string `json:"secretName"`
}

// LicenseSpec defines license configuration
type LicenseSpec struct {
	// License key secret
	KeySecret string `json:"keySecret,omitempty"`

	// License server URL
	ServerURL string `json:"serverURL,omitempty"`

	// Product name
	Product string `json:"product,omitempty"`
}

// ManagerConfig defines manager configuration
type ManagerConfig struct {
	// Log level
	LogLevel string `json:"logLevel,omitempty"`

	// Cluster mode
	ClusterMode string `json:"clusterMode,omitempty"`

	// Prometheus enabled
	PrometheusEnabled bool `json:"prometheusEnabled,omitempty"`

	// Health check enabled
	HealthCheckEnabled bool `json:"healthCheckEnabled,omitempty"`

	// Additional configuration
	Additional map[string]string `json:"additional,omitempty"`
}

// ProxyConfig defines proxy configuration
type ProxyConfig struct {
	// Log level
	LogLevel string `json:"logLevel,omitempty"`

	// Proxy mode
	ProxyMode string `json:"proxyMode,omitempty"`

	// Enable eBPF
	EnableEBPF bool `json:"enableEBPF,omitempty"`

	// Enable hardware acceleration
	EnableHardwareAcceleration bool `json:"enableHardwareAcceleration,omitempty"`

	// Prometheus enabled
	PrometheusEnabled bool `json:"prometheusEnabled,omitempty"`

	// Health check enabled
	HealthCheckEnabled bool `json:"healthCheckEnabled,omitempty"`

	// Config refresh interval
	ConfigRefreshInterval string `json:"configRefreshInterval,omitempty"`

	// GOMAXPROCS
	GOMAXPROCS string `json:"gomaxprocs,omitempty"`

	// Additional configuration
	Additional map[string]string `json:"additional,omitempty"`
}

// MarchProxyStatus defines the observed state of MarchProxy
type MarchProxyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Phase represents the current phase of the MarchProxy deployment
	Phase string `json:"phase,omitempty"`

	// Conditions represent the latest available observations of an object's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Manager status
	Manager ComponentStatus `json:"manager,omitempty"`

	// Proxy status
	Proxy ComponentStatus `json:"proxy,omitempty"`

	// Database status
	Database ComponentStatus `json:"database,omitempty"`

	// Redis status
	Redis ComponentStatus `json:"redis,omitempty"`

	// Monitoring status
	Monitoring MonitoringStatus `json:"monitoring,omitempty"`

	// Observed generation
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ComponentStatus defines the status of a component
type ComponentStatus struct {
	// Ready replicas
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Total replicas
	Replicas int32 `json:"replicas,omitempty"`

	// Service endpoint
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// Last update time
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`
}

// MonitoringStatus defines the monitoring status
type MonitoringStatus struct {
	// Prometheus status
	Prometheus ComponentStatus `json:"prometheus,omitempty"`

	// Grafana status
	Grafana ComponentStatus `json:"grafana,omitempty"`

	// ServiceMonitor created
	ServiceMonitorCreated bool `json:"serviceMonitorCreated,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=mp
//+kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="Manager Ready",type=string,JSONPath=`.status.manager.readyReplicas`
//+kubebuilder:printcolumn:name="Proxy Ready",type=string,JSONPath=`.status.proxy.readyReplicas`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MarchProxy is the Schema for the marchproxies API
type MarchProxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MarchProxySpec   `json:"spec,omitempty"`
	Status MarchProxyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// MarchProxyList contains a list of MarchProxy
type MarchProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MarchProxy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MarchProxy{}, &MarchProxyList{})
}