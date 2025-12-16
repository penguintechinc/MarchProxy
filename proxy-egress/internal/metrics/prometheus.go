package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"marchproxy-egress/internal/killkrill"
)

type PrometheusMetrics struct {
	registry *prometheus.Registry
	
	// Request metrics
	requestsTotal      *prometheus.CounterVec
	requestDuration    *prometheus.HistogramVec
	requestSize        *prometheus.HistogramVec
	responseSize       *prometheus.HistogramVec
	
	// Proxy metrics
	activeConnections  prometheus.Gauge
	upstreamRequests   *prometheus.CounterVec
	upstreamDuration   *prometheus.HistogramVec
	upstreamErrors     *prometheus.CounterVec
	
	// Load balancing metrics
	loadBalancerRequests *prometheus.CounterVec
	backendHealth       *prometheus.GaugeVec
	backendConnections  *prometheus.GaugeVec
	
	// Circuit breaker metrics
	circuitBreakerState    *prometheus.GaugeVec
	circuitBreakerRequests *prometheus.CounterVec
	circuitBreakerFailures *prometheus.CounterVec
	
	// Cache metrics
	cacheRequests      *prometheus.CounterVec
	cacheHitRatio      *prometheus.GaugeVec
	cacheSize          prometheus.Gauge
	cacheOperations    *prometheus.CounterVec
	
	// Rate limiting metrics
	rateLimitRequests  *prometheus.CounterVec
	rateLimitBlocked   *prometheus.CounterVec
	rateLimitQuota     *prometheus.GaugeVec
	
	// Security metrics
	wafRequests        *prometheus.CounterVec
	wafBlocked         *prometheus.CounterVec
	tlsHandshakes      *prometheus.CounterVec
	authAttempts       *prometheus.CounterVec
	
	// System metrics
	goroutines         prometheus.Gauge
	memoryUsage        prometheus.Gauge
	cpuUsage           prometheus.Gauge
	openFiles          prometheus.Gauge
	
	// Custom metrics
	customMetrics      map[string]prometheus.Collector
	mutex              sync.RWMutex
}

type MetricsConfig struct {
	Namespace       string
	Subsystem       string
	EnabledMetrics  []string
	CustomLabels    map[string]string
	HistogramBuckets []float64
	CollectionInterval time.Duration
	ExposeGoMetrics    bool
	ExposeProcessMetrics bool
	KillKrillConfig *killkrill.Config
}

type MetricsCollector struct {
	prometheus      *PrometheusMetrics
	config          MetricsConfig
	collectors      []Collector
	server          *http.Server
	enabled         bool
	mutex           sync.RWMutex
	killKrillClient *killkrill.Client
}

type Collector interface {
	Collect() error
	Name() string
	Enabled() bool
}

type SystemCollector struct {
	goroutines *prometheus.GaugeFunc
	memory     *prometheus.GaugeFunc
	cpu        *prometheus.GaugeFunc
	files      *prometheus.GaugeFunc
}

type ProxyCollector struct {
	metrics *PrometheusMetrics
	proxies map[string]*ProxyStats
	mutex   sync.RWMutex
}

type ProxyStats struct {
	Requests         uint64
	Responses        uint64
	Errors           uint64
	BytesSent        uint64
	BytesReceived    uint64
	AverageLatency   time.Duration
	ActiveConnections int64
}

func NewPrometheusMetrics(config MetricsConfig) *PrometheusMetrics {
	registry := prometheus.NewRegistry()
	
	if config.Namespace == "" {
		config.Namespace = "marchproxy"
	}
	
	if len(config.HistogramBuckets) == 0 {
		config.HistogramBuckets = prometheus.DefBuckets
	}
	
	pm := &PrometheusMetrics{
		registry:      registry,
		customMetrics: make(map[string]prometheus.Collector),
	}
	
	pm.initializeMetrics(config)
	pm.registerMetrics()
	
	return pm
}

func (pm *PrometheusMetrics) initializeMetrics(config MetricsConfig) {
	// Request metrics
	pm.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status_code", "backend"},
	)
	
	pm.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: config.Namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   config.HistogramBuckets,
		},
		[]string{"method", "path", "backend"},
	)
	
	pm.requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: config.Namespace,
			Subsystem: "http",
			Name:      "request_size_bytes",
			Help:      "HTTP request size in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"method", "path"},
	)
	
	pm.responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: config.Namespace,
			Subsystem: "http",
			Name:      "response_size_bytes",
			Help:      "HTTP response size in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		},
		[]string{"method", "path", "status_code"},
	)
	
	// Proxy metrics
	pm.activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "proxy",
			Name:      "active_connections",
			Help:      "Number of active proxy connections",
		},
	)
	
	pm.upstreamRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "upstream",
			Name:      "requests_total",
			Help:      "Total upstream requests",
		},
		[]string{"backend", "status"},
	)
	
	pm.upstreamDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: config.Namespace,
			Subsystem: "upstream",
			Name:      "request_duration_seconds",
			Help:      "Upstream request duration in seconds",
			Buckets:   config.HistogramBuckets,
		},
		[]string{"backend"},
	)
	
	pm.upstreamErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "upstream",
			Name:      "errors_total",
			Help:      "Total upstream errors",
		},
		[]string{"backend", "error_type"},
	)
	
	// Load balancing metrics
	pm.loadBalancerRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "loadbalancer",
			Name:      "requests_total",
			Help:      "Total load balancer requests",
		},
		[]string{"algorithm", "backend"},
	)
	
	pm.backendHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "backend",
			Name:      "health_status",
			Help:      "Backend health status (1=healthy, 0=unhealthy)",
		},
		[]string{"backend", "host", "port"},
	)
	
	pm.backendConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "backend",
			Name:      "active_connections",
			Help:      "Number of active connections to backend",
		},
		[]string{"backend", "host", "port"},
	)
	
	// Circuit breaker metrics
	pm.circuitBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "circuitbreaker",
			Name:      "state",
			Help:      "Circuit breaker state (0=closed, 1=open, 2=half-open)",
		},
		[]string{"backend"},
	)
	
	pm.circuitBreakerRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "circuitbreaker",
			Name:      "requests_total",
			Help:      "Total circuit breaker requests",
		},
		[]string{"backend", "result"},
	)
	
	pm.circuitBreakerFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "circuitbreaker",
			Name:      "failures_total",
			Help:      "Total circuit breaker failures",
		},
		[]string{"backend"},
	)
	
	// Cache metrics
	pm.cacheRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "cache",
			Name:      "requests_total",
			Help:      "Total cache requests",
		},
		[]string{"store", "result"},
	)
	
	pm.cacheHitRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "cache",
			Name:      "hit_ratio",
			Help:      "Cache hit ratio",
		},
		[]string{"store"},
	)
	
	pm.cacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "cache",
			Name:      "size_bytes",
			Help:      "Cache size in bytes",
		},
	)
	
	pm.cacheOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "cache",
			Name:      "operations_total",
			Help:      "Total cache operations",
		},
		[]string{"operation", "store"},
	)
	
	// Rate limiting metrics
	pm.rateLimitRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "ratelimit",
			Name:      "requests_total",
			Help:      "Total rate limit requests",
		},
		[]string{"client_type", "result"},
	)
	
	pm.rateLimitBlocked = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "ratelimit",
			Name:      "blocked_total",
			Help:      "Total rate limit blocks",
		},
		[]string{"client_type", "reason"},
	)
	
	pm.rateLimitQuota = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "ratelimit",
			Name:      "quota_remaining",
			Help:      "Remaining rate limit quota",
		},
		[]string{"client_id"},
	)
	
	// Security metrics
	pm.wafRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "waf",
			Name:      "requests_total",
			Help:      "Total WAF requests",
		},
		[]string{"action", "rule_category"},
	)
	
	pm.wafBlocked = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "waf",
			Name:      "blocked_total",
			Help:      "Total WAF blocks",
		},
		[]string{"rule_category", "severity"},
	)
	
	pm.tlsHandshakes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "tls",
			Name:      "handshakes_total",
			Help:      "Total TLS handshakes",
		},
		[]string{"version", "cipher", "result"},
	)
	
	pm.authAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: "auth",
			Name:      "attempts_total",
			Help:      "Total authentication attempts",
		},
		[]string{"method", "result"},
	)
	
	// System metrics
	pm.goroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "system",
			Name:      "goroutines",
			Help:      "Number of goroutines",
		},
	)
	
	pm.memoryUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "system",
			Name:      "memory_bytes",
			Help:      "Memory usage in bytes",
		},
	)
	
	pm.cpuUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "system",
			Name:      "cpu_usage_percent",
			Help:      "CPU usage percentage",
		},
	)
	
	pm.openFiles = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: "system",
			Name:      "open_files",
			Help:      "Number of open files",
		},
	)
}

func (pm *PrometheusMetrics) registerMetrics() {
	pm.registry.MustRegister(
		pm.requestsTotal,
		pm.requestDuration,
		pm.requestSize,
		pm.responseSize,
		pm.activeConnections,
		pm.upstreamRequests,
		pm.upstreamDuration,
		pm.upstreamErrors,
		pm.loadBalancerRequests,
		pm.backendHealth,
		pm.backendConnections,
		pm.circuitBreakerState,
		pm.circuitBreakerRequests,
		pm.circuitBreakerFailures,
		pm.cacheRequests,
		pm.cacheHitRatio,
		pm.cacheSize,
		pm.cacheOperations,
		pm.rateLimitRequests,
		pm.rateLimitBlocked,
		pm.rateLimitQuota,
		pm.wafRequests,
		pm.wafBlocked,
		pm.tlsHandshakes,
		pm.authAttempts,
		pm.goroutines,
		pm.memoryUsage,
		pm.cpuUsage,
		pm.openFiles,
	)
}

// Request metrics methods
func (pm *PrometheusMetrics) RecordRequest(method, path, statusCode, backend string) {
	pm.requestsTotal.WithLabelValues(method, path, statusCode, backend).Inc()
}

func (pm *PrometheusMetrics) RecordRequestDuration(method, path, backend string, duration time.Duration) {
	pm.requestDuration.WithLabelValues(method, path, backend).Observe(duration.Seconds())
}

func (pm *PrometheusMetrics) RecordRequestSize(method, path string, size int64) {
	pm.requestSize.WithLabelValues(method, path).Observe(float64(size))
}

func (pm *PrometheusMetrics) RecordResponseSize(method, path, statusCode string, size int64) {
	pm.responseSize.WithLabelValues(method, path, statusCode).Observe(float64(size))
}

// Proxy metrics methods
func (pm *PrometheusMetrics) SetActiveConnections(count int) {
	pm.activeConnections.Set(float64(count))
}

func (pm *PrometheusMetrics) RecordUpstreamRequest(backend, status string) {
	pm.upstreamRequests.WithLabelValues(backend, status).Inc()
}

func (pm *PrometheusMetrics) RecordUpstreamDuration(backend string, duration time.Duration) {
	pm.upstreamDuration.WithLabelValues(backend).Observe(duration.Seconds())
}

func (pm *PrometheusMetrics) RecordUpstreamError(backend, errorType string) {
	pm.upstreamErrors.WithLabelValues(backend, errorType).Inc()
}

// Load balancer metrics methods
func (pm *PrometheusMetrics) RecordLoadBalancerRequest(algorithm, backend string) {
	pm.loadBalancerRequests.WithLabelValues(algorithm, backend).Inc()
}

func (pm *PrometheusMetrics) SetBackendHealth(backend, host, port string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	pm.backendHealth.WithLabelValues(backend, host, port).Set(value)
}

func (pm *PrometheusMetrics) SetBackendConnections(backend, host, port string, count int) {
	pm.backendConnections.WithLabelValues(backend, host, port).Set(float64(count))
}

// Circuit breaker metrics methods
func (pm *PrometheusMetrics) SetCircuitBreakerState(backend string, state int) {
	pm.circuitBreakerState.WithLabelValues(backend).Set(float64(state))
}

func (pm *PrometheusMetrics) RecordCircuitBreakerRequest(backend, result string) {
	pm.circuitBreakerRequests.WithLabelValues(backend, result).Inc()
}

func (pm *PrometheusMetrics) RecordCircuitBreakerFailure(backend string) {
	pm.circuitBreakerFailures.WithLabelValues(backend).Inc()
}

// Cache metrics methods
func (pm *PrometheusMetrics) RecordCacheRequest(store, result string) {
	pm.cacheRequests.WithLabelValues(store, result).Inc()
}

func (pm *PrometheusMetrics) SetCacheHitRatio(store string, ratio float64) {
	pm.cacheHitRatio.WithLabelValues(store).Set(ratio)
}

func (pm *PrometheusMetrics) SetCacheSize(size int64) {
	pm.cacheSize.Set(float64(size))
}

func (pm *PrometheusMetrics) RecordCacheOperation(operation, store string) {
	pm.cacheOperations.WithLabelValues(operation, store).Inc()
}

// Rate limit metrics methods
func (pm *PrometheusMetrics) RecordRateLimitRequest(clientType, result string) {
	pm.rateLimitRequests.WithLabelValues(clientType, result).Inc()
}

func (pm *PrometheusMetrics) RecordRateLimitBlock(clientType, reason string) {
	pm.rateLimitBlocked.WithLabelValues(clientType, reason).Inc()
}

func (pm *PrometheusMetrics) SetRateLimitQuota(clientID string, remaining int64) {
	pm.rateLimitQuota.WithLabelValues(clientID).Set(float64(remaining))
}

// Security metrics methods
func (pm *PrometheusMetrics) RecordWAFRequest(action, ruleCategory string) {
	pm.wafRequests.WithLabelValues(action, ruleCategory).Inc()
}

func (pm *PrometheusMetrics) RecordWAFBlock(ruleCategory, severity string) {
	pm.wafBlocked.WithLabelValues(ruleCategory, severity).Inc()
}

func (pm *PrometheusMetrics) RecordTLSHandshake(version, cipher, result string) {
	pm.tlsHandshakes.WithLabelValues(version, cipher, result).Inc()
}

func (pm *PrometheusMetrics) RecordAuthAttempt(method, result string) {
	pm.authAttempts.WithLabelValues(method, result).Inc()
}

// System metrics methods
func (pm *PrometheusMetrics) SetGoroutines(count int) {
	pm.goroutines.Set(float64(count))
}

func (pm *PrometheusMetrics) SetMemoryUsage(bytes int64) {
	pm.memoryUsage.Set(float64(bytes))
}

func (pm *PrometheusMetrics) SetCPUUsage(percent float64) {
	pm.cpuUsage.Set(percent)
}

func (pm *PrometheusMetrics) SetOpenFiles(count int) {
	pm.openFiles.Set(float64(count))
}

// Custom metrics
func (pm *PrometheusMetrics) AddCustomMetric(name string, collector prometheus.Collector) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	pm.customMetrics[name] = collector
	pm.registry.MustRegister(collector)
}

func (pm *PrometheusMetrics) GetRegistry() *prometheus.Registry {
	return pm.registry
}

func NewMetricsCollector(config MetricsConfig) *MetricsCollector {
	mc := &MetricsCollector{
		prometheus: NewPrometheusMetrics(config),
		config:     config,
		collectors: make([]Collector, 0),
		enabled:    true,
	}

	// Initialize KillKrill client if config provided
	if config.KillKrillConfig != nil {
		killKrillClient, err := killkrill.NewClient(*config.KillKrillConfig)
		if err != nil {
			// Log error but don't fail initialization
			// TODO: Use proper logging here
		} else {
			mc.killKrillClient = killKrillClient
		}
	}

	if config.ExposeGoMetrics {
		mc.prometheus.registry.MustRegister(prometheus.NewGoCollector())
	}

	if config.ExposeProcessMetrics {
		mc.prometheus.registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	}

	mc.addDefaultCollectors()
	return mc
}

func (mc *MetricsCollector) addDefaultCollectors() {
	systemCollector := NewSystemCollector(mc.prometheus)
	mc.collectors = append(mc.collectors, systemCollector)
	
	proxyCollector := NewProxyCollector(mc.prometheus)
	mc.collectors = append(mc.collectors, proxyCollector)
}

func (mc *MetricsCollector) StartCollection() {
	if mc.config.CollectionInterval == 0 {
		mc.config.CollectionInterval = 15 * time.Second
	}
	
	ticker := time.NewTicker(mc.config.CollectionInterval)
	go func() {
		for range ticker.C {
			mc.collectMetrics()
		}
	}()
}

func (mc *MetricsCollector) collectMetrics() {
	if !mc.enabled {
		return
	}

	for _, collector := range mc.collectors {
		if collector.Enabled() {
			collector.Collect()
		}
	}

	// Export metrics to KillKrill if configured
	mc.exportToKillKrill()
}

// exportToKillKrill exports metrics to KillKrill
func (mc *MetricsCollector) exportToKillKrill() {
	if mc.killKrillClient == nil || !mc.config.KillKrillConfig.Enabled {
		return
	}

	// Gather all metrics from the Prometheus registry
	metrics, err := killkrill.GatherMetricsFromRegistry(mc.prometheus.registry)
	if err != nil {
		// TODO: Use proper logging
		return
	}

	// Send each metric to KillKrill
	for _, metric := range metrics {
		mc.killKrillClient.SendMetric(metric)
	}
}

func (mc *MetricsCollector) StartServer(addr string) error {
	handler := promhttp.HandlerFor(mc.prometheus.registry, promhttp.HandlerOpts{})
	
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	mc.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	
	return mc.server.ListenAndServe()
}

func (mc *MetricsCollector) StopServer(ctx context.Context) error {
	if mc.server != nil {
		return mc.server.Shutdown(ctx)
	}
	return nil
}

// Close shuts down the metrics collector and its KillKrill client
func (mc *MetricsCollector) Close() error {
	if mc.killKrillClient != nil {
		return mc.killKrillClient.Close()
	}
	return nil
}

func (mc *MetricsCollector) GetPrometheus() *PrometheusMetrics {
	return mc.prometheus
}

func (mc *MetricsCollector) Enable() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	mc.enabled = true
}

func (mc *MetricsCollector) Disable() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	mc.enabled = false
}

func NewSystemCollector(metrics *PrometheusMetrics) *SystemCollector {
	return &SystemCollector{}
}

func (sc *SystemCollector) Collect() error {
	return nil
}

func (sc *SystemCollector) Name() string {
	return "system"
}

func (sc *SystemCollector) Enabled() bool {
	return true
}

func NewProxyCollector(metrics *PrometheusMetrics) *ProxyCollector {
	return &ProxyCollector{
		metrics: metrics,
		proxies: make(map[string]*ProxyStats),
	}
}

func (pc *ProxyCollector) Collect() error {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()
	
	totalConnections := int64(0)
	for _, stats := range pc.proxies {
		totalConnections += stats.ActiveConnections
	}
	
	pc.metrics.SetActiveConnections(int(totalConnections))
	return nil
}

func (pc *ProxyCollector) Name() string {
	return "proxy"
}

func (pc *ProxyCollector) Enabled() bool {
	return true
}

func (pc *ProxyCollector) UpdateProxyStats(name string, stats *ProxyStats) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	pc.proxies[name] = stats
}

func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Namespace:          "marchproxy",
		CollectionInterval: 15 * time.Second,
		HistogramBuckets:   prometheus.DefBuckets,
		ExposeGoMetrics:    true,
		ExposeProcessMetrics: true,
		EnabledMetrics:     []string{"all"},
	}
}

type MetricsMiddleware struct {
	metrics *PrometheusMetrics
	enabled bool
}

func NewMetricsMiddleware(metrics *PrometheusMetrics) *MetricsMiddleware {
	return &MetricsMiddleware{
		metrics: metrics,
		enabled: true,
	}
}

func (mm *MetricsMiddleware) RecordHTTPMetrics(method, path, statusCode, backend string, duration time.Duration, requestSize, responseSize int64) {
	if !mm.enabled {
		return
	}
	
	mm.metrics.RecordRequest(method, path, statusCode, backend)
	mm.metrics.RecordRequestDuration(method, path, backend, duration)
	mm.metrics.RecordRequestSize(method, path, requestSize)
	mm.metrics.RecordResponseSize(method, path, statusCode, responseSize)
}

func (mm *MetricsMiddleware) Enable() {
	mm.enabled = true
}

func (mm *MetricsMiddleware) Disable() {
	mm.enabled = false
}