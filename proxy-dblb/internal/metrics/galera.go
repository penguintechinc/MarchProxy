package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Galera cluster metrics
	galeraNodeState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "node_state",
			Help:      "Current state of Galera cluster node (0-6)",
		},
		[]string{"node"},
	)

	galeraNodeReady = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "node_ready",
			Help:      "Whether Galera node is ready (1=ready, 0=not ready)",
		},
		[]string{"node"},
	)

	galeraClusterSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "cluster_size",
			Help:      "Number of nodes in Galera cluster",
		},
		[]string{"node"},
	)

	galeraFlowControl = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "flow_control_paused",
			Help:      "Whether node is in flow control pause (1=paused, 0=active)",
		},
		[]string{"node"},
	)

	galeraNodeErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "node_errors_total",
			Help:      "Total number of errors connecting to Galera node",
		},
		[]string{"node"},
	)

	galeraConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "connections",
			Help:      "Current number of active connections to Galera cluster",
		},
		[]string{"protocol"},
	)

	galeraQueries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "queries_total",
			Help:      "Total number of queries processed by Galera handler",
		},
		[]string{"protocol", "type"},
	)

	galeraSQLInjections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "marchproxy_dblb",
			Subsystem: "galera",
			Name:      "sql_injections_total",
			Help:      "Total number of SQL injection attempts blocked",
		},
		[]string{"protocol"},
	)

	// Mutex for thread-safe metric updates
	metricsLock sync.RWMutex
)

// SetGaleraNodeState sets the current state of a Galera node
func SetGaleraNodeState(node string, state int) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraNodeState.WithLabelValues(node).Set(float64(state))
}

// SetGaleraNodeReady sets whether a Galera node is ready
func SetGaleraNodeReady(node string, ready bool) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	value := 0.0
	if ready {
		value = 1.0
	}
	galeraNodeReady.WithLabelValues(node).Set(value)
}

// SetGaleraClusterSize sets the cluster size for a node
func SetGaleraClusterSize(node string, size float64) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraClusterSize.WithLabelValues(node).Set(size)
}

// SetGaleraFlowControl sets the flow control status for a node
func SetGaleraFlowControl(node string, paused bool) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	value := 0.0
	if paused {
		value = 1.0
	}
	galeraFlowControl.WithLabelValues(node).Set(value)
}

// IncGaleraNodeErrors increments the error counter for a node
func IncGaleraNodeErrors(node string) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraNodeErrors.WithLabelValues(node).Inc()
}

// IncConnection increments the active connection counter
func IncConnection(protocol string) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraConnections.WithLabelValues(protocol).Inc()
}

// DecConnection decrements the active connection counter
func DecConnection(protocol string) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraConnections.WithLabelValues(protocol).Dec()
}

// IncQuery increments the query counter
func IncQuery(protocol string, isWrite bool) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	queryType := "read"
	if isWrite {
		queryType = "write"
	}
	galeraQueries.WithLabelValues(protocol, queryType).Inc()
}

// IncSQLInjection increments the SQL injection counter
func IncSQLInjection(protocol string) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraSQLInjections.WithLabelValues(protocol).Inc()
}

// Additional metrics for handler support

var (
	authFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "marchproxy_dblb",
			Name:      "auth_failures_total",
			Help:      "Total number of authentication failures",
		},
		[]string{"protocol", "user"},
	)

	authSuccesses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "marchproxy_dblb",
			Name:      "auth_successes_total",
			Help:      "Total number of successful authentications",
		},
		[]string{"protocol", "user"},
	)

	bytesTransferred = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "marchproxy_dblb",
			Name:      "bytes_transferred_total",
			Help:      "Total bytes transferred",
		},
		[]string{"protocol", "direction"},
	)
)

// IncAuthFailure increments authentication failure counter
func IncAuthFailure(protocol string, user string) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	authFailures.WithLabelValues(protocol, user).Inc()
}

// IncAuthSuccess increments successful authentication counter
func IncAuthSuccess(protocol string, user string) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	authSuccesses.WithLabelValues(protocol, user).Inc()
}

// AddBytesTransferred adds to bytes transferred counter
func AddBytesTransferred(protocol string, direction string, bytes int64) {
	metricsLock.Lock()
	defer metricsLock.Unlock()
	bytesTransferred.WithLabelValues(protocol, direction).Add(float64(bytes))
}

// RecordBytesTransferred is an alias for AddBytesTransferred for compatibility
func RecordBytesTransferred(protocol string, direction string, bytes int64) {
	AddBytesTransferred(protocol, direction, bytes)
}

// IncBackendError increments backend error counter
func IncBackendError(protocol string) {
	// Using node errors metric for now
	metricsLock.Lock()
	defer metricsLock.Unlock()
	galeraNodeErrors.WithLabelValues(protocol).Inc()
}
