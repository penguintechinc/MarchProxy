package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/metrics"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// GaleraNodeState represents the state of a Galera cluster node
type GaleraNodeState int

const (
	GaleraStateUndefined    GaleraNodeState = 0 // Node is undefined
	GaleraStateJoining      GaleraNodeState = 1 // Node is joining cluster
	GaleraStateDonor        GaleraNodeState = 2 // Node is donor/desynced
	GaleraStateJoined       GaleraNodeState = 3 // Node has joined cluster
	GaleraStateSynced       GaleraNodeState = 4 // Node is synced (ready)
	GaleraStateError        GaleraNodeState = 5 // Node is in error state
	GaleraStateDisconnected GaleraNodeState = 6 // Node disconnected
)

func (s GaleraNodeState) String() string {
	switch s {
	case GaleraStateUndefined:
		return "Undefined"
	case GaleraStateJoining:
		return "Joining"
	case GaleraStateDonor:
		return "Donor/Desynced"
	case GaleraStateJoined:
		return "Joined"
	case GaleraStateSynced:
		return "Synced"
	case GaleraStateError:
		return "Error"
	case GaleraStateDisconnected:
		return "Disconnected"
	default:
		return "Unknown"
	}
}

// GaleraBackend represents a Galera cluster node backend
type GaleraBackend struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	TLS      bool
	Weight   float64
}

// GaleraNodeInfo contains information about a Galera cluster node
type GaleraNodeInfo struct {
	Backend             *GaleraBackend
	State               GaleraNodeState
	Ready               bool
	LocalIndex          int64
	ClusterSize         int64
	ClusterStatus       string
	FlowControlPaused   bool
	FlowControlSent     int64
	FlowControlReceived int64
	LastUpdated         time.Time
	CertFailures        int64
	LocalCommits        int64
	LocalReplays        int64
	ConnectErrors       int
	ConsecutiveErrors   int
	Weight              float64
	ReplicationLatency  time.Duration
	LastHealthCheck     time.Time
}

// IsHealthy returns true if the node is in a healthy state for serving queries
func (n *GaleraNodeInfo) IsHealthy() bool {
	return n.Ready &&
		n.State == GaleraStateSynced &&
		!n.FlowControlPaused &&
		n.ConsecutiveErrors < 3 &&
		time.Since(n.LastHealthCheck) < 30*time.Second
}

// CanServeReads returns true if the node can serve read queries
func (n *GaleraNodeInfo) CanServeReads() bool {
	return n.IsHealthy() || (n.State == GaleraStateJoined && !n.FlowControlPaused)
}

// CanServeWrites returns true if the node can serve write queries
func (n *GaleraNodeInfo) CanServeWrites() bool {
	return n.IsHealthy()
}

// GaleraHandler handles MariaDB Galera Cluster connections with cluster-aware routing
type GaleraHandler struct {
	protocol        string
	port            int
	pools           map[string]*pool.SQLPool
	nodeInfo        map[string]*GaleraNodeInfo
	poolMu          sync.RWMutex
	nodeInfoMu      sync.RWMutex
	securityChecker *security.Checker
	config          *config.Config
	logger          *logrus.Logger
	listener        net.Listener
	connLimiter     *rate.Limiter
	queryLimiter    *rate.Limiter
	activeConns     int64
	totalConns      int64
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc

	// Health check management
	healthCheckTicker *time.Ticker
	stopHealthCheck   chan bool

	// Galera-specific configuration
	healthCheckInterval  time.Duration
	maxConsecutiveErrors int
	flowControlThreshold int64
	readOnlyNodes        bool // Allow reads from non-synced nodes
	writeBalancing       bool // Balance writes across all synced nodes
	nodeWeightEnabled    bool // Use node weights for load balancing

	// Backend configuration
	backends []*GaleraBackend
}

// GaleraConfig contains Galera-specific configuration
type GaleraConfig struct {
	HealthCheckInterval  time.Duration
	MaxConsecutiveErrors int
	FlowControlThreshold int64
	ReadOnlyNodes        bool
	WriteBalancing       bool
	NodeWeightEnabled    bool
	ConnectionTimeout    time.Duration
	QueryTimeout         time.Duration
	Backends             []*GaleraBackend
}

// NewGaleraHandler creates a new Galera cluster handler
func NewGaleraHandler(protocol string, port int, galeraConfig *GaleraConfig,
	securityChecker *security.Checker, cfg *config.Config, logger *logrus.Logger) *GaleraHandler {

	// Set defaults if not provided
	if galeraConfig == nil {
		galeraConfig = &GaleraConfig{
			HealthCheckInterval:  10 * time.Second,
			MaxConsecutiveErrors: 3,
			FlowControlThreshold: 100,
			ReadOnlyNodes:        false,
			WriteBalancing:       true,
			NodeWeightEnabled:    true,
			ConnectionTimeout:    5 * time.Second,
			QueryTimeout:         30 * time.Second,
		}
	}

	handler := &GaleraHandler{
		protocol:             protocol,
		port:                 port,
		pools:                make(map[string]*pool.SQLPool),
		nodeInfo:             make(map[string]*GaleraNodeInfo),
		securityChecker:      securityChecker,
		config:               cfg,
		logger:               logger,
		connLimiter:          rate.NewLimiter(rate.Limit(cfg.DefaultConnectionRate), int(cfg.DefaultConnectionRate)),
		queryLimiter:         rate.NewLimiter(rate.Limit(cfg.DefaultQueryRate), int(cfg.DefaultQueryRate)),
		healthCheckInterval:  galeraConfig.HealthCheckInterval,
		maxConsecutiveErrors: galeraConfig.MaxConsecutiveErrors,
		flowControlThreshold: galeraConfig.FlowControlThreshold,
		readOnlyNodes:        galeraConfig.ReadOnlyNodes,
		writeBalancing:       galeraConfig.WriteBalancing,
		nodeWeightEnabled:    galeraConfig.NodeWeightEnabled,
		stopHealthCheck:      make(chan bool),
		backends:             galeraConfig.Backends,
	}

	return handler
}

// Start starts the Galera handler
func (h *GaleraHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("handler already running")
	}

	// Initialize connection pools
	if err := h.initPools(); err != nil {
		return fmt.Errorf("failed to initialize pools: %w", err)
	}

	// Start health checks
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.startHealthChecks(h.ctx)

	// Start listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.port))
	if err != nil {
		h.stopHealthChecks()
		h.closePools()
		return fmt.Errorf("failed to listen on port %d: %w", h.port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"protocol": h.protocol,
		"port":     h.port,
		"backends": len(h.backends),
	}).Info("Galera handler started")

	return nil
}

// Stop stops the Galera handler
func (h *GaleraHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("protocol", h.protocol).Info("Stopping Galera handler")

	h.stopHealthChecks()

	if h.cancel != nil {
		h.cancel()
	}

	if h.listener != nil {
		h.listener.Close()
	}

	h.closePools()
	h.running = false

	return nil
}

// GetStats returns handler statistics
func (h *GaleraHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	nodeStats := make(map[string]interface{})
	for key, node := range h.nodeInfo {
		nodeStats[key] = map[string]interface{}{
			"state":                node.State.String(),
			"ready":                node.Ready,
			"cluster_size":         node.ClusterSize,
			"cluster_status":       node.ClusterStatus,
			"flow_control_paused":  node.FlowControlPaused,
			"consecutive_errors":   node.ConsecutiveErrors,
			"last_health_check":    node.LastHealthCheck,
			"can_serve_reads":      node.CanServeReads(),
			"can_serve_writes":     node.CanServeWrites(),
		}
	}

	return map[string]interface{}{
		"protocol":     h.protocol,
		"port":         h.port,
		"active_conns": h.activeConns,
		"total_conns":  h.totalConns,
		"running":      h.running,
		"nodes":        nodeStats,
	}
}

// initPools initializes connection pools for all backends
func (h *GaleraHandler) initPools() error {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	if len(h.backends) == 0 {
		return fmt.Errorf("no backends configured for Galera cluster")
	}

	maxConnsPerBackend := h.config.MaxConnectionsPerRoute / len(h.backends)
	if maxConnsPerBackend < 10 {
		maxConnsPerBackend = 10
	}

	for _, backend := range h.backends {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=%s&readTimeout=%s&writeTimeout=%s",
			backend.User, backend.Password, backend.Host, backend.Port, backend.Database,
			h.healthCheckInterval.String(), h.healthCheckInterval.String(), h.healthCheckInterval.String())

		if backend.TLS {
			dsn += "&tls=true"
		}

		// Add Galera-specific connection parameters
		dsn += "&autocommit=true&sql_mode=STRICT_TRANS_TABLES"

		sqlPool, err := pool.NewSQLPool("mysql", dsn, maxConnsPerBackend, h.logger)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"host": backend.Host,
				"port": backend.Port,
			}).Warn("Failed to create pool for backend, will retry in health check")
			// Continue with other backends
		}

		key := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
		if sqlPool != nil {
			h.pools[key] = sqlPool
		}

		// Initialize node info
		h.nodeInfoMu.Lock()
		h.nodeInfo[key] = &GaleraNodeInfo{
			Backend:     backend,
			State:       GaleraStateUndefined,
			Ready:       false,
			Weight:      backend.Weight,
			LastUpdated: time.Now(),
		}
		h.nodeInfoMu.Unlock()

		h.logger.WithFields(logrus.Fields{
			"backend":   key,
			"max_conns": maxConnsPerBackend,
		}).Info("Galera backend pool initialized")
	}

	return nil
}

// startHealthChecks starts periodic health checking of Galera nodes
func (h *GaleraHandler) startHealthChecks(ctx context.Context) {
	h.healthCheckTicker = time.NewTicker(h.healthCheckInterval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-h.stopHealthCheck:
				return
			case <-h.healthCheckTicker.C:
				h.performHealthChecks(ctx)
			}
		}
	}()

	// Perform initial health check
	go h.performHealthChecks(ctx)
}

// stopHealthChecks stops health checking
func (h *GaleraHandler) stopHealthChecks() {
	if h.healthCheckTicker != nil {
		h.healthCheckTicker.Stop()
	}
	select {
	case h.stopHealthCheck <- true:
	default:
	}
}

// performHealthChecks performs health checks on all Galera nodes
func (h *GaleraHandler) performHealthChecks(ctx context.Context) {
	h.nodeInfoMu.RLock()
	nodes := make(map[string]*GaleraNodeInfo)
	for k, v := range h.nodeInfo {
		nodes[k] = v
	}
	h.nodeInfoMu.RUnlock()

	var wg sync.WaitGroup
	for key, node := range nodes {
		wg.Add(1)
		go func(k string, n *GaleraNodeInfo) {
			defer wg.Done()
			h.checkNodeHealth(ctx, k, n)
		}(key, node)
	}
	wg.Wait()
}

// checkNodeHealth performs health check on a single Galera node
func (h *GaleraHandler) checkNodeHealth(ctx context.Context, key string, node *GaleraNodeInfo) {
	h.poolMu.RLock()
	sqlPool, exists := h.pools[key]
	h.poolMu.RUnlock()

	if !exists {
		h.logger.Warn("Pool not found for node", logrus.Fields{"node": key})
		return
	}

	conn, err := sqlPool.Get()
	if err != nil {
		h.updateNodeError(key, node, err)
		return
	}
	defer conn.Close()

	// Query Galera status variables
	queries := []string{
		"SHOW STATUS LIKE 'wsrep_local_state'",
		"SHOW STATUS LIKE 'wsrep_ready'",
		"SHOW STATUS LIKE 'wsrep_local_index'",
		"SHOW STATUS LIKE 'wsrep_cluster_size'",
		"SHOW STATUS LIKE 'wsrep_cluster_status'",
		"SHOW STATUS LIKE 'wsrep_flow_control_paused'",
		"SHOW STATUS LIKE 'wsrep_flow_control_sent'",
		"SHOW STATUS LIKE 'wsrep_flow_control_recv'",
		"SHOW STATUS LIKE 'wsrep_cert_deps_distance'",
		"SHOW STATUS LIKE 'wsrep_local_commits'",
		"SHOW STATUS LIKE 'wsrep_local_cert_failures'",
		"SHOW STATUS LIKE 'wsrep_local_replays'",
	}

	statusMap := make(map[string]string)
	for _, query := range queries {
		rows, err := conn.QueryContext(ctx, query)
		if err != nil {
			h.updateNodeError(key, node, fmt.Errorf("health check query failed: %w", err))
			return
		}

		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err != nil {
				rows.Close()
				h.updateNodeError(key, node, fmt.Errorf("scan failed: %w", err))
				return
			}
			statusMap[name] = value
		}
		rows.Close()
	}

	// Update node information
	h.updateNodeInfo(key, node, statusMap)
}

// updateNodeInfo updates node information from health check results
func (h *GaleraHandler) updateNodeInfo(key string, node *GaleraNodeInfo, statusMap map[string]string) {
	h.nodeInfoMu.Lock()
	defer h.nodeInfoMu.Unlock()

	// Parse wsrep_local_state
	if stateStr, ok := statusMap["wsrep_local_state"]; ok {
		if state, err := strconv.Atoi(stateStr); err == nil {
			node.State = GaleraNodeState(state)
		}
	}

	// Parse wsrep_ready
	if readyStr, ok := statusMap["wsrep_ready"]; ok {
		node.Ready = strings.ToUpper(readyStr) == "ON"
	}

	// Parse wsrep_local_index
	if indexStr, ok := statusMap["wsrep_local_index"]; ok {
		if index, err := strconv.ParseInt(indexStr, 10, 64); err == nil {
			node.LocalIndex = index
		}
	}

	// Parse wsrep_cluster_size
	if sizeStr, ok := statusMap["wsrep_cluster_size"]; ok {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			node.ClusterSize = size
		}
	}

	// Parse wsrep_cluster_status
	if status, ok := statusMap["wsrep_cluster_status"]; ok {
		node.ClusterStatus = status
	}

	// Parse flow control information
	if pausedStr, ok := statusMap["wsrep_flow_control_paused"]; ok {
		node.FlowControlPaused = pausedStr != "0" && pausedStr != "0.000000"
	}

	if sentStr, ok := statusMap["wsrep_flow_control_sent"]; ok {
		if sent, err := strconv.ParseInt(sentStr, 10, 64); err == nil {
			node.FlowControlSent = sent
		}
	}

	if recvStr, ok := statusMap["wsrep_flow_control_recv"]; ok {
		if recv, err := strconv.ParseInt(recvStr, 10, 64); err == nil {
			node.FlowControlReceived = recv
		}
	}

	// Parse certificate failures
	if certFailStr, ok := statusMap["wsrep_local_cert_failures"]; ok {
		if failures, err := strconv.ParseInt(certFailStr, 10, 64); err == nil {
			node.CertFailures = failures
		}
	}

	// Parse commits and replays
	if commitsStr, ok := statusMap["wsrep_local_commits"]; ok {
		if commits, err := strconv.ParseInt(commitsStr, 10, 64); err == nil {
			node.LocalCommits = commits
		}
	}

	if replaysStr, ok := statusMap["wsrep_local_replays"]; ok {
		if replays, err := strconv.ParseInt(replaysStr, 10, 64); err == nil {
			node.LocalReplays = replays
		}
	}

	// Reset error counters on successful health check
	node.ConsecutiveErrors = 0
	node.LastUpdated = time.Now()
	node.LastHealthCheck = time.Now()

	h.logger.WithFields(logrus.Fields{
		"node":                 key,
		"state":                node.State.String(),
		"ready":                node.Ready,
		"flow_control_paused":  node.FlowControlPaused,
		"cluster_size":         node.ClusterSize,
		"cluster_status":       node.ClusterStatus,
	}).Debug("Updated Galera node info")

	// Update metrics
	metrics.SetGaleraNodeState(key, int(node.State))
	metrics.SetGaleraNodeReady(key, node.Ready)
	metrics.SetGaleraClusterSize(key, float64(node.ClusterSize))
	metrics.SetGaleraFlowControl(key, node.FlowControlPaused)
}

// updateNodeError updates node information when health check fails
func (h *GaleraHandler) updateNodeError(key string, node *GaleraNodeInfo, err error) {
	h.nodeInfoMu.Lock()
	defer h.nodeInfoMu.Unlock()

	node.ConsecutiveErrors++
	node.ConnectErrors++
	node.LastUpdated = time.Now()

	if node.ConsecutiveErrors >= h.maxConsecutiveErrors {
		node.Ready = false
		node.State = GaleraStateError
	}

	h.logger.WithFields(logrus.Fields{
		"node":               key,
		"error":              err.Error(),
		"consecutive_errors": node.ConsecutiveErrors,
	}).Warn("Galera node health check failed")

	// Update metrics
	metrics.IncGaleraNodeErrors(key)
	metrics.SetGaleraNodeReady(key, node.Ready)
}

// closePools closes all connection pools
func (h *GaleraHandler) closePools() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	for key, p := range h.pools {
		if err := p.Close(); err != nil {
			h.logger.WithError(err).WithField("pool", key).Error("Failed to close pool")
		}
	}
}

// acceptConnections accepts incoming connections
func (h *GaleraHandler) acceptConnections() {
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
			conn, err := h.listener.Accept()
			if err != nil {
				if !h.isRunning() {
					return
				}
				h.logger.WithError(err).Error("Failed to accept connection")
				continue
			}

			// Apply rate limiting
			if !h.connLimiter.Allow() {
				h.logger.Warn("Connection rate limit exceeded")
				conn.Close()
				continue
			}

			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single client connection
func (h *GaleraHandler) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	h.incrementActiveConns()
	defer h.decrementActiveConns()

	h.incrementTotalConns()

	metrics.IncConnection("galera")
	defer metrics.DecConnection("galera")

	// Perform MySQL handshake
	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.WithError(err).Error("Handshake failed")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"username": username,
		"database": database,
		"client":   clientConn.RemoteAddr().String(),
	}).Debug("Client connected")

	// Select backend (start with read assumption, will detect writes later)
	backend := h.selectGaleraBackend(false)
	if backend == nil {
		h.logger.Error("No healthy Galera node available")
		h.sendError(clientConn, "No healthy Galera node available")
		return
	}

	// Get backend connection
	backendConn, err := h.getBackendConnection(backend)
	if err != nil {
		h.logger.WithError(err).Error("Failed to connect to Galera backend")
		h.sendError(clientConn, "Backend connection failed")
		return
	}
	defer backendConn.Close()

	// Proxy traffic between client and backend
	h.proxyTraffic(h.ctx, clientConn, backendConn, username, database)
}

// selectGaleraBackend selects the best Galera node for a query
func (h *GaleraHandler) selectGaleraBackend(isWrite bool) *GaleraBackend {
	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	var candidates []*GaleraNodeInfo

	// Filter nodes based on query type and health
	for _, node := range h.nodeInfo {
		if isWrite {
			if node.CanServeWrites() {
				candidates = append(candidates, node)
			}
		} else {
			if node.CanServeReads() {
				candidates = append(candidates, node)
			} else if h.readOnlyNodes && node.State == GaleraStateJoined && !node.FlowControlPaused {
				candidates = append(candidates, node)
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Select best node based on configuration
	if h.nodeWeightEnabled {
		return h.selectByWeight(candidates)
	}

	return h.selectByRoundRobin(candidates)
}

// selectByWeight selects a node using weighted random selection
func (h *GaleraHandler) selectByWeight(candidates []*GaleraNodeInfo) *GaleraBackend {
	if len(candidates) == 0 {
		return nil
	}

	// Calculate total weight
	totalWeight := 0.0
	for _, node := range candidates {
		weight := node.Weight
		if weight <= 0 {
			weight = 1.0
		}

		// Adjust weight based on flow control and error rate
		if node.FlowControlPaused {
			weight *= 0.1 // Heavily penalize flow control
		}
		if node.ConsecutiveErrors > 0 {
			weight *= 0.5 // Penalize nodes with recent errors
		}

		totalWeight += weight
	}

	if totalWeight == 0 {
		return candidates[0].Backend
	}

	// Weighted random selection (simplified without config.GetRandomFloat)
	r := float64(time.Now().UnixNano()%1000) / 1000.0 * totalWeight
	currentWeight := 0.0

	for _, node := range candidates {
		weight := node.Weight
		if weight <= 0 {
			weight = 1.0
		}

		// Apply same adjustments
		if node.FlowControlPaused {
			weight *= 0.1
		}
		if node.ConsecutiveErrors > 0 {
			weight *= 0.5
		}

		currentWeight += weight
		if r <= currentWeight {
			return node.Backend
		}
	}

	return candidates[0].Backend
}

// selectByRoundRobin selects a node using round-robin
func (h *GaleraHandler) selectByRoundRobin(candidates []*GaleraNodeInfo) *GaleraBackend {
	if len(candidates) == 0 {
		return nil
	}

	// Simple round-robin selection based on timestamp
	index := time.Now().UnixNano() % int64(len(candidates))
	return candidates[index].Backend
}

// performHandshake performs MySQL protocol handshake
func (h *GaleraHandler) performHandshake(conn net.Conn) (string, string, error) {
	// Send greeting packet
	greeting := []byte{
		// Packet length (low 3 bytes) + sequence
		0x4a, 0x00, 0x00, 0x00,
		// Protocol version
		0x0a,
		// Server version "5.7.33-galera\0"
		0x35, 0x2e, 0x37, 0x2e, 0x33, 0x33, 0x2d, 0x67, 0x61, 0x6c, 0x65, 0x72, 0x61, 0x00,
		// Connection ID
		0x01, 0x00, 0x00, 0x00,
		// Auth plugin data part 1
		0x47, 0x61, 0x6c, 0x65, 0x72, 0x61, 0x44, 0x42,
		// Filler
		0x00,
		// Capability flags (lower 2 bytes)
		0xff, 0xf7,
		// Character set
		0x21,
		// Status flags
		0x02, 0x00,
		// Capability flags (upper 2 bytes)
		0xff, 0x81,
		// Auth plugin data length
		0x15,
		// Reserved (10 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Auth plugin data part 2
		0x4d, 0x61, 0x72, 0x63, 0x68, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x44, 0x42, 0x00,
	}

	if _, err := conn.Write(greeting); err != nil {
		return "", "", fmt.Errorf("failed to send greeting: %w", err)
	}

	// Read handshake response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read handshake response: %w", err)
	}

	if n < 36 {
		return "", "", fmt.Errorf("invalid handshake packet: too short")
	}

	// Parse username and database from handshake response
	username := ""
	database := ""

	// Skip packet header (4 bytes) + capability flags (4 bytes) + max packet (4 bytes) + charset (1 byte) + filler (23 bytes)
	pos := 36
	for pos < n && buf[pos] != 0 {
		username += string(buf[pos])
		pos++
	}
	pos++ // Skip null terminator

	// Skip auth response length and data
	if pos < n {
		authLen := int(buf[pos])
		pos += 1 + authLen
	}

	// Parse database name if present
	if pos < n {
		for pos < n && buf[pos] != 0 {
			database += string(buf[pos])
			pos++
		}
	}

	// Send OK packet
	okPacket := []byte{
		0x07, 0x00, 0x00, 0x02, // Packet header
		0x00,                   // OK
		0x00, 0x00,             // Affected rows, last insert id
		0x02, 0x00,             // Status flags
		0x00, 0x00,             // Warnings
	}
	conn.Write(okPacket)

	return username, database, nil
}

// sendError sends an MySQL error packet to the client
func (h *GaleraHandler) sendError(conn net.Conn, message string) {
	errorPacket := []byte{
		0xff,                         // ERR packet
		0x48, 0x04,                   // Error code 1128
		0x23, 0x48, 0x59, 0x30, 0x30, 0x30, // SQL state marker + "HY000"
	}
	errorPacket = append(errorPacket, []byte(message)...)

	// Add packet header
	length := len(errorPacket)
	header := []byte{
		byte(length & 0xff),
		byte((length >> 8) & 0xff),
		byte((length >> 16) & 0xff),
		0x01, // Sequence number
	}

	packet := append(header, errorPacket...)
	conn.Write(packet)
}

// getBackendConnection gets a connection from the pool for a specific backend
func (h *GaleraHandler) getBackendConnection(backend *GaleraBackend) (*sql.Conn, error) {
	key := fmt.Sprintf("%s:%d", backend.Host, backend.Port)

	h.poolMu.RLock()
	sqlPool, ok := h.pools[key]
	h.poolMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("pool not found for backend %s", key)
	}

	return sqlPool.Get()
}

// proxyTraffic proxies traffic between client and backend with security checks
func (h *GaleraHandler) proxyTraffic(ctx context.Context, client net.Conn,
	backend *sql.Conn, username, database string) {

	// For now, we'll use a simplified proxy approach
	// In production, this should parse MySQL packets and perform query-level routing

	// Create a raw connection from sql.Conn for bidirectional copy
	// Note: This is a simplified implementation. Production would need full MySQL protocol parsing

	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to backend
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				n, err := client.Read(buf)
				if err != nil {
					if err != io.EOF {
						errChan <- err
					}
					return
				}

				if n > 0 {
					// Simple query detection for metrics
					// In production, parse MySQL packets properly
					query := string(buf[:n])
					isWrite := h.isWriteQuery(query)

					// Apply rate limiting
					if !h.queryLimiter.Allow() {
						h.logger.Warn("Query rate limit exceeded")
						h.sendError(client, "Query rate limit exceeded")
						return
					}

					// Security check if enabled
					if h.config.EnableSQLInjectionDetection {
						if suspicious, reason := h.securityChecker.CheckQuery(query); suspicious {
							h.logger.WithFields(logrus.Fields{
								"user":     username,
								"database": database,
								"reason":   reason,
							}).Warn("Suspicious query blocked")
							metrics.IncSQLInjection("galera")
							h.sendError(client, "Query blocked by security policy")
							return
						}
					}

					metrics.IncQuery("galera", isWrite)
				}
			}
		}
	}()

	// Backend to client
	go func() {
		defer wg.Done()
		// Note: This is simplified. Production needs proper MySQL packet handling
		<-ctx.Done()
	}()

	// Wait for first error or context cancellation
	select {
	case <-errChan:
	case <-ctx.Done():
	}

	wg.Wait()
}

// isWriteQuery checks if a query is a write operation
func (h *GaleraHandler) isWriteQuery(query string) bool {
	normalized := strings.ToLower(strings.TrimSpace(query))
	writeKeywords := []string{"insert", "update", "delete", "replace", "create", "alter", "drop", "truncate"}

	for _, keyword := range writeKeywords {
		if strings.HasPrefix(normalized, keyword) {
			return true
		}
	}

	return false
}

// GetClusterStatus returns the current status of the Galera cluster
func (h *GaleraHandler) GetClusterStatus() map[string]*GaleraNodeInfo {
	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	status := make(map[string]*GaleraNodeInfo)
	for k, v := range h.nodeInfo {
		// Create a copy to avoid race conditions
		nodeCopy := *v
		status[k] = &nodeCopy
	}

	return status
}

// GetHealthyNodes returns a list of healthy nodes that can serve queries
func (h *GaleraHandler) GetHealthyNodes(forWrites bool) []*GaleraNodeInfo {
	h.nodeInfoMu.RLock()
	defer h.nodeInfoMu.RUnlock()

	var healthy []*GaleraNodeInfo
	for _, node := range h.nodeInfo {
		if forWrites {
			if node.CanServeWrites() {
				healthy = append(healthy, node)
			}
		} else {
			if node.CanServeReads() {
				healthy = append(healthy, node)
			}
		}
	}

	return healthy
}

// isRunning returns whether the handler is running
func (h *GaleraHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// incrementActiveConns increments active connection counter
func (h *GaleraHandler) incrementActiveConns() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeConns++
}

// decrementActiveConns decrements active connection counter
func (h *GaleraHandler) decrementActiveConns() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeConns--
}

// incrementTotalConns increments total connection counter
func (h *GaleraHandler) incrementTotalConns() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.totalConns++
}
