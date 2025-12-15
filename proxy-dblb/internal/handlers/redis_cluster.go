package handlers

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"
)

const (
	HASH_SLOTS               = 16384
	DEFAULT_ASK_TIMEOUT      = 5 * time.Second
	CLUSTER_REFRESH_INTERVAL = 30 * time.Second
	MAX_REDIRECTIONS         = 3
)

// RedisClusterHandler implements the Handler interface for Redis Cluster protocol
type RedisClusterHandler struct {
	cfg             *config.Config
	routeConfig     *config.RouteConfig
	redis           *redis.Client
	logger          *logrus.Logger
	pool            *pool.Pool
	securityChecker *security.Checker

	clusterNodes    map[string]*RedisNode
	slotMap         [HASH_SLOTS]*RedisNode
	nodeConnections map[string]*redis.Client

	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	stats    *RedisClusterStats
	listener net.Listener
	running  bool
}

// RedisNode represents a node in the Redis cluster
type RedisNode struct {
	ID          string          `json:"id"`
	Host        string          `json:"host"`
	Port        int             `json:"port"`
	Master      bool            `json:"master"`
	Slots       []SlotRange     `json:"slots"`
	Replicas    []*RedisNode    `json:"replicas"`
	Client      *redis.Client   `json:"-"`
	LastSeen    time.Time       `json:"last_seen"`
	Healthy     bool            `json:"healthy"`
	Latency     time.Duration   `json:"latency"`
	Connections int32           `json:"connections"`
	QPS         uint64          `json:"qps"`
}

// SlotRange represents a range of hash slots
type SlotRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// RedisClusterStats tracks cluster-wide statistics
type RedisClusterStats struct {
	TotalNodes       int                   `json:"total_nodes"`
	MasterNodes      int                   `json:"master_nodes"`
	ReplicaNodes     int                   `json:"replica_nodes"`
	HealthyNodes     int                   `json:"healthy_nodes"`
	TotalRequests    uint64                `json:"total_requests"`
	RedirectedMoved  uint64                `json:"redirected_moved"`
	RedirectedAsk    uint64                `json:"redirected_ask"`
	ClusterErrors    uint64                `json:"cluster_errors"`
	NodeStats        map[string]*NodeStats `json:"node_stats"`
	AvgLatency       time.Duration         `json:"avg_latency"`
	LastRefresh      time.Time             `json:"last_refresh"`
}

// NodeStats tracks per-node statistics
type NodeStats struct {
	Requests    uint64        `json:"requests"`
	Errors      uint64        `json:"errors"`
	Latency     time.Duration `json:"latency"`
	Connections int32         `json:"connections"`
	LastAccess  time.Time     `json:"last_access"`
}

// RedisClusterCommand represents a parsed Redis command with cluster info
type RedisClusterCommand struct {
	Command string
	Args    []string
	Key     string
	Slot    int
	IsRead  bool
}

// NewRedisClusterHandler creates a new Redis Cluster protocol handler
func NewRedisClusterHandler(
	cfg *config.Config,
	routeConfig *config.RouteConfig,
	pool *pool.Pool,
	securityChecker *security.Checker,
	logger *logrus.Logger,
) *RedisClusterHandler {
	ctx, cancel := context.WithCancel(context.Background())

	// Create Redis client for cluster discovery
	redisClient := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", routeConfig.BackendHost, routeConfig.BackendPort),
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})

	handler := &RedisClusterHandler{
		cfg:             cfg,
		routeConfig:     routeConfig,
		redis:           redisClient,
		logger:          logger,
		pool:            pool,
		securityChecker: securityChecker,
		clusterNodes:    make(map[string]*RedisNode),
		nodeConnections: make(map[string]*redis.Client),
		ctx:             ctx,
		cancel:          cancel,
		stats: &RedisClusterStats{
			NodeStats: make(map[string]*NodeStats),
		},
	}

	// Start background tasks
	go handler.clusterTopologyRefresh()
	go handler.healthMonitor()
	go handler.statsCollector()

	// Initial cluster discovery
	if err := handler.discoverClusterTopology(); err != nil {
		logger.WithError(err).Warn("Initial cluster discovery failed, will retry")
	}

	logger.WithFields(logrus.Fields{
		"route": routeConfig.Name,
		"nodes": len(handler.clusterNodes),
	}).Info("Redis cluster handler initialized")

	return handler
}

// Start implements the Handler interface
func (h *RedisClusterHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("handler already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.routeConfig.ListenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.routeConfig.ListenPort, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"port":  h.routeConfig.ListenPort,
		"route": h.routeConfig.Name,
	}).Info("Redis cluster handler started")

	return nil
}

// Stop implements the Handler interface
func (h *RedisClusterHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("route", h.routeConfig.Name).Info("Stopping Redis cluster handler")

	h.cancel()

	if h.listener != nil {
		h.listener.Close()
	}

	// Close all node connections
	for _, client := range h.nodeConnections {
		client.Close()
	}

	if h.redis != nil {
		h.redis.Close()
	}

	h.running = false
	h.logger.Info("Redis cluster handler stopped")
	return nil
}

// GetStats implements the Handler interface
func (h *RedisClusterHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"route":            h.routeConfig.Name,
		"protocol":         "redis_cluster",
		"port":             h.routeConfig.ListenPort,
		"running":          h.running,
		"total_nodes":      h.stats.TotalNodes,
		"master_nodes":     h.stats.MasterNodes,
		"replica_nodes":    h.stats.ReplicaNodes,
		"healthy_nodes":    h.stats.HealthyNodes,
		"total_requests":   atomic.LoadUint64(&h.stats.TotalRequests),
		"redirected_moved": atomic.LoadUint64(&h.stats.RedirectedMoved),
		"redirected_ask":   atomic.LoadUint64(&h.stats.RedirectedAsk),
		"cluster_errors":   atomic.LoadUint64(&h.stats.ClusterErrors),
		"avg_latency":      h.stats.AvgLatency.String(),
		"last_refresh":     h.stats.LastRefresh,
	}
}

// acceptConnections accepts incoming client connections
func (h *RedisClusterHandler) acceptConnections() {
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

			go h.handleConnection(h.ctx, conn)
		}
	}
}

// handleConnection handles a single client connection
func (h *RedisClusterHandler) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	username := "default"
	database := "0"

	scanner := bufio.NewScanner(clientConn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := scanner.Text()
			if err := h.processRedisCommand(ctx, clientConn, line, username, database); err != nil {
				h.logger.WithError(err).Error("Error processing Redis command")
				return
			}
		}
	}
}

// processRedisCommand processes a single Redis command
func (h *RedisClusterHandler) processRedisCommand(
	ctx context.Context,
	conn net.Conn,
	line string,
	username, database string,
) error {
	atomic.AddUint64(&h.stats.TotalRequests, 1)

	// Parse Redis command
	cmd := h.parseRedisCommand(line)
	if cmd == nil {
		return fmt.Errorf("failed to parse Redis command")
	}

	// Security checks
	if h.cfg.BlockSuspiciousQueries {
		if h.isBlockedRedisCommand(*cmd) {
			h.logger.WithFields(logrus.Fields{
				"user":    username,
				"command": cmd.Command,
			}).Warn("Blocked Redis command")
			return h.sendError(conn, "Command blocked by security policy")
		}
	}

	// Execute command through cluster
	response, err := h.executeClusterCommand(ctx, cmd, username)
	if err != nil {
		return h.sendError(conn, err.Error())
	}

	// Send response to client
	if response != nil {
		conn.Write(response)
	}

	return nil
}

// executeClusterCommand executes a command on the appropriate cluster node
func (h *RedisClusterHandler) executeClusterCommand(
	ctx context.Context,
	cmd *RedisClusterCommand,
	username string,
) ([]byte, error) {
	// Find the appropriate node for this command
	node := h.getNodeForCommand(cmd)
	if node == nil {
		return nil, fmt.Errorf("no available node for command")
	}

	// Track redirections to avoid infinite loops
	redirections := 0

	for redirections <= MAX_REDIRECTIONS {
		// Execute command on the selected node
		result, err := h.executeOnNode(ctx, node, cmd, username)
		if err != nil {
			// Check for cluster redirections
			if moved, newNode := h.parseMovedError(err.Error()); moved {
				atomic.AddUint64(&h.stats.RedirectedMoved, 1)
				node = newNode
				redirections++
				continue
			}

			if ask, newNode := h.parseAskError(err.Error()); ask {
				atomic.AddUint64(&h.stats.RedirectedAsk, 1)
				// For ASK redirect, execute ASKING followed by the command
				if _, err := h.executeOnNode(ctx, newNode, &RedisClusterCommand{Command: "ASKING"}, username); err != nil {
					h.logger.WithError(err).Warn("Failed to send ASKING command")
				}
				node = newNode
				redirections++
				continue
			}

			return nil, err
		}

		// Convert Redis result to bytes
		if result != nil {
			return []byte(fmt.Sprintf("%v\r\n", result)), nil
		}

		return []byte("+OK\r\n"), nil
	}

	return nil, fmt.Errorf("too many redirections")
}

// executeOnNode executes a command on a specific node
func (h *RedisClusterHandler) executeOnNode(
	ctx context.Context,
	node *RedisNode,
	cmd *RedisClusterCommand,
	username string,
) (interface{}, error) {
	if node.Client == nil {
		return nil, fmt.Errorf("no client connection to node %s", node.ID)
	}

	// Increment connection counter for this node
	atomic.AddInt32(&node.Connections, 1)
	defer atomic.AddInt32(&node.Connections, -1)

	start := time.Now()
	defer func() {
		latency := time.Since(start)
		node.Latency = latency

		if stats := h.stats.NodeStats[node.ID]; stats != nil {
			atomic.AddUint64(&stats.Requests, 1)
			stats.Latency = latency
			stats.LastAccess = time.Now()
		}
	}()

	// Prepare Redis command
	args := make([]interface{}, len(cmd.Args)+1)
	args[0] = cmd.Command
	for i, arg := range cmd.Args {
		args[i+1] = arg
	}

	// Execute command
	result := node.Client.Do(ctx, args...)
	return result.Val(), result.Err()
}

// getNodeForCommand selects the appropriate node for a command
func (h *RedisClusterHandler) getNodeForCommand(cmd *RedisClusterCommand) *RedisNode {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// For commands with keys, use consistent hashing
	if cmd.Key != "" {
		slot := h.calculateSlot(cmd.Key)
		cmd.Slot = slot

		if slot >= 0 && slot < HASH_SLOTS {
			node := h.slotMap[slot]
			if node != nil && node.Healthy {
				// For read commands, try replicas first if available
				if cmd.IsRead && len(node.Replicas) > 0 {
					// Fallback to first healthy replica
					for _, replica := range node.Replicas {
						if replica.Healthy {
							return replica
						}
					}
				}

				return node
			}
		}
	}

	// For commands without keys or when slot mapping fails, use any healthy master
	for _, node := range h.clusterNodes {
		if node.Master && node.Healthy {
			return node
		}
	}

	return nil
}

// calculateSlot calculates the Redis Cluster hash slot for a key
func (h *RedisClusterHandler) calculateSlot(key string) int {
	// Handle hash tags
	start := strings.Index(key, "{")
	if start != -1 {
		end := strings.Index(key[start+1:], "}")
		if end != -1 {
			key = key[start+1 : start+1+end]
		}
	}

	// CRC16 calculation
	crc := uint16(0)
	for _, b := range []byte(key) {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc = crc << 1
			}
		}
	}

	return int(crc % HASH_SLOTS)
}

// discoverClusterTopology discovers the cluster topology
func (h *RedisClusterHandler) discoverClusterTopology() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Get cluster nodes from any connected Redis instance
	clusterNodes, err := h.redis.ClusterNodes(h.ctx).Result()
	if err != nil {
		// Fallback to single node operation
		h.logger.WithError(err).Warn("Failed to discover cluster topology, using single node")
		return h.setupSingleNode()
	}

	return h.parseClusterNodes(clusterNodes)
}

// parseClusterNodes parses the CLUSTER NODES response
func (h *RedisClusterHandler) parseClusterNodes(nodesInfo string) error {
	lines := strings.Split(strings.TrimSpace(nodesInfo), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 8 {
			continue
		}

		nodeID := parts[0]
		endpoint := parts[1]
		flags := parts[2]
		masterID := parts[3]

		// Parse host:port
		hostPort := strings.Split(endpoint, ":")
		if len(hostPort) < 2 {
			continue
		}

		host := hostPort[0]
		port, err := strconv.Atoi(strings.Split(hostPort[1], "@")[0])
		if err != nil {
			continue
		}

		// Create node
		node := &RedisNode{
			ID:       nodeID,
			Host:     host,
			Port:     port,
			Master:   strings.Contains(flags, "master"),
			Healthy:  !strings.Contains(flags, "fail"),
			LastSeen: time.Now(),
		}

		// Create Redis client for this node
		nodeClient := redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", host, port),
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		})

		node.Client = nodeClient
		h.nodeConnections[nodeID] = nodeClient

		// Parse slots if this is a master
		if node.Master && len(parts) > 8 {
			for i := 8; i < len(parts); i++ {
				slotRange := h.parseSlotRange(parts[i])
				if slotRange != nil {
					node.Slots = append(node.Slots, *slotRange)

					// Update slot map
					for slot := slotRange.Start; slot <= slotRange.End; slot++ {
						if slot >= 0 && slot < HASH_SLOTS {
							h.slotMap[slot] = node
						}
					}
				}
			}
		}

		h.clusterNodes[nodeID] = node
		h.stats.NodeStats[nodeID] = &NodeStats{}

		// Link replicas to masters
		if !node.Master && masterID != "-" {
			if master, exists := h.clusterNodes[masterID]; exists {
				master.Replicas = append(master.Replicas, node)
			}
		}
	}

	h.updateStatsCounters()
	h.stats.LastRefresh = time.Now()

	h.logger.WithFields(logrus.Fields{
		"total_nodes":   h.stats.TotalNodes,
		"master_nodes":  h.stats.MasterNodes,
		"replica_nodes": h.stats.ReplicaNodes,
	}).Info("Cluster topology discovered")

	return nil
}

// parseSlotRange parses a slot range string
func (h *RedisClusterHandler) parseSlotRange(slotStr string) *SlotRange {
	if strings.Contains(slotStr, "-") {
		parts := strings.Split(slotStr, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil {
				return &SlotRange{Start: start, End: end}
			}
		}
	} else {
		slot, err := strconv.Atoi(slotStr)
		if err == nil {
			return &SlotRange{Start: slot, End: slot}
		}
	}
	return nil
}

// setupSingleNode sets up a single node (non-cluster mode)
func (h *RedisClusterHandler) setupSingleNode() error {
	node := &RedisNode{
		ID:       "single",
		Host:     h.routeConfig.BackendHost,
		Port:     h.routeConfig.BackendPort,
		Master:   true,
		Healthy:  true,
		LastSeen: time.Now(),
		Client:   h.redis,
	}

	// Map all slots to this node
	for i := 0; i < HASH_SLOTS; i++ {
		h.slotMap[i] = node
	}

	h.clusterNodes["single"] = node
	h.stats.NodeStats["single"] = &NodeStats{}
	h.updateStatsCounters()

	return nil
}

// parseMovedError parses a MOVED error response
func (h *RedisClusterHandler) parseMovedError(errStr string) (bool, *RedisNode) {
	// MOVED 3999 127.0.0.1:7002
	if strings.HasPrefix(errStr, "MOVED") {
		parts := strings.Fields(errStr)
		if len(parts) >= 3 {
			hostPort := parts[2]
			return true, h.findNodeByAddress(hostPort)
		}
	}
	return false, nil
}

// parseAskError parses an ASK error response
func (h *RedisClusterHandler) parseAskError(errStr string) (bool, *RedisNode) {
	// ASK 3999 127.0.0.1:7002
	if strings.HasPrefix(errStr, "ASK") {
		parts := strings.Fields(errStr)
		if len(parts) >= 3 {
			hostPort := parts[2]
			return true, h.findNodeByAddress(hostPort)
		}
	}
	return false, nil
}

// findNodeByAddress finds a node by its address
func (h *RedisClusterHandler) findNodeByAddress(address string) *RedisNode {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, node := range h.clusterNodes {
		if fmt.Sprintf("%s:%d", node.Host, node.Port) == address {
			return node
		}
	}
	return nil
}

// clusterTopologyRefresh periodically refreshes the cluster topology
func (h *RedisClusterHandler) clusterTopologyRefresh() {
	ticker := time.NewTicker(CLUSTER_REFRESH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			if err := h.discoverClusterTopology(); err != nil {
				h.logger.WithError(err).Warn("Failed to refresh cluster topology")
			}
		}
	}
}

// healthMonitor periodically checks node health
func (h *RedisClusterHandler) healthMonitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.checkNodeHealth()
		}
	}
}

// checkNodeHealth checks the health of all nodes
func (h *RedisClusterHandler) checkNodeHealth() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for nodeID, node := range h.clusterNodes {
		if node.Client == nil {
			continue
		}

		ctx, cancel := context.WithTimeout(h.ctx, 2*time.Second)
		start := time.Now()

		_, err := node.Client.Ping(ctx).Result()
		latency := time.Since(start)
		cancel()

		if err != nil {
			node.Healthy = false
			if stats := h.stats.NodeStats[nodeID]; stats != nil {
				atomic.AddUint64(&stats.Errors, 1)
			}
		} else {
			node.Healthy = true
			node.Latency = latency
			node.LastSeen = time.Now()
		}
	}

	h.updateStatsCounters()
}

// updateStatsCounters updates cluster-wide statistics
func (h *RedisClusterHandler) updateStatsCounters() {
	totalNodes := len(h.clusterNodes)
	masterNodes := 0
	replicaNodes := 0
	healthyNodes := 0

	for _, node := range h.clusterNodes {
		if node.Master {
			masterNodes++
		} else {
			replicaNodes++
		}

		if node.Healthy {
			healthyNodes++
		}
	}

	h.stats.TotalNodes = totalNodes
	h.stats.MasterNodes = masterNodes
	h.stats.ReplicaNodes = replicaNodes
	h.stats.HealthyNodes = healthyNodes
}

// statsCollector periodically collects statistics
func (h *RedisClusterHandler) statsCollector() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.collectStats()
		}
	}
}

// collectStats collects cluster-wide statistics
func (h *RedisClusterHandler) collectStats() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var totalLatency time.Duration
	validNodes := 0

	for _, node := range h.clusterNodes {
		if node.Healthy && node.Latency > 0 {
			totalLatency += node.Latency
			validNodes++
		}

		atomic.StoreUint64(&node.QPS, 0) // Reset QPS counter
	}

	if validNodes > 0 {
		h.stats.AvgLatency = totalLatency / time.Duration(validNodes)
	}
}

// parseRedisCommand parses a Redis protocol command
func (h *RedisClusterHandler) parseRedisCommand(line string) *RedisClusterCommand {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) == 0 {
		return nil
	}

	cmd := &RedisClusterCommand{
		Command: strings.ToUpper(parts[0]),
		Args:    parts[1:],
	}

	// Extract key and determine if it's a read operation
	if len(parts) > 1 {
		cmd.Key = parts[1]
	}

	// Classify as read or write operation
	readCommands := map[string]bool{
		"GET": true, "MGET": true, "HGET": true, "HGETALL": true, "HMGET": true,
		"LLEN": true, "LRANGE": true, "SMEMBERS": true, "SCARD": true,
		"ZRANGE": true, "ZCARD": true, "EXISTS": true, "TTL": true, "TYPE": true,
	}

	cmd.IsRead = readCommands[cmd.Command]

	return cmd
}

// isBlockedRedisCommand checks if a command is blocked by security policy
func (h *RedisClusterHandler) isBlockedRedisCommand(cmd RedisClusterCommand) bool {
	// Block dangerous Redis commands
	dangerousCommands := map[string]bool{
		"FLUSHDB": true, "FLUSHALL": true, "SHUTDOWN": true, "DEBUG": true,
		"CONFIG": true, "EVAL": true, "EVALSHA": true, "SCRIPT": true,
		"CLIENT": true, "MONITOR": true, "SYNC": true, "PSYNC": true,
		"CLUSTER": true, "MODULE": true, "ACL": true,
	}

	return dangerousCommands[cmd.Command]
}

// sendError sends an error response to the client
func (h *RedisClusterHandler) sendError(conn net.Conn, message string) error {
	errorResponse := fmt.Sprintf("-ERR %s\r\n", message)
	_, err := conn.Write([]byte(errorResponse))
	return err
}

// isRunning returns whether the handler is running
func (h *RedisClusterHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}
