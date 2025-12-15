package handlers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// RedisHandler implements the Handler interface for Redis protocol
type RedisHandler struct {
	protocol        string
	port            int
	pool            *pool.Pool
	securityChecker *security.Checker
	config          *config.Config
	logger          *logrus.Logger
	listener        net.Listener
	connLimiter     *rate.Limiter
	queryLimiter    *rate.Limiter
	activeConns     int64
	totalConns      int64
	totalQueries    int64
	blockedQueries  int64
	readQueries     int64
	writeQueries    int64
	roundRobin      uint64
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
}

// RedisCommand represents a parsed Redis command
type RedisCommand struct {
	Command string
	Args    []string
	Raw     string
}

// NewRedisHandler creates a new Redis protocol handler
func NewRedisHandler(port int, pool *pool.Pool, securityChecker *security.Checker, cfg *config.Config, logger *logrus.Logger) *RedisHandler {
	return &RedisHandler{
		protocol:        "redis",
		port:            port,
		pool:            pool,
		securityChecker: securityChecker,
		config:          cfg,
		logger:          logger,
		connLimiter:     rate.NewLimiter(rate.Limit(cfg.DefaultConnectionRate), int(cfg.DefaultConnectionRate)),
		queryLimiter:    rate.NewLimiter(rate.Limit(cfg.DefaultQueryRate), int(cfg.DefaultQueryRate)),
	}
}

// Start starts the Redis handler
func (h *RedisHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("redis handler already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.port, err)
	}

	h.listener = listener
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.running = true

	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"protocol": h.protocol,
		"port":     h.port,
	}).Info("Redis handler started")

	return nil
}

// Stop stops the Redis handler
func (h *RedisHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("protocol", h.protocol).Info("Stopping Redis handler")

	if h.cancel != nil {
		h.cancel()
	}

	if h.listener != nil {
		h.listener.Close()
	}

	h.running = false
	return nil
}

// GetStats returns Redis handler statistics
func (h *RedisHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"protocol":        h.protocol,
		"port":            h.port,
		"active_conns":    atomic.LoadInt64(&h.activeConns),
		"total_conns":     atomic.LoadInt64(&h.totalConns),
		"total_queries":   atomic.LoadInt64(&h.totalQueries),
		"read_queries":    atomic.LoadInt64(&h.readQueries),
		"write_queries":   atomic.LoadInt64(&h.writeQueries),
		"blocked_queries": atomic.LoadInt64(&h.blockedQueries),
		"running":         h.running,
	}
}

// acceptConnections accepts incoming Redis connections
func (h *RedisHandler) acceptConnections() {
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
				h.logger.WithError(err).Error("Failed to accept Redis connection")
				continue
			}

			// Apply connection rate limiting
			if !h.connLimiter.Allow() {
				h.logger.Warn("Redis connection rate limit exceeded")
				h.sendError(conn, "Connection rate limit exceeded")
				conn.Close()
				continue
			}

			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single Redis connection
func (h *RedisHandler) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	atomic.AddInt64(&h.activeConns, 1)
	defer atomic.AddInt64(&h.activeConns, -1)
	atomic.AddInt64(&h.totalConns, 1)

	// Track current user and database (Redis numbered databases)
	username := "default"
	database := "0"

	// Get backend connection from pool
	backendConn, err := h.getBackendConnection()
	if err != nil {
		h.logger.WithError(err).Error("Failed to get Redis backend connection")
		h.sendError(clientConn, "Backend connection unavailable")
		return
	}
	defer h.releaseBackendConnection(backendConn)

	// Proxy Redis traffic with protocol awareness
	h.proxyRedisTraffic(h.ctx, clientConn, backendConn, &username, &database)
}

// proxyRedisTraffic proxies Redis protocol traffic with command inspection
func (h *RedisHandler) proxyRedisTraffic(ctx context.Context, client net.Conn, backend net.Conn, username, database *string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to backend with protocol inspection
	go func() {
		defer wg.Done()
		h.proxyClientToBackend(ctx, client, backend, username, database)
	}()

	// Backend to client (passthrough)
	go func() {
		defer wg.Done()
		h.proxyBackendToClient(ctx, client, backend)
	}()

	wg.Wait()
}

// proxyClientToBackend handles client to backend with command inspection
func (h *RedisHandler) proxyClientToBackend(ctx context.Context, client net.Conn, backend net.Conn, username, database *string) {
	scanner := bufio.NewScanner(client)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB initial, 1MB max

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := scanner.Text()
			if line == "" {
				continue
			}

			// Parse Redis command
			cmd := h.parseRedisCommand(line)

			// Update database if SELECT command
			if strings.ToUpper(cmd.Command) == "SELECT" && len(cmd.Args) > 0 {
				*database = cmd.Args[0]
			}

			// Update username if AUTH command
			if strings.ToUpper(cmd.Command) == "AUTH" && len(cmd.Args) > 0 {
				if len(cmd.Args) == 1 {
					// AUTH password (Redis < 6.0)
					*username = "default"
				} else if len(cmd.Args) >= 2 {
					// AUTH username password (Redis >= 6.0)
					*username = cmd.Args[0]
				}
			}

			// Apply query rate limiting
			if !h.queryLimiter.Allow() {
				h.logger.Warn("Redis query rate limit exceeded")
				h.sendError(client, "Query rate limit exceeded")
				return
			}

			// Check for blocked Redis commands
			if h.isBlockedRedisCommand(cmd) {
				h.logger.WithFields(logrus.Fields{
					"user":     *username,
					"database": *database,
					"command":  cmd.Command,
				}).Warn("Blocked Redis command")
				atomic.AddInt64(&h.blockedQueries, 1)
				h.sendError(client, "Command blocked by security policy")
				return
			}

			// Security check on command and arguments
			if h.config.EnableSQLInjectionDetection {
				commandStr := h.commandToString(cmd)
				if suspicious, reason := h.securityChecker.CheckQuery(commandStr); suspicious {
					h.logger.WithFields(logrus.Fields{
						"user":     *username,
						"database": *database,
						"command":  cmd.Command,
						"reason":   reason,
					}).Warn("Blocked suspicious Redis command")
					atomic.AddInt64(&h.blockedQueries, 1)
					h.sendError(client, "Command blocked: "+reason)
					return
				}
			}

			// Track query statistics
			atomic.AddInt64(&h.totalQueries, 1)
			if h.isWriteCommand(cmd.Command) {
				atomic.AddInt64(&h.writeQueries, 1)
			} else {
				atomic.AddInt64(&h.readQueries, 1)
			}

			// Forward to backend
			if _, err := backend.Write([]byte(line + "\r\n")); err != nil {
				h.logger.WithError(err).Error("Failed to write to Redis backend")
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		h.logger.WithError(err).Debug("Redis client scanner error")
	}
}

// proxyBackendToClient handles backend to client passthrough
func (h *RedisHandler) proxyBackendToClient(ctx context.Context, client net.Conn, backend net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := backend.Read(buf)
			if err != nil {
				if err != io.EOF {
					h.logger.WithError(err).Debug("Redis backend read error")
				}
				return
			}

			if _, err := client.Write(buf[:n]); err != nil {
				h.logger.WithError(err).Debug("Redis client write error")
				return
			}
		}
	}
}

// parseRedisCommand parses a Redis command from RESP protocol
func (h *RedisHandler) parseRedisCommand(line string) RedisCommand {
	cmd := RedisCommand{Raw: line}

	// Simple RESP protocol parsing
	if strings.HasPrefix(line, "*") {
		// Array format (proper RESP)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			cmd.Command = strings.TrimPrefix(parts[0], "*")
			if len(parts) > 1 {
				cmd.Args = parts[1:]
			}
		}
	} else {
		// Simple string format (inline commands)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			cmd.Command = parts[0]
			if len(parts) > 1 {
				cmd.Args = parts[1:]
			}
		}
	}

	return cmd
}

// commandToString converts a Redis command to string for inspection
func (h *RedisHandler) commandToString(cmd RedisCommand) string {
	if len(cmd.Args) == 0 {
		return cmd.Command
	}
	return cmd.Command + " " + strings.Join(cmd.Args, " ")
}

// isBlockedRedisCommand checks if a Redis command is blocked
func (h *RedisHandler) isBlockedRedisCommand(cmd RedisCommand) bool {
	// Block dangerous Redis commands that could compromise server
	dangerousCommands := map[string]bool{
		// System/server management
		"FLUSHDB":   true,
		"FLUSHALL":  true,
		"SHUTDOWN":  true,
		"DEBUG":     true,
		"CONFIG":    true,
		"SAVE":      true,
		"BGSAVE":    true,
		"BGREWRITEAOF": true,

		// Replication
		"SYNC":     true,
		"PSYNC":    true,
		"REPLCONF": true,
		"SLAVEOF":  true,
		"REPLICAOF": true,

		// Monitoring (can leak sensitive info)
		"MONITOR": true,
		"CLIENT":  true,

		// Script execution (potential security risk)
		"EVAL":    true,
		"EVALSHA": true,
		"SCRIPT":  true,

		// Data migration (can be abused)
		"MIGRATE": true,
		"DUMP":    true,
		"RESTORE": true,

		// Cluster management
		"CLUSTER": true,

		// Module management
		"MODULE": true,

		// ACL management (if blocking admin operations)
		"ACL": true,

		// Info commands (can leak topology)
		"INFO":    true,
		"SLOWLOG": true,
		"LATENCY": true,
	}

	cmdUpper := strings.ToUpper(cmd.Command)
	return dangerousCommands[cmdUpper]
}

// isWriteCommand determines if a Redis command is a write operation
func (h *RedisHandler) isWriteCommand(command string) bool {
	writeCommands := map[string]bool{
		// String operations
		"SET": true, "SETNX": true, "SETEX": true, "PSETEX": true,
		"MSET": true, "MSETNX": true, "APPEND": true, "SETRANGE": true,
		"INCR": true, "INCRBY": true, "INCRBYFLOAT": true,
		"DECR": true, "DECRBY": true,
		"GETSET": true, "GETDEL": true,

		// Key operations
		"DEL": true, "UNLINK": true,
		"EXPIRE": true, "EXPIREAT": true, "PEXPIRE": true, "PEXPIREAT": true,
		"PERSIST": true, "RENAME": true, "RENAMENX": true,
		"RESTORE": true, "MIGRATE": true,

		// Hash operations
		"HSET": true, "HSETNX": true, "HMSET": true,
		"HINCRBY": true, "HINCRBYFLOAT": true, "HDEL": true,

		// List operations
		"LPUSH": true, "LPUSHX": true, "RPUSH": true, "RPUSHX": true,
		"LPOP": true, "RPOP": true, "BLPOP": true, "BRPOP": true,
		"LREM": true, "LSET": true, "LTRIM": true, "LINSERT": true,
		"RPOPLPUSH": true, "BRPOPLPUSH": true, "LMOVE": true, "BLMOVE": true,

		// Set operations
		"SADD": true, "SREM": true, "SPOP": true, "SMOVE": true,

		// Sorted set operations
		"ZADD": true, "ZREM": true, "ZINCRBY": true,
		"ZREMRANGEBYSCORE": true, "ZREMRANGEBYRANK": true, "ZREMRANGEBYLEX": true,
		"ZPOPMIN": true, "ZPOPMAX": true, "BZPOPMIN": true, "BZPOPMAX": true,

		// Stream operations
		"XADD": true, "XDEL": true, "XTRIM": true,
		"XACK": true, "XGROUP": true, "XCLAIM": true,

		// Bitmap operations
		"SETBIT": true, "BITFIELD": true,

		// HyperLogLog operations
		"PFADD": true, "PFMERGE": true,

		// Geospatial operations
		"GEOADD": true,

		// Database operations
		"FLUSHDB": true, "FLUSHALL": true, "SELECT": true, "SWAPDB": true,

		// Transaction operations
		"MULTI": true, "EXEC": true, "DISCARD": true,
		"WATCH": true, "UNWATCH": true,

		// Pub/Sub operations (writes to channels)
		"PUBLISH": true,

		// Scripting
		"EVAL": true, "EVALSHA": true, "SCRIPT": true,
	}

	cmdUpper := strings.ToUpper(command)
	return writeCommands[cmdUpper]
}

// sendError sends a Redis error response to the client
func (h *RedisHandler) sendError(conn net.Conn, message string) {
	// Redis error response format: -ERR message\r\n
	errorResponse := fmt.Sprintf("-ERR %s\r\n", message)
	conn.Write([]byte(errorResponse))
}

// getBackendConnection retrieves a backend connection
func (h *RedisHandler) getBackendConnection() (net.Conn, error) {
	// Try to get from pool first
	conn, err := h.pool.Get(h.protocol)
	if err == nil {
		return conn, nil
	}

	// Pool might not be available, create direct connection
	// This requires backend configuration - for now use round-robin selection
	backend := h.selectBackend()
	if backend == nil {
		return nil, fmt.Errorf("no backend available for Redis")
	}

	return h.connectToBackend(backend)
}

// releaseBackendConnection returns a connection to the pool
func (h *RedisHandler) releaseBackendConnection(conn net.Conn) {
	if conn != nil {
		h.pool.Put(h.protocol, conn)
	}
}

// selectBackend selects a backend using round-robin
func (h *RedisHandler) selectBackend() *config.RouteConfig {
	// Find Redis routes in configuration
	var redisRoutes []config.RouteConfig
	for _, route := range h.config.Routes {
		if route.Protocol == "redis" {
			redisRoutes = append(redisRoutes, route)
		}
	}

	if len(redisRoutes) == 0 {
		return nil
	}

	// Round-robin selection
	idx := atomic.AddUint64(&h.roundRobin, 1) % uint64(len(redisRoutes))
	return &redisRoutes[idx]
}

// connectToBackend creates a connection to a backend
func (h *RedisHandler) connectToBackend(backend *config.RouteConfig) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", backend.BackendHost, backend.BackendPort)
	return net.Dial("tcp", address)
}

// isRunning returns whether the handler is running
func (h *RedisHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}
