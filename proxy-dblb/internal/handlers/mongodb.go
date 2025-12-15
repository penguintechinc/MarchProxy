package handlers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/metrics"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"

	"github.com/sirupsen/logrus"
)

// MongoDBHandler implements the Handler interface for MongoDB protocol
type MongoDBHandler struct {
	protocol        string
	port            int
	backendHost     string
	backendPort     int
	pool            *pool.Pool
	securityChecker *security.Checker
	config          *config.Config
	logger          *logrus.Logger
	listener        net.Listener
	roundRobin      uint64
	activeConns     int64
	totalConns      int64
	totalQueries    int64
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewMongoDBHandler creates a new MongoDB protocol handler
func NewMongoDBHandler(
	port int,
	backendHost string,
	backendPort int,
	p *pool.Pool,
	securityChecker *security.Checker,
	cfg *config.Config,
	logger *logrus.Logger,
) *MongoDBHandler {
	return &MongoDBHandler{
		protocol:        "mongodb",
		port:            port,
		backendHost:     backendHost,
		backendPort:     backendPort,
		pool:            p,
		securityChecker: securityChecker,
		config:          cfg,
		logger:          logger,
	}
}

// Start starts the MongoDB handler
func (h *MongoDBHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("MongoDB handler already running")
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
	}).Info("MongoDB handler started")

	return nil
}

// Stop stops the MongoDB handler
func (h *MongoDBHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("protocol", h.protocol).Info("Stopping MongoDB handler")

	if h.cancel != nil {
		h.cancel()
	}

	if h.listener != nil {
		h.listener.Close()
	}

	h.running = false
	return nil
}

// GetStats returns handler statistics
func (h *MongoDBHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"protocol":      h.protocol,
		"port":          h.port,
		"active_conns":  h.activeConns,
		"total_conns":   h.totalConns,
		"total_queries": h.totalQueries,
		"running":       h.running,
	}
}

// acceptConnections accepts incoming MongoDB connections
func (h *MongoDBHandler) acceptConnections() {
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
				h.logger.WithError(err).Error("Failed to accept MongoDB connection")
				continue
			}

			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single MongoDB connection
func (h *MongoDBHandler) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	atomic.AddInt64(&h.activeConns, 1)
	atomic.AddInt64(&h.totalConns, 1)
	metrics.IncConnection(h.protocol)

	defer func() {
		atomic.AddInt64(&h.activeConns, -1)
		metrics.DecConnection(h.protocol)
	}()

	// Perform MongoDB handshake
	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.WithError(err).Error("MongoDB handshake failed")
		metrics.IncAuthFailure(h.protocol, "unknown")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"username": username,
		"database": database,
	}).Debug("MongoDB handshake completed")

	// Connect to backend
	backendAddr := fmt.Sprintf("%s:%d", h.backendHost, h.backendPort)
	backendConn, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		h.logger.WithError(err).Error("Failed to connect to MongoDB backend")
		h.sendError(clientConn, "Backend connection failed")
		metrics.IncBackendError(h.protocol)
		return
	}
	defer backendConn.Close()

	// Proxy traffic with MongoDB-aware monitoring
	h.proxyTraffic(h.ctx, clientConn, backendConn, username, database)
}

// performHandshake performs MongoDB wire protocol handshake
func (h *MongoDBHandler) performHandshake(conn net.Conn) (string, string, error) {
	// Set read deadline for handshake
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read handshake: %w", err)
	}

	if n < 16 {
		return "", "", fmt.Errorf("invalid MongoDB handshake packet: too short")
	}

	username := "unknown"
	database := "admin"

	// Parse MongoDB wire protocol message
	// MongoDB wire protocol format:
	// - bytes 0-3: message length (int32)
	// - bytes 4-7: request ID (int32)
	// - bytes 8-11: response to (int32)
	// - bytes 12-15: opcode (int32)
	// - bytes 16+: message body

	messageLength := int(binary.LittleEndian.Uint32(buf[0:4]))
	opcode := int(binary.LittleEndian.Uint32(buf[12:16]))

	h.logger.WithFields(logrus.Fields{
		"message_length": messageLength,
		"opcode":         opcode,
		"bytes_read":     n,
	}).Debug("MongoDB handshake received")

	// Extract username and database from handshake message
	// This is a simplified parsing - real implementation should use BSON parser
	message := string(buf[16:n])

	// Look for common authentication fields
	if idx := strings.Index(message, "user"); idx != -1 && idx+10 < len(message) {
		start := idx + 5
		end := start
		for end < len(message) && message[end] != 0 && end-start < 100 {
			end++
		}
		if end > start {
			extracted := strings.TrimSpace(message[start:end])
			if len(extracted) > 0 && len(extracted) < 64 {
				username = extracted
			}
		}
	}

	// Look for database field
	if idx := strings.Index(message, "db"); idx != -1 && idx+10 < len(message) {
		start := idx + 3
		end := start
		for end < len(message) && message[end] != 0 && end-start < 100 {
			end++
		}
		if end > start {
			extracted := strings.TrimSpace(message[start:end])
			if len(extracted) > 0 && len(extracted) < 64 {
				database = extracted
			}
		}
	}

	// Send handshake acknowledgment
	// This is a simplified response - real implementation should handle full protocol
	response := h.buildHandshakeResponse()
	if _, err := conn.Write(response); err != nil {
		return "", "", fmt.Errorf("failed to send handshake response: %w", err)
	}

	return username, database, nil
}

// buildHandshakeResponse builds a MongoDB handshake response
func (h *MongoDBHandler) buildHandshakeResponse() []byte {
	// Simplified OP_REPLY response
	response := make([]byte, 36)

	// Message length
	binary.LittleEndian.PutUint32(response[0:4], 36)

	// Request ID
	binary.LittleEndian.PutUint32(response[4:8], 1)

	// Response to
	binary.LittleEndian.PutUint32(response[8:12], 0)

	// OpCode (OP_REPLY = 1)
	binary.LittleEndian.PutUint32(response[12:16], 1)

	// Response flags
	binary.LittleEndian.PutUint32(response[16:20], 0)

	// Cursor ID
	binary.LittleEndian.PutUint64(response[20:28], 0)

	// Starting from
	binary.LittleEndian.PutUint32(response[28:32], 0)

	// Number returned
	binary.LittleEndian.PutUint32(response[32:36], 1)

	return response
}

// sendError sends a MongoDB error response to the client
func (h *MongoDBHandler) sendError(conn net.Conn, message string) {
	errorDoc := map[string]interface{}{
		"ok":       0,
		"errmsg":   message,
		"code":     18,
		"codeName": "AuthenticationFailed",
	}

	errorJSON, _ := json.Marshal(errorDoc)

	// Build OP_REPLY with error
	header := make([]byte, 36)
	messageLength := 36 + len(errorJSON)

	binary.LittleEndian.PutUint32(header[0:4], uint32(messageLength))
	binary.LittleEndian.PutUint32(header[4:8], 2)
	binary.LittleEndian.PutUint32(header[8:12], 0)
	binary.LittleEndian.PutUint32(header[12:16], 1) // OP_REPLY
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint64(header[20:28], 0)
	binary.LittleEndian.PutUint32(header[28:32], 0)
	binary.LittleEndian.PutUint32(header[32:36], 1)

	response := append(header, errorJSON...)
	conn.Write(response)
}

// proxyTraffic proxies bidirectional MongoDB traffic with security checks
func (h *MongoDBHandler) proxyTraffic(
	ctx context.Context,
	clientConn net.Conn,
	backendConn net.Conn,
	username string,
	database string,
) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to backend with security checks
	go func() {
		defer wg.Done()
		h.proxyClientToBackend(ctx, clientConn, backendConn, username, database)
	}()

	// Backend to client
	go func() {
		defer wg.Done()
		h.proxyBackendToClient(ctx, backendConn, clientConn)
	}()

	wg.Wait()
}

// proxyClientToBackend proxies client to backend with MongoDB command inspection
func (h *MongoDBHandler) proxyClientToBackend(
	ctx context.Context,
	client net.Conn,
	backend net.Conn,
	username string,
	database string,
) {
	buf := make([]byte, 32*1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := client.Read(buf)
			if err != nil {
				if err != io.EOF {
					h.logger.WithError(err).Debug("Client read error")
				}
				return
			}

			// Parse MongoDB command for monitoring and security
			cmd := h.parseMongoCommand(buf[:n])

			// Security check for blocked operations
			if h.config.BlockSuspiciousQueries && h.isBlockedMongoOperation(cmd) {
				h.logger.WithFields(logrus.Fields{
					"username":   username,
					"database":   database,
					"operation":  cmd.Operation,
					"collection": cmd.Collection,
				}).Warn("Blocked dangerous MongoDB operation")

				metrics.IncSQLInjection(h.protocol)
				h.sendError(client, "Operation blocked by security policy")
				return
			}

			// Check for suspicious patterns using security checker
			if h.config.EnableSQLInjectionDetection {
				if blocked, reason := h.securityChecker.CheckData(buf[:n]); blocked {
					h.logger.WithFields(logrus.Fields{
						"username": username,
						"database": database,
						"reason":   reason,
					}).Warn("Blocked suspicious MongoDB command")

					metrics.IncSQLInjection(h.protocol)
					h.sendError(client, "Command blocked: "+reason)
					return
				}
			}

			// Record query metrics
			atomic.AddInt64(&h.totalQueries, 1)
			metrics.IncQuery(h.protocol, h.isWriteOperation(cmd.Operation))

			// Forward to backend
			if _, err := backend.Write(buf[:n]); err != nil {
				h.logger.WithError(err).Debug("Backend write error")
				return
			}

			// Record bytes transferred
			metrics.RecordBytesTransferred(h.protocol, "outbound", int64(n))
		}
	}
}

// proxyBackendToClient proxies backend to client
func (h *MongoDBHandler) proxyBackendToClient(
	ctx context.Context,
	backend net.Conn,
	client net.Conn,
) {
	buf := make([]byte, 32*1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := backend.Read(buf)
			if err != nil {
				if err != io.EOF {
					h.logger.WithError(err).Debug("Backend read error")
				}
				return
			}

			if _, err := client.Write(buf[:n]); err != nil {
				h.logger.WithError(err).Debug("Client write error")
				return
			}

			// Record bytes transferred
			metrics.RecordBytesTransferred(h.protocol, "inbound", int64(n))
		}
	}
}

// MongoCommand represents a parsed MongoDB command
type MongoCommand struct {
	Operation  string
	Database   string
	Collection string
	OpCode     int32
}

// parseMongoCommand parses a MongoDB wire protocol message
func (h *MongoDBHandler) parseMongoCommand(data []byte) MongoCommand {
	cmd := MongoCommand{
		Operation:  "unknown",
		Database:   "unknown",
		Collection: "unknown",
	}

	if len(data) < 16 {
		return cmd
	}

	// Parse opcode
	cmd.OpCode = int32(binary.LittleEndian.Uint32(data[12:16]))

	// Parse message body for operation type
	// This is simplified - real implementation should use BSON parser
	if len(data) > 16 {
		message := strings.ToLower(string(data[16:]))

		// Detect operation type from message content
		operations := map[string]string{
			"find":        "find",
			"insert":      "insert",
			"update":      "update",
			"delete":      "delete",
			"remove":      "delete",
			"drop":        "drop",
			"create":      "create",
			"count":       "count",
			"aggregate":   "aggregate",
			"mapredu":     "mapreduce",
			"eval":        "eval",
			"group":       "group",
			"distinct":    "distinct",
			"createindex": "createindex",
			"dropindex":   "dropindex",
		}

		for pattern, op := range operations {
			if strings.Contains(message, pattern) {
				cmd.Operation = op
				break
			}
		}

		// Try to extract collection name
		// Look for collection field in BSON-like structure
		if idx := strings.Index(message, "collection"); idx != -1 && idx+15 < len(message) {
			start := idx + 11
			end := start
			for end < len(message) && end-start < 100 {
				if message[end] == 0 || message[end] == '"' || message[end] == '\'' {
					break
				}
				end++
			}
			if end > start {
				cmd.Collection = strings.TrimSpace(message[start:end])
			}
		}
	}

	return cmd
}

// isBlockedMongoOperation checks if a MongoDB operation should be blocked
func (h *MongoDBHandler) isBlockedMongoOperation(cmd MongoCommand) bool {
	// Block dangerous operations
	dangerousOps := map[string]bool{
		"eval":         true, // Server-side JavaScript execution
		"mapreduce":    true, // Can execute arbitrary JavaScript
		"group":        true, // Can execute arbitrary JavaScript
		"where":        true, // JavaScript evaluation in queries
		"copydb":       true, // Database copying
		"clone":        true, // Database cloning
		"shutdown":     true, // Server shutdown
		"killop":       true, // Kill operations
		"fsync":        true, // Force filesystem sync
		"dropdatabase": true, // Drop entire database
	}

	if dangerousOps[strings.ToLower(cmd.Operation)] {
		return true
	}

	// Block operations on system collections
	systemCollections := []string{
		"system.users",
		"system.roles",
		"system.version",
		"system.replset",
		"system.indexbuilds",
		"system.profile",
		"system.js",
	}

	collection := strings.ToLower(cmd.Collection)
	for _, sysCol := range systemCollections {
		if collection == sysCol || strings.HasPrefix(collection, "system.") {
			return true
		}
	}

	return false
}

// isWriteOperation checks if a MongoDB operation is a write operation
func (h *MongoDBHandler) isWriteOperation(operation string) bool {
	writeOps := map[string]bool{
		"insert":           true,
		"update":           true,
		"delete":           true,
		"remove":           true,
		"save":             true,
		"drop":             true,
		"dropdatabase":     true,
		"createindex":      true,
		"dropindex":        true,
		"dropindexes":      true,
		"create":           true,
		"converttocapped":  true,
		"emptycapped":      true,
		"renamecollection": true,
	}

	return writeOps[strings.ToLower(operation)]
}

// isRunning returns whether the handler is running
func (h *MongoDBHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}
