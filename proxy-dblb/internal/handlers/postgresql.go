package handlers

import (
	"context"
	"encoding/binary"
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

// PostgreSQLHandler implements the Handler interface for PostgreSQL protocol
type PostgreSQLHandler struct {
	config          *config.Config
	route           *config.RouteConfig
	pool            *pool.Pool
	securityChecker *security.Checker
	logger          *logrus.Logger
	listener        net.Listener
	ctx             context.Context
	cancel          context.CancelFunc
	running         bool
	mu              sync.RWMutex

	// Statistics
	activeConns   int64
	totalConns    int64
	totalQueries  int64
	writeQueries  int64
	readQueries   int64
	blockedQueries int64
	authFailures  int64
	authSuccesses int64

	// Round-robin for backend selection
	roundRobin uint64
}

// NewPostgreSQLHandler creates a new PostgreSQL protocol handler
func NewPostgreSQLHandler(
	cfg *config.Config,
	route *config.RouteConfig,
	poolManager *pool.Pool,
	secChecker *security.Checker,
	logger *logrus.Logger,
) *PostgreSQLHandler {
	return &PostgreSQLHandler{
		config:          cfg,
		route:           route,
		pool:            poolManager,
		securityChecker: secChecker,
		logger:          logger,
	}
}

// Start implements the Handler interface
func (h *PostgreSQLHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("PostgreSQL handler already running")
	}

	// Create listener
	addr := fmt.Sprintf(":%d", h.route.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	h.listener = listener
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.running = true

	// Start accepting connections
	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"protocol": "postgresql",
		"port":     h.route.ListenPort,
		"route":    h.route.Name,
	}).Info("PostgreSQL handler started")

	return nil
}

// Stop implements the Handler interface
func (h *PostgreSQLHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("route", h.route.Name).Info("Stopping PostgreSQL handler")

	if h.cancel != nil {
		h.cancel()
	}

	if h.listener != nil {
		h.listener.Close()
	}

	h.running = false
	return nil
}

// GetStats implements the Handler interface
func (h *PostgreSQLHandler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"protocol":        "postgresql",
		"route":           h.route.Name,
		"port":            h.route.ListenPort,
		"active_conns":    atomic.LoadInt64(&h.activeConns),
		"total_conns":     atomic.LoadInt64(&h.totalConns),
		"total_queries":   atomic.LoadInt64(&h.totalQueries),
		"write_queries":   atomic.LoadInt64(&h.writeQueries),
		"read_queries":    atomic.LoadInt64(&h.readQueries),
		"blocked_queries": atomic.LoadInt64(&h.blockedQueries),
		"auth_failures":   atomic.LoadInt64(&h.authFailures),
		"auth_successes":  atomic.LoadInt64(&h.authSuccesses),
		"running":         h.isRunning(),
	}
}

// acceptConnections accepts incoming PostgreSQL connections
func (h *PostgreSQLHandler) acceptConnections() {
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
				h.logger.WithError(err).Error("Failed to accept PostgreSQL connection")
				continue
			}

			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single PostgreSQL client connection
func (h *PostgreSQLHandler) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Update connection metrics
	atomic.AddInt64(&h.activeConns, 1)
	atomic.AddInt64(&h.totalConns, 1)
	metrics.IncConnection("postgresql")
	defer func() {
		atomic.AddInt64(&h.activeConns, -1)
		metrics.DecConnection("postgresql")
	}()

	// Perform PostgreSQL handshake
	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.WithError(err).Error("PostgreSQL handshake failed")
		atomic.AddInt64(&h.authFailures, 1)
		metrics.IncAuthFailure("postgresql", "unknown")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user":     username,
		"database": database,
		"route":    h.route.Name,
	}).Debug("PostgreSQL connection authenticated")

	atomic.AddInt64(&h.authSuccesses, 1)
	metrics.IncAuthSuccess("postgresql", username)

	// Get backend connection from pool
	backendConn, err := h.pool.Get("postgresql")
	if err != nil {
		h.logger.WithError(err).Error("Failed to get backend connection")
		h.sendError(clientConn, "Backend connection unavailable")
		return
	}
	defer h.pool.Put("postgresql", backendConn)

	// Proxy traffic between client and backend
	h.proxyTraffic(clientConn, backendConn, username, database)
}

// performHandshake handles the PostgreSQL startup handshake
func (h *PostgreSQLHandler) performHandshake(conn net.Conn) (string, string, error) {
	// Read startup message
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read startup message: %w", err)
	}

	if n < 8 {
		return "", "", fmt.Errorf("invalid startup message: too short")
	}

	// Parse message length and protocol version
	length := binary.BigEndian.Uint32(buf[0:4])
	protocolVersion := binary.BigEndian.Uint32(buf[4:8])

	h.logger.WithFields(logrus.Fields{
		"length":           length,
		"protocol_version": protocolVersion,
	}).Debug("PostgreSQL startup message received")

	// Parse connection parameters
	params := h.parseStartupParams(buf[8:n])

	username := params["user"]
	if username == "" {
		username = "unknown"
	}

	database := params["database"]
	if database == "" {
		database = username // PostgreSQL defaults to username as database
	}

	// Check route authentication if enabled
	if h.route.EnableAuth {
		if username != h.route.Username {
			h.sendError(conn, "Authentication failed: invalid username")
			return "", "", fmt.Errorf("authentication failed: invalid username")
		}
	}

	// Send authentication OK (AuthenticationOk = 'R' + length + 0)
	authOk := []byte{'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(authOk); err != nil {
		return "", "", fmt.Errorf("failed to send auth OK: %w", err)
	}

	// Send backend key data (BackendKeyData = 'K' + length + process_id + secret_key)
	keyData := []byte{'K', 0x00, 0x00, 0x00, 0x0C}
	keyData = append(keyData, 0x00, 0x00, 0x00, 0x01) // process ID
	keyData = append(keyData, 0x00, 0x00, 0x00, 0x01) // secret key
	if _, err := conn.Write(keyData); err != nil {
		return "", "", fmt.Errorf("failed to send backend key data: %w", err)
	}

	// Send ready for query (ReadyForQuery = 'Z' + length + status)
	readyForQuery := []byte{'Z', 0x00, 0x00, 0x00, 0x05, 'I'} // 'I' = idle
	if _, err := conn.Write(readyForQuery); err != nil {
		return "", "", fmt.Errorf("failed to send ready for query: %w", err)
	}

	return username, database, nil
}

// parseStartupParams parses PostgreSQL startup message parameters
func (h *PostgreSQLHandler) parseStartupParams(data []byte) map[string]string {
	params := make(map[string]string)
	i := 0

	for i < len(data) {
		// Find null terminator for key
		keyStart := i
		for i < len(data) && data[i] != 0 {
			i++
		}
		if i >= len(data) {
			break
		}
		key := string(data[keyStart:i])
		i++ // skip null terminator

		if key == "" {
			break // End of parameters
		}

		// Find null terminator for value
		valueStart := i
		for i < len(data) && data[i] != 0 {
			i++
		}
		if i > len(data) {
			break
		}
		value := string(data[valueStart:i])
		i++ // skip null terminator

		params[key] = value
	}

	return params
}

// sendError sends a PostgreSQL error message to the client
func (h *PostgreSQLHandler) sendError(conn net.Conn, message string) {
	// ErrorResponse = 'E' + length + fields
	errorMsg := fmt.Sprintf("SERROR\x00CFATAL\x00M%s\x00\x00", message)

	// Calculate length (includes length field itself)
	length := uint32(len(errorMsg) + 4)

	response := []byte{'E'}
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, length)
	response = append(response, lengthBytes...)
	response = append(response, []byte(errorMsg)...)

	conn.Write(response)
}

// proxyTraffic proxies traffic between client and backend with security inspection
func (h *PostgreSQLHandler) proxyTraffic(client, backend net.Conn, username, database string) {
	var wg sync.WaitGroup
	wg.Add(2)

	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()

	// Client to backend (with query inspection)
	go func() {
		defer wg.Done()
		defer cancel()

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

				// Inspect query for security threats
				if h.config.EnableSQLInjectionDetection {
					query := h.extractQuery(buf[:n])
					if query != "" {
						atomic.AddInt64(&h.totalQueries, 1)

						// Check for SQL injection
						if malicious, reason := h.securityChecker.CheckQuery(query); malicious {
							h.logger.WithFields(logrus.Fields{
								"user":     username,
								"database": database,
								"reason":   reason,
								"query":    h.truncateQuery(query, 100),
							}).Warn("Blocked malicious query")

							atomic.AddInt64(&h.blockedQueries, 1)
							metrics.IncSQLInjection("postgresql")

							if h.config.BlockSuspiciousQueries {
								h.sendError(client, "Query blocked: "+reason)
								return
							}
						}

						// Track query types
						if h.isWriteQuery(query) {
							atomic.AddInt64(&h.writeQueries, 1)
							metrics.IncQuery("postgresql", true)
						} else {
							atomic.AddInt64(&h.readQueries, 1)
							metrics.IncQuery("postgresql", false)
						}
					}
				}

				// Forward to backend
				if _, err := backend.Write(buf[:n]); err != nil {
					h.logger.WithError(err).Debug("Backend write error")
					return
				}

				metrics.AddBytesTransferred("postgresql", "upstream", int64(n))
			}
		}
	}()

	// Backend to client
	go func() {
		defer wg.Done()
		defer cancel()

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

				metrics.AddBytesTransferred("postgresql", "downstream", int64(n))
			}
		}
	}()

	wg.Wait()
}

// extractQuery attempts to extract SQL query from PostgreSQL protocol message
func (h *PostgreSQLHandler) extractQuery(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// PostgreSQL message format: Type (1 byte) + Length (4 bytes) + Payload
	msgType := data[0]

	// 'Q' = Simple Query
	if msgType == 'Q' {
		// Query text is null-terminated string starting at byte 5
		queryBytes := data[5:]
		for i, b := range queryBytes {
			if b == 0 {
				return string(queryBytes[:i])
			}
		}
		return string(queryBytes)
	}

	// 'P' = Parse (prepared statement)
	if msgType == 'P' {
		// Parse message contains prepared statement query
		// Format: name\0query\0param_types
		payload := data[5:]
		// Skip statement name
		nameEnd := 0
		for nameEnd < len(payload) && payload[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd+1 >= len(payload) {
			return ""
		}
		queryStart := nameEnd + 1
		queryBytes := payload[queryStart:]
		for i, b := range queryBytes {
			if b == 0 {
				return string(queryBytes[:i])
			}
		}
		return string(queryBytes)
	}

	return ""
}

// isWriteQuery checks if a query is a write operation
func (h *PostgreSQLHandler) isWriteQuery(query string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(query))

	writeKeywords := []string{
		"INSERT", "UPDATE", "DELETE", "CREATE", "DROP",
		"ALTER", "TRUNCATE", "REPLACE", "MERGE",
	}

	for _, keyword := range writeKeywords {
		if strings.HasPrefix(normalized, keyword) {
			return true
		}
	}

	return false
}

// truncateQuery truncates a query to specified length for logging
func (h *PostgreSQLHandler) truncateQuery(query string, maxLen int) string {
	if len(query) <= maxLen {
		return query
	}
	return query[:maxLen] + "..."
}

// isRunning returns whether the handler is currently running
func (h *PostgreSQLHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// SetDeadline sets read/write deadlines on a connection (helper for timeout handling)
func (h *PostgreSQLHandler) setDeadline(conn net.Conn, timeout time.Duration) {
	if timeout > 0 {
		deadline := time.Now().Add(timeout)
		conn.SetDeadline(deadline)
	}
}
