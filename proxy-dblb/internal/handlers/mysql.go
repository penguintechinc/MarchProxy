package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// MySQLHandler implements the Handler interface for MySQL protocol
type MySQLHandler struct {
	config          *config.Config
	route           *config.RouteConfig
	pool            *pool.Pool
	sqlPools        map[string]*sql.DB
	securityChecker *security.Checker
	logger          *logrus.Logger
	listener        net.Listener
	connLimiter     *rate.Limiter
	queryLimiter    *rate.Limiter
	roundRobin      uint64
	activeConns     int64
	totalConns      int64
	totalQueries    int64
	readQueries     int64
	writeQueries    int64
	blockedQueries  int64
	poolMu          sync.RWMutex
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// NewMySQLHandler creates a new MySQL protocol handler
func NewMySQLHandler(route *config.RouteConfig, p *pool.Pool, securityChecker *security.Checker, cfg *config.Config, logger *logrus.Logger) *MySQLHandler {
	if route.Protocol != "mysql" {
		logger.Warnf("Invalid protocol %s for MySQL handler, expected 'mysql'", route.Protocol)
	}

	connRate := route.ConnectionRate
	if connRate <= 0 {
		connRate = cfg.DefaultConnectionRate
	}

	queryRate := route.QueryRate
	if queryRate <= 0 {
		queryRate = cfg.DefaultQueryRate
	}

	return &MySQLHandler{
		config:          cfg,
		route:           route,
		pool:            p,
		sqlPools:        make(map[string]*sql.DB),
		securityChecker: securityChecker,
		logger:          logger,
		connLimiter:     rate.NewLimiter(rate.Limit(connRate), int(connRate)),
		queryLimiter:    rate.NewLimiter(rate.Limit(queryRate), int(queryRate)),
	}
}

// Start starts the MySQL handler and begins accepting connections
func (h *MySQLHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("MySQL handler already running on port %d", h.route.ListenPort)
	}

	// Initialize connection pools
	if err := h.initSQLPools(); err != nil {
		return fmt.Errorf("failed to initialize SQL pools: %w", err)
	}

	// Start listening
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.route.ListenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.route.ListenPort, err)
	}

	h.listener = listener
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.running = true

	// Start accepting connections
	h.wg.Add(1)
	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"protocol": h.route.Protocol,
		"port":     h.route.ListenPort,
		"backend":  fmt.Sprintf("%s:%d", h.route.BackendHost, h.route.BackendPort),
	}).Info("MySQL handler started")

	return nil
}

// Stop stops the MySQL handler
func (h *MySQLHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("port", h.route.ListenPort).Info("Stopping MySQL handler")

	// Cancel context to stop all goroutines
	if h.cancel != nil {
		h.cancel()
	}

	// Close listener
	if h.listener != nil {
		h.listener.Close()
	}

	// Wait for all connections to finish
	h.wg.Wait()

	// Close SQL connection pools
	h.closeSQLPools()

	h.running = false
	return nil
}

// GetStats returns handler statistics
func (h *MySQLHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"protocol":        h.route.Protocol,
		"port":            h.route.ListenPort,
		"backend":         fmt.Sprintf("%s:%d", h.route.BackendHost, h.route.BackendPort),
		"active_conns":    atomic.LoadInt64(&h.activeConns),
		"total_conns":     atomic.LoadInt64(&h.totalConns),
		"total_queries":   atomic.LoadInt64(&h.totalQueries),
		"read_queries":    atomic.LoadInt64(&h.readQueries),
		"write_queries":   atomic.LoadInt64(&h.writeQueries),
		"blocked_queries": atomic.LoadInt64(&h.blockedQueries),
		"running":         h.running,
	}
}

// initSQLPools initializes database connection pools for backends
func (h *MySQLHandler) initSQLPools() error {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	// Build DSN for backend
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true&timeout=10s",
		h.route.Username,
		h.route.Password,
		h.route.BackendHost,
		h.route.BackendPort)

	if h.route.EnableSSL {
		dsn += "&tls=true"
	}

	// Create SQL connection pool
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	// Configure connection pool
	maxConns := h.route.MaxConnections
	if maxConns <= 0 {
		maxConns = h.config.MaxConnectionsPerRoute
	}

	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns / 2)
	db.SetConnMaxLifetime(h.config.ConnectionMaxLifetime)
	db.SetConnMaxIdleTime(h.config.ConnectionIdleTimeout)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping backend: %w", err)
	}

	key := fmt.Sprintf("%s:%d", h.route.BackendHost, h.route.BackendPort)
	h.sqlPools[key] = db

	h.logger.WithFields(logrus.Fields{
		"backend":   key,
		"max_conns": maxConns,
	}).Info("MySQL connection pool initialized")

	return nil
}

// closeSQLPools closes all SQL connection pools
func (h *MySQLHandler) closeSQLPools() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	for key, db := range h.sqlPools {
		if err := db.Close(); err != nil {
			h.logger.WithError(err).Errorf("Failed to close SQL pool for %s", key)
		} else {
			h.logger.WithField("backend", key).Info("SQL connection pool closed")
		}
	}

	h.sqlPools = make(map[string]*sql.DB)
}

// acceptConnections accepts incoming MySQL connections
func (h *MySQLHandler) acceptConnections() {
	defer h.wg.Done()

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
				h.logger.WithError(err).Error("Failed to accept MySQL connection")
				continue
			}

			// Apply connection rate limiting
			if h.config.EnableRateLimiting && !h.connLimiter.Allow() {
				h.logger.Warn("MySQL connection rate limit exceeded")
				conn.Close()
				continue
			}

			// Handle connection in new goroutine
			h.wg.Add(1)
			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single MySQL client connection
func (h *MySQLHandler) handleConnection(clientConn net.Conn) {
	defer h.wg.Done()
	defer clientConn.Close()

	atomic.AddInt64(&h.activeConns, 1)
	defer atomic.AddInt64(&h.activeConns, -1)
	atomic.AddInt64(&h.totalConns, 1)

	// Perform MySQL handshake
	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.WithError(err).Error("MySQL handshake failed")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"username": username,
		"database": database,
		"client":   clientConn.RemoteAddr().String(),
	}).Debug("MySQL handshake completed")

	// Get backend connection
	backendConn, err := h.getBackendConnection()
	if err != nil {
		h.logger.WithError(err).Error("Failed to get MySQL backend connection")
		h.sendError(clientConn, "Backend connection failed")
		return
	}
	defer backendConn.Close()

	// Proxy traffic between client and backend
	h.proxyTraffic(clientConn, backendConn, username, database)
}

// performHandshake performs the MySQL protocol handshake
func (h *MySQLHandler) performHandshake(conn net.Conn) (string, string, error) {
	// Send initial handshake packet
	greeting := h.buildHandshakePacket()
	if _, err := conn.Write(greeting); err != nil {
		return "", "", fmt.Errorf("failed to send handshake: %w", err)
	}

	// Read handshake response from client
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read handshake response: %w", err)
	}

	if n < 36 {
		return "", "", fmt.Errorf("invalid handshake packet: too short")
	}

	// Parse username and database from handshake response
	username, database := h.parseHandshakeResponse(buf[:n])

	// Send OK packet
	okPacket := []byte{
		0x07, 0x00, 0x00, 0x02, // header
		0x00, 0x00, 0x00, // OK packet
		0x02, 0x00, 0x00, 0x00, // status flags
	}
	if _, err := conn.Write(okPacket); err != nil {
		return username, database, fmt.Errorf("failed to send OK packet: %w", err)
	}

	return username, database, nil
}

// buildHandshakePacket builds the MySQL initial handshake packet
func (h *MySQLHandler) buildHandshakePacket() []byte {
	// MySQL 5.7.33 server greeting packet
	greeting := []byte{
		0x4a, 0x00, 0x00, 0x00, // packet length + sequence
		0x0a,                                     // protocol version 10
		0x35, 0x2e, 0x37, 0x2e, 0x33, 0x33, 0x00, // version "5.7.33"
		0x01, 0x00, 0x00, 0x00, // connection ID
		0x4d, 0x61, 0x72, 0x63, 0x68, 0x50, 0x72, 0x6f, // auth plugin data part 1 "MarchPro"
		0x00,       // filler
		0xff, 0xf7, // capability flags (lower 2 bytes)
		0x08,       // character set (latin1)
		0x02, 0x00, // status flags
		0xff, 0xc1, // capability flags (upper 2 bytes)
		0x15,                                                       // auth plugin data length
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
		0x78, 0x79, 0x44, 0x42, 0x4c, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth plugin data part 2
		0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, // auth plugin name
	}

	return greeting
}

// parseHandshakeResponse parses username and database from client handshake response
func (h *MySQLHandler) parseHandshakeResponse(buf []byte) (string, string) {
	// Skip capability flags, max packet size, charset, reserved bytes (32 bytes total)
	pos := 32

	if pos >= len(buf) {
		return "", ""
	}

	// Extract username (null-terminated string)
	username := ""
	for pos < len(buf) && buf[pos] != 0 {
		username += string(buf[pos])
		pos++
	}
	pos++ // skip null terminator

	// Skip auth response length and auth response data
	if pos < len(buf) {
		authLen := int(buf[pos])
		pos += 1 + authLen
	}

	// Extract database name (null-terminated string)
	database := ""
	if pos < len(buf) {
		for pos < len(buf) && buf[pos] != 0 {
			database += string(buf[pos])
			pos++
		}
	}

	return username, database
}

// sendError sends a MySQL error packet to the client
func (h *MySQLHandler) sendError(conn net.Conn, message string) {
	// MySQL error packet format
	errorPacket := []byte{
		0xff,       // error header
		0x15, 0x04, // error code 1045
		0x23,                         // SQL state marker '#'
		0x48, 0x59, 0x30, 0x30, 0x30, // SQL state "HY000"
	}
	errorPacket = append(errorPacket, []byte(message)...)

	// Add packet header (length + sequence)
	length := len(errorPacket)
	header := []byte{
		byte(length & 0xff),
		byte((length >> 8) & 0xff),
		byte((length >> 16) & 0xff),
		0x01, // sequence number
	}

	packet := append(header, errorPacket...)
	conn.Write(packet)
}

// getBackendConnection retrieves a connection from the SQL pool
func (h *MySQLHandler) getBackendConnection() (*sql.Conn, error) {
	key := fmt.Sprintf("%s:%d", h.route.BackendHost, h.route.BackendPort)

	h.poolMu.RLock()
	db, ok := h.sqlPools[key]
	h.poolMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no SQL pool found for backend %s", key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection from pool: %w", err)
	}

	return conn, nil
}

// proxyTraffic proxies MySQL traffic between client and backend
func (h *MySQLHandler) proxyTraffic(client net.Conn, backend *sql.Conn, username, database string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to backend
	go func() {
		defer wg.Done()
		h.proxyClientToBackend(client, backend, username, database)
	}()

	// Backend to client (results)
	go func() {
		defer wg.Done()
		h.proxyBackendToClient(client, backend)
	}()

	wg.Wait()
}

// proxyClientToBackend forwards queries from client to backend with security checks
func (h *MySQLHandler) proxyClientToBackend(client net.Conn, backend *sql.Conn, username, database string) {
	buf := make([]byte, 32*1024)

	for {
		select {
		case <-h.ctx.Done():
			return
		default:
			// Set read deadline
			client.SetReadDeadline(time.Now().Add(30 * time.Second))

			n, err := client.Read(buf)
			if err != nil {
				return
			}

			// Parse MySQL packet
			if n < 5 {
				continue
			}

			// Extract query from COM_QUERY packet
			if buf[4] == 0x03 { // COM_QUERY command
				query := string(buf[5:n])

				// Apply query rate limiting
				if h.config.EnableRateLimiting && !h.queryLimiter.Allow() {
					h.logger.Warn("MySQL query rate limit exceeded")
					h.sendError(client, "Query rate limit exceeded")
					return
				}

				// Security check for SQL injection
				if h.config.EnableSQLInjectionDetection {
					if isMalicious, reason := h.securityChecker.CheckQuery(query); isMalicious {
						atomic.AddInt64(&h.blockedQueries, 1)

						h.logger.WithFields(logrus.Fields{
							"username": username,
							"database": database,
							"query":    query[:min(100, len(query))],
							"reason":   reason,
							"client":   client.RemoteAddr().String(),
						}).Warn("Blocked suspicious MySQL query")

						if h.config.BlockSuspiciousQueries {
							h.sendError(client, "Query blocked by security policy: "+reason)
							return
						}
					}
				}

				// Track query statistics
				atomic.AddInt64(&h.totalQueries, 1)
				if h.isWriteQuery(query) {
					atomic.AddInt64(&h.writeQueries, 1)
				} else {
					atomic.AddInt64(&h.readQueries, 1)
				}

				h.logger.WithFields(logrus.Fields{
					"username": username,
					"database": database,
					"query":    query[:min(50, len(query))],
					"is_write": h.isWriteQuery(query),
				}).Debug("MySQL query")
			}

			// Forward packet to backend (in a real implementation)
			// For now, we just log since we're using sql.Conn which doesn't support raw packets
			// In production, this would use a raw TCP connection to the backend
		}
	}
}

// proxyBackendToClient forwards results from backend to client
func (h *MySQLHandler) proxyBackendToClient(client net.Conn, backend *sql.Conn) {
	// This would forward result packets from backend to client
	// Implementation depends on whether we use raw TCP or database/sql
	// For now, placeholder implementation
	<-h.ctx.Done()
}

// isWriteQuery determines if a query is a write operation
func (h *MySQLHandler) isWriteQuery(query string) bool {
	queryUpper := []byte(query)
	for i := 0; i < len(queryUpper) && i < 20; i++ {
		if queryUpper[i] >= 'a' && queryUpper[i] <= 'z' {
			queryUpper[i] -= 32 // Convert to uppercase
		}
	}
	queryStr := string(queryUpper)

	// Check for write operations
	writeKeywords := []string{
		"INSERT", "UPDATE", "DELETE", "REPLACE",
		"CREATE", "ALTER", "DROP", "TRUNCATE",
		"GRANT", "REVOKE", "SET", "COMMIT", "ROLLBACK",
	}

	for _, keyword := range writeKeywords {
		if len(queryStr) >= len(keyword) && queryStr[:len(keyword)] == keyword {
			return true
		}
	}

	return false
}

// isRunning returns whether the handler is running
func (h *MySQLHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
