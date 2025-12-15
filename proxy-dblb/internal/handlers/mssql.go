package handlers

import (
	"context"
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
	"golang.org/x/time/rate"
)

// MSSQLHandler implements Handler interface for Microsoft SQL Server (TDS protocol)
type MSSQLHandler struct {
	protocol        string
	route           *config.RouteConfig
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
	roundRobin      uint64
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewMSSQLHandler creates a new MSSQL/TDS protocol handler
func NewMSSQLHandler(route *config.RouteConfig, p *pool.Pool, securityChecker *security.Checker, cfg *config.Config, logger *logrus.Logger) *MSSQLHandler {
	connRate := route.ConnectionRate
	if connRate <= 0 {
		connRate = cfg.DefaultConnectionRate
	}

	queryRate := route.QueryRate
	if queryRate <= 0 {
		queryRate = cfg.DefaultQueryRate
	}

	return &MSSQLHandler{
		protocol:        "mssql",
		route:           route,
		pool:            p,
		securityChecker: securityChecker,
		config:          cfg,
		logger:          logger,
		connLimiter:     rate.NewLimiter(rate.Limit(connRate), int(connRate)),
		queryLimiter:    rate.NewLimiter(rate.Limit(queryRate), int(queryRate)),
	}
}

// Start starts the MSSQL handler
func (h *MSSQLHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("handler already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.route.ListenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.route.ListenPort, err)
	}

	h.listener = listener
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.running = true

	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"protocol": h.protocol,
		"port":     h.route.ListenPort,
		"backend":  fmt.Sprintf("%s:%d", h.route.BackendHost, h.route.BackendPort),
	}).Info("MSSQL handler started")

	return nil
}

// Stop stops the MSSQL handler
func (h *MSSQLHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("protocol", h.protocol).Info("Stopping MSSQL handler")

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
func (h *MSSQLHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"protocol":        h.protocol,
		"port":            h.route.ListenPort,
		"active_conns":    atomic.LoadInt64(&h.activeConns),
		"total_conns":     atomic.LoadInt64(&h.totalConns),
		"total_queries":   atomic.LoadInt64(&h.totalQueries),
		"blocked_queries": atomic.LoadInt64(&h.blockedQueries),
		"running":         h.running,
		"backend":         fmt.Sprintf("%s:%d", h.route.BackendHost, h.route.BackendPort),
	}
}

// acceptConnections accepts incoming connections
func (h *MSSQLHandler) acceptConnections() {
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
				h.logger.WithError(err).Error("Failed to accept MSSQL connection")
				continue
			}

			// Apply connection rate limiting
			if h.config.EnableRateLimiting && !h.connLimiter.Allow() {
				h.logger.Warn("MSSQL connection rate limit exceeded")
				h.sendError(conn, "Connection rate limit exceeded")
				conn.Close()
				continue
			}

			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single MSSQL connection
func (h *MSSQLHandler) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	atomic.AddInt64(&h.activeConns, 1)
	atomic.AddInt64(&h.totalConns, 1)
	metrics.IncConnection(h.protocol)

	defer func() {
		atomic.AddInt64(&h.activeConns, -1)
		metrics.DecConnection(h.protocol)
	}()

	// Perform TDS handshake and extract credentials
	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.WithError(err).Error("TDS handshake failed")
		metrics.IncAuthFailure(h.protocol, "unknown")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"username": username,
		"database": database,
		"protocol": h.protocol,
	}).Debug("MSSQL connection authenticated")

	// Get backend connection from pool
	backendConn, err := h.pool.Get(h.protocol)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get backend connection")
		metrics.IncBackendError(h.protocol)
		h.sendError(clientConn, "Backend connection failed")
		return
	}
	defer h.pool.Put(h.protocol, backendConn)

	// Proxy traffic with security inspection
	h.proxyTrafficWithInspection(h.ctx, clientConn, backendConn, username, database)
}

// performHandshake performs TDS protocol handshake
func (h *MSSQLHandler) performHandshake(conn net.Conn) (string, string, error) {
	// Set read timeout for handshake
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read handshake: %w", err)
	}

	if n < 8 {
		return "", "", fmt.Errorf("invalid TDS handshake packet: too short")
	}

	// Parse TDS pre-login or login packet
	// TDS packet structure:
	// Byte 0: Type (0x12 = pre-login, 0x10 = TDS7 login)
	// Byte 1: Status
	// Bytes 2-3: Length (big-endian)
	// Bytes 4-7: SPID and packet ID
	// Bytes 8+: Data

	packetType := buf[0]
	username := "unknown"
	database := "master" // Default database

	// Extract credentials from TDS login packet
	if packetType == 0x10 { // TDS7 Login packet
		username, database = h.parseTDSLogin(buf[:n])
	}

	// Send TDS login acknowledgment
	// This is a simplified response - full implementation would need proper TDS protocol handling
	ackResponse := h.buildTDSLoginAck()
	_, err = conn.Write(ackResponse)
	if err != nil {
		return "", "", fmt.Errorf("failed to send login ack: %w", err)
	}

	return username, database, nil
}

// parseTDSLogin extracts username and database from TDS login packet
func (h *MSSQLHandler) parseTDSLogin(packet []byte) (string, string) {
	// Simplified TDS login parsing
	// In production, this should use a full TDS protocol parser
	username := "unknown"
	database := "master"

	// TDS login packet has username at offset 94 (after header and fixed fields)
	// This is a simplified extraction - real implementation needs proper parsing
	if len(packet) > 100 {
		// Try to extract username (Unicode format in TDS)
		usernameStart := 94
		usernameLen := 0
		if len(packet) > usernameStart+40 {
			// Extract up to 20 characters (40 bytes in Unicode)
			for i := usernameStart; i < usernameStart+40 && i < len(packet)-1; i += 2 {
				if packet[i] == 0 && packet[i+1] == 0 {
					break
				}
				if packet[i] != 0 || packet[i+1] < 128 {
					usernameLen++
				}
			}
			if usernameLen > 0 && usernameLen < 20 {
				// Convert Unicode to ASCII (simplified)
				userBytes := make([]byte, 0, usernameLen)
				for i := 0; i < usernameLen; i++ {
					userBytes = append(userBytes, packet[usernameStart+i*2])
				}
				username = string(userBytes)
			}
		}

		// Try to extract database name (appears after username)
		dbStart := usernameStart + usernameLen*2 + 4
		if len(packet) > dbStart+40 {
			dbLen := 0
			for i := dbStart; i < dbStart+40 && i < len(packet)-1; i += 2 {
				if packet[i] == 0 && packet[i+1] == 0 {
					break
				}
				if packet[i] != 0 || packet[i+1] < 128 {
					dbLen++
				}
			}
			if dbLen > 0 && dbLen < 20 {
				dbBytes := make([]byte, 0, dbLen)
				for i := 0; i < dbLen; i++ {
					dbBytes = append(dbBytes, packet[dbStart+i*2])
				}
				database = string(dbBytes)
			}
		}
	}

	return username, database
}

// buildTDSLoginAck builds a TDS login acknowledgment packet
func (h *MSSQLHandler) buildTDSLoginAck() []byte {
	// Simplified TDS login ack
	// Type: 0x04 (Response), Status: 0x01 (EOM), Length: variable
	return []byte{
		0x04, 0x01, 0x00, 0x25, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// sendError sends a TDS error packet to the client
func (h *MSSQLHandler) sendError(conn net.Conn, message string) {
	// Build TDS error packet
	// Type: 0x04 (Response), Token: 0xAA (Error)
	errorMsg := fmt.Sprintf("MarchProxy DBLB: %s", message)

	// Simplified TDS error packet
	errorPacket := []byte{0x04, 0x01} // Type: Response, Status: EOM

	// Length placeholder (will be updated)
	length := len(errorMsg) + 20
	errorPacket = append(errorPacket, byte(length>>8), byte(length&0xFF))

	// SPID and packet ID
	errorPacket = append(errorPacket, 0x00, 0x00, 0x01, 0x00)

	// Error token
	errorPacket = append(errorPacket, 0xAA) // Token type: Error

	// Error details (simplified)
	errorPacket = append(errorPacket, []byte(errorMsg)...)

	conn.Write(errorPacket)
}

// proxyTrafficWithInspection proxies traffic with security inspection
func (h *MSSQLHandler) proxyTrafficWithInspection(ctx context.Context, clientConn, backendConn net.Conn, username, database string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to backend (with inspection)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024) // 32KB buffer for TDS packets

		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := clientConn.Read(buf)
				if err != nil {
					if err != io.EOF {
						h.logger.WithError(err).Debug("Client read error")
					}
					return
				}

				// Apply query rate limiting
				if h.config.EnableRateLimiting && !h.queryLimiter.Allow() {
					h.logger.Warn("MSSQL query rate limit exceeded")
					h.sendError(clientConn, "Query rate limit exceeded")
					atomic.AddInt64(&h.blockedQueries, 1)
					return
				}

				// Inspect SQL queries if security is enabled
				if h.config.EnableSQLInjectionDetection && h.config.BlockSuspiciousQueries {
					query := h.extractSQLFromTDS(buf[:n])
					if query != "" {
						if blocked, reason := h.securityChecker.CheckQuery(query); blocked {
							h.logger.WithFields(logrus.Fields{
								"username": username,
								"database": database,
								"reason":   reason,
								"query":    truncateString(query, 100),
							}).Warn("Blocked suspicious MSSQL query")

							metrics.IncSQLInjection(h.protocol)
							atomic.AddInt64(&h.blockedQueries, 1)
							h.sendError(clientConn, "Query blocked by security policy")
							return
						}

						// Track query type
						isWrite := h.isWriteQuery(query)
						atomic.AddInt64(&h.totalQueries, 1)
						metrics.IncQuery(h.protocol, isWrite)
					}
				}

				// Forward to backend
				_, err = backendConn.Write(buf[:n])
				if err != nil {
					h.logger.WithError(err).Debug("Backend write error")
					return
				}

				metrics.RecordBytesTransferred(h.protocol, "upstream", int64(n))
			}
		}
	}()

	// Backend to client (passthrough)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := backendConn.Read(buf)
				if err != nil {
					if err != io.EOF {
						h.logger.WithError(err).Debug("Backend read error")
					}
					return
				}

				_, err = clientConn.Write(buf[:n])
				if err != nil {
					h.logger.WithError(err).Debug("Client write error")
					return
				}

				metrics.RecordBytesTransferred(h.protocol, "downstream", int64(n))
			}
		}
	}()

	wg.Wait()
}

// extractSQLFromTDS extracts SQL query from TDS packet
func (h *MSSQLHandler) extractSQLFromTDS(packet []byte) string {
	// Simplified TDS SQL extraction
	// TDS packet types:
	// 0x01 = SQL Batch
	// 0x03 = RPC request
	// 0x0E = Transaction manager request

	if len(packet) < 8 {
		return ""
	}

	packetType := packet[0]

	// SQL Batch packet
	if packetType == 0x01 {
		// SQL is in Unicode after the 8-byte header
		if len(packet) > 8 {
			return h.extractUnicodeSQL(packet[8:])
		}
	}

	return ""
}

// extractUnicodeSQL extracts SQL from Unicode-encoded TDS data
func (h *MSSQLHandler) extractUnicodeSQL(data []byte) string {
	// Convert Unicode (UTF-16LE) to ASCII
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}

	result := make([]byte, 0, len(data)/2)
	for i := 0; i < len(data)-1; i += 2 {
		// Simple Unicode to ASCII conversion (only handles ASCII range)
		if data[i+1] == 0 {
			result = append(result, data[i])
		}
	}

	return strings.TrimSpace(string(result))
}

// isWriteQuery determines if a query is a write operation
func (h *MSSQLHandler) isWriteQuery(query string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(query))

	writeKeywords := []string{
		"INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
		"ALTER", "TRUNCATE", "MERGE", "EXEC", "EXECUTE",
	}

	for _, keyword := range writeKeywords {
		if strings.HasPrefix(normalized, keyword) {
			return true
		}
	}

	return false
}

// isRunning returns whether the handler is running
func (h *MSSQLHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
