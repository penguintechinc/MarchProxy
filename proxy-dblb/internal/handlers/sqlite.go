package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// SQLiteConfig contains SQLite-specific configuration
type SQLiteConfig struct {
	Path           string `json:"path" yaml:"path"`                       // Database file path or :memory:
	Name           string `json:"name" yaml:"name"`                       // Logical database name
	ReadOnly       bool   `json:"read_only" yaml:"read_only"`             // Open in read-only mode
	WALMode        bool   `json:"wal_mode" yaml:"wal_mode"`               // Enable Write-Ahead Logging
	BusyTimeout    int    `json:"busy_timeout" yaml:"busy_timeout"`       // Busy timeout in milliseconds
	CacheSize      int    `json:"cache_size" yaml:"cache_size"`           // Page cache size in KB
	JournalMode    string `json:"journal_mode" yaml:"journal_mode"`       // Journal mode (DELETE, TRUNCATE, PERSIST, MEMORY, WAL, OFF)
	Synchronous    string `json:"synchronous" yaml:"synchronous"`         // Synchronous mode (OFF, NORMAL, FULL, EXTRA)
	ForeignKeys    bool   `json:"foreign_keys" yaml:"foreign_keys"`       // Enable foreign key constraints
	MaxConnections int    `json:"max_connections" yaml:"max_connections"` // Maximum concurrent connections
}

// SQLiteDatabase represents a single SQLite database instance
type SQLiteDatabase struct {
	config     SQLiteConfig
	db         *sql.DB
	mu         sync.RWMutex
	lastAccess time.Time
	queryCount uint64
	errorCount uint64
}

// SQLiteHandler handles SQLite database connections
type SQLiteHandler struct {
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
	databases       map[string]*SQLiteDatabase
	dbMu            sync.RWMutex
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewSQLiteHandler creates a new SQLite handler
func NewSQLiteHandler(port int, pool *pool.Pool, securityChecker *security.Checker, cfg *config.Config, logger *logrus.Logger) *SQLiteHandler {
	return &SQLiteHandler{
		protocol:        "sqlite",
		port:            port,
		pool:            pool,
		securityChecker: securityChecker,
		config:          cfg,
		logger:          logger,
		connLimiter:     rate.NewLimiter(rate.Limit(cfg.DefaultConnectionRate), int(cfg.DefaultConnectionRate)),
		queryLimiter:    rate.NewLimiter(rate.Limit(cfg.DefaultQueryRate), int(cfg.DefaultQueryRate)),
		databases:       make(map[string]*SQLiteDatabase),
	}
}

// Start starts the SQLite handler
func (h *SQLiteHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("handler already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.port, err)
	}

	h.listener = listener
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.running = true

	// Initialize configured databases
	h.initDatabases()

	// Start maintenance loop
	go h.maintenanceLoop()

	// Start accepting connections
	go h.acceptConnections()

	h.logger.WithFields(logrus.Fields{
		"protocol": h.protocol,
		"port":     h.port,
	}).Info("SQLite handler started")

	return nil
}

// Stop stops the SQLite handler
func (h *SQLiteHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.WithField("protocol", h.protocol).Info("Stopping SQLite handler")

	if h.cancel != nil {
		h.cancel()
	}

	if h.listener != nil {
		h.listener.Close()
	}

	// Close all databases
	h.closeDatabases()

	h.running = false
	return nil
}

// GetStats returns handler statistics
func (h *SQLiteHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := map[string]interface{}{
		"protocol":     h.protocol,
		"port":         h.port,
		"active_conns": atomic.LoadInt64(&h.activeConns),
		"total_conns":  atomic.LoadInt64(&h.totalConns),
		"running":      h.running,
		"databases":    h.getDatabaseStats(),
	}

	return stats
}

// getDatabaseStats returns statistics for all databases
func (h *SQLiteHandler) getDatabaseStats() map[string]interface{} {
	h.dbMu.RLock()
	defer h.dbMu.RUnlock()

	stats := make(map[string]interface{})
	for name, db := range h.databases {
		db.mu.RLock()
		stats[name] = map[string]interface{}{
			"path":        db.config.Path,
			"read_only":   db.config.ReadOnly,
			"wal_mode":    db.config.WALMode,
			"query_count": db.queryCount,
			"error_count": db.errorCount,
			"last_access": db.lastAccess,
		}
		db.mu.RUnlock()
	}
	return stats
}

// initDatabases initializes all configured SQLite databases
func (h *SQLiteHandler) initDatabases() {
	h.dbMu.Lock()
	defer h.dbMu.Unlock()

	configs := h.getSQLiteConfigs()

	for _, cfg := range configs {
		if err := h.initDatabase(cfg); err != nil {
			h.logger.WithFields(logrus.Fields{
				"name":  cfg.Name,
				"path":  cfg.Path,
				"error": err,
			}).Error("Failed to initialize SQLite database")
			continue
		}

		h.logger.WithFields(logrus.Fields{
			"name":      cfg.Name,
			"path":      cfg.Path,
			"read_only": cfg.ReadOnly,
			"wal_mode":  cfg.WALMode,
		}).Info("Initialized SQLite database")
	}
}

// initDatabase initializes a single SQLite database
func (h *SQLiteHandler) initDatabase(cfg SQLiteConfig) error {
	dsn := h.buildDSN(cfg)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	if cfg.MaxConnections > 0 {
		db.SetMaxOpenConns(cfg.MaxConnections)
		db.SetMaxIdleConns(cfg.MaxConnections / 2)
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
	}
	db.SetConnMaxLifetime(time.Hour)

	// Apply PRAGMA settings
	if err := h.applyPragmas(db, cfg); err != nil {
		db.Close()
		return fmt.Errorf("failed to apply pragmas: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	sqliteDB := &SQLiteDatabase{
		config:     cfg,
		db:         db,
		lastAccess: time.Now(),
	}

	h.databases[cfg.Name] = sqliteDB
	return nil
}

// buildDSN builds the SQLite connection string
func (h *SQLiteHandler) buildDSN(cfg SQLiteConfig) string {
	params := []string{}

	path := cfg.Path
	if path == ":memory:" {
		params = append(params, "mode=memory")
	} else {
		if !filepath.IsAbs(path) {
			absPath, _ := filepath.Abs(path)
			path = absPath
		}

		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			h.logger.WithFields(logrus.Fields{
				"dir":   dir,
				"error": err,
			}).Warn("Failed to create database directory")
		}

		if cfg.ReadOnly {
			params = append(params, "mode=ro")
		} else {
			params = append(params, "mode=rwc")
		}
	}

	if path != ":memory:" {
		params = append(params, "cache=shared")
	}

	if cfg.BusyTimeout > 0 {
		params = append(params, fmt.Sprintf("_busy_timeout=%d", cfg.BusyTimeout))
	} else {
		params = append(params, "_busy_timeout=5000")
	}

	if len(params) > 0 {
		return fmt.Sprintf("file:%s?%s", path, strings.Join(params, "&"))
	}
	return path
}

// applyPragmas applies PRAGMA settings to the database
func (h *SQLiteHandler) applyPragmas(db *sql.DB, cfg SQLiteConfig) error {
	pragmas := []string{}

	if cfg.JournalMode != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA journal_mode = %s", cfg.JournalMode))
	} else if cfg.WALMode {
		pragmas = append(pragmas, "PRAGMA journal_mode = WAL")
	}

	if cfg.Synchronous != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA synchronous = %s", cfg.Synchronous))
	} else {
		pragmas = append(pragmas, "PRAGMA synchronous = NORMAL")
	}

	if cfg.CacheSize > 0 {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA cache_size = -%d", cfg.CacheSize))
	} else {
		pragmas = append(pragmas, "PRAGMA cache_size = -64000")
	}

	if cfg.ForeignKeys {
		pragmas = append(pragmas, "PRAGMA foreign_keys = ON")
	}

	pragmas = append(pragmas,
		"PRAGMA temp_store = MEMORY",
		"PRAGMA mmap_size = 268435456",
		"PRAGMA page_size = 4096",
	)

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			h.logger.WithFields(logrus.Fields{
				"pragma": pragma,
				"error":  err,
			}).Warn("Failed to apply pragma")
		}
	}

	return nil
}

// acceptConnections accepts incoming connections
func (h *SQLiteHandler) acceptConnections() {
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

			if !h.connLimiter.Allow() {
				h.logger.Warn("Connection rate limit exceeded")
				conn.Close()
				continue
			}

			go h.handleConnection(conn)
		}
	}
}

// handleConnection handles a single SQLite connection
func (h *SQLiteHandler) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	atomic.AddInt64(&h.activeConns, 1)
	defer atomic.AddInt64(&h.activeConns, -1)
	atomic.AddInt64(&h.totalConns, 1)

	// Perform handshake to get username and database
	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.WithError(err).Error("Handshake failed")
		return
	}

	// Get database
	sqliteDB, err := h.getDatabase(database)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"database": database,
			"error":    err,
		}).Error("Database not found")
		h.sendError(clientConn, "Database not found")
		return
	}

	// Handle queries
	h.proxyTraffic(clientConn, sqliteDB, username, database)
}

// getDatabase retrieves a SQLite database by name
func (h *SQLiteHandler) getDatabase(name string) (*SQLiteDatabase, error) {
	h.dbMu.RLock()
	defer h.dbMu.RUnlock()

	db, ok := h.databases[name]
	if !ok {
		return nil, fmt.Errorf("database %s not found", name)
	}

	db.mu.Lock()
	db.lastAccess = time.Now()
	db.mu.Unlock()

	return db, nil
}

// proxyTraffic handles query traffic for SQLite
func (h *SQLiteHandler) proxyTraffic(client net.Conn, sqliteDB *SQLiteDatabase, username, database string) {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
			n, err := client.Read(buf)
			if err != nil {
				return
			}

			query := string(buf[:n])

			// Check if database is read-only
			if sqliteDB.config.ReadOnly && h.isWriteQuery(query) {
				h.logger.WithFields(logrus.Fields{
					"database": database,
					"query":    truncateQuery(query, 100),
				}).Warn("Write query on read-only database")
				h.sendError(client, "Database is read-only")
				continue
			}

			// Security check
			if isMalicious, reason := h.securityChecker.CheckQuery(query); isMalicious {
				h.logger.WithFields(logrus.Fields{
					"user":     username,
					"database": database,
					"reason":   reason,
				}).Warn("Security threat detected")
				h.sendError(client, "Query blocked: "+reason)
				continue
			}

			// Rate limit queries
			if !h.queryLimiter.Allow() {
				h.sendError(client, "Query rate limit exceeded")
				continue
			}

			// Execute query
			result, err := h.executeQuery(sqliteDB, query)
			if err != nil {
				h.logger.WithFields(logrus.Fields{
					"database": database,
					"error":    err,
				}).Error("Query execution failed")
				sqliteDB.mu.Lock()
				sqliteDB.errorCount++
				sqliteDB.mu.Unlock()
				h.sendError(client, err.Error())
				continue
			}

			sqliteDB.mu.Lock()
			sqliteDB.queryCount++
			sqliteDB.mu.Unlock()

			client.Write([]byte(result))
		}
	}
}

// executeQuery executes a query on the SQLite database
func (h *SQLiteHandler) executeQuery(sqliteDB *SQLiteDatabase, query string) (string, error) {
	query = strings.TrimSpace(query)
	upperQuery := strings.ToUpper(query)

	// Handle different query types
	if strings.HasPrefix(upperQuery, "SELECT") ||
		strings.HasPrefix(upperQuery, "PRAGMA") ||
		strings.HasPrefix(upperQuery, "EXPLAIN") {
		rows, err := sqliteDB.db.Query(query)
		if err != nil {
			return "", err
		}
		defer rows.Close()

		// Get column names
		columns, err := rows.Columns()
		if err != nil {
			return "", err
		}

		// Build result
		var result strings.Builder
		result.WriteString(strings.Join(columns, "\t"))
		result.WriteString("\n")

		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		rowCount := 0
		for rows.Next() {
			if err := rows.Scan(valuePtrs...); err != nil {
				continue
			}
			rowCount++

			for i, val := range values {
				if i > 0 {
					result.WriteString("\t")
				}
				if val == nil {
					result.WriteString("NULL")
				} else {
					result.WriteString(fmt.Sprintf("%v", val))
				}
			}
			result.WriteString("\n")
		}

		result.WriteString(fmt.Sprintf("\n(%d rows)\n", rowCount))
		return result.String(), nil
	}

	// Execute non-query statements
	res, err := sqliteDB.db.Exec(query)
	if err != nil {
		return "", err
	}

	rowsAffected, _ := res.RowsAffected()
	return fmt.Sprintf("OK (%d rows affected)\n", rowsAffected), nil
}

// performHandshake performs a simplified handshake
func (h *SQLiteHandler) performHandshake(conn net.Conn) (string, string, error) {
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", "", err
	}

	// Parse format: username:database
	parts := strings.Split(string(buf[:n]), ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid handshake format")
	}

	conn.Write([]byte("OK\n"))

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

// sendError sends an error message to the client
func (h *SQLiteHandler) sendError(conn net.Conn, message string) {
	conn.Write([]byte(fmt.Sprintf("ERROR: %s\n", message)))
}

// isWriteQuery checks if a query is a write operation
func (h *SQLiteHandler) isWriteQuery(query string) bool {
	upper := strings.ToUpper(strings.TrimSpace(query))
	writeKeywords := []string{"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "REPLACE"}
	for _, kw := range writeKeywords {
		if strings.HasPrefix(upper, kw) {
			return true
		}
	}
	return false
}

// getSQLiteConfigs gets SQLite configurations from environment or defaults
func (h *SQLiteHandler) getSQLiteConfigs() []SQLiteConfig {
	configs := []SQLiteConfig{}

	// Check for environment-based configuration
	if sqlitePath := os.Getenv("SQLITE_PATH"); sqlitePath != "" {
		configs = append(configs, SQLiteConfig{
			Name:           os.Getenv("SQLITE_NAME"),
			Path:           sqlitePath,
			ReadOnly:       os.Getenv("SQLITE_READONLY") == "true",
			WALMode:        os.Getenv("SQLITE_WAL") != "false",
			BusyTimeout:    5000,
			CacheSize:      64000,
			JournalMode:    "WAL",
			Synchronous:    "NORMAL",
			ForeignKeys:    true,
			MaxConnections: 10,
		})
		if configs[0].Name == "" {
			configs[0].Name = "default"
		}
	}

	// Default configuration if none specified
	if len(configs) == 0 {
		configs = append(configs, SQLiteConfig{
			Name:           "default",
			Path:           "/data/dblb/default.db",
			ReadOnly:       false,
			WALMode:        true,
			BusyTimeout:    5000,
			CacheSize:      64000,
			JournalMode:    "WAL",
			Synchronous:    "NORMAL",
			ForeignKeys:    true,
			MaxConnections: 10,
		})
	}

	return configs
}

// maintenanceLoop performs periodic maintenance tasks
func (h *SQLiteHandler) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.performMaintenance()
		}
	}
}

// performMaintenance performs database maintenance
func (h *SQLiteHandler) performMaintenance() {
	h.dbMu.RLock()
	databases := make([]*SQLiteDatabase, 0, len(h.databases))
	for _, db := range h.databases {
		databases = append(databases, db)
	}
	h.dbMu.RUnlock()

	for _, sqliteDB := range databases {
		// Run VACUUM if needed (only on non-memory databases)
		if sqliteDB.config.Path != ":memory:" {
			sqliteDB.mu.RLock()
			errorRate := float64(sqliteDB.errorCount) / float64(sqliteDB.queryCount+1)
			sqliteDB.mu.RUnlock()

			if errorRate > 0.01 {
				h.logger.WithField("name", sqliteDB.config.Name).Info("Running VACUUM on database")
				if _, err := sqliteDB.db.Exec("VACUUM"); err != nil {
					h.logger.WithFields(logrus.Fields{
						"name":  sqliteDB.config.Name,
						"error": err,
					}).Error("VACUUM failed")
				}
			}
		}

		// Run ANALYZE periodically
		if _, err := sqliteDB.db.Exec("ANALYZE"); err != nil {
			h.logger.WithFields(logrus.Fields{
				"name":  sqliteDB.config.Name,
				"error": err,
			}).Warn("ANALYZE failed")
		}
	}
}

// closeDatabases closes all SQLite databases
func (h *SQLiteHandler) closeDatabases() {
	h.dbMu.Lock()
	defer h.dbMu.Unlock()

	for name, sqliteDB := range h.databases {
		if err := sqliteDB.db.Close(); err != nil {
			h.logger.WithFields(logrus.Fields{
				"name":  name,
				"error": err,
			}).Error("Failed to close database")
		}
	}

	h.databases = make(map[string]*SQLiteDatabase)
}

// isRunning returns whether the handler is running
func (h *SQLiteHandler) isRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// GetDatabaseStatus returns the status of all SQLite databases
func (h *SQLiteHandler) GetDatabaseStatus() map[string]interface{} {
	h.dbMu.RLock()
	defer h.dbMu.RUnlock()

	status := make(map[string]interface{})

	for name, sqliteDB := range h.databases {
		sqliteDB.mu.RLock()
		dbStatus := map[string]interface{}{
			"path":        sqliteDB.config.Path,
			"read_only":   sqliteDB.config.ReadOnly,
			"wal_mode":    sqliteDB.config.WALMode,
			"last_access": sqliteDB.lastAccess,
			"query_count": sqliteDB.queryCount,
			"error_count": sqliteDB.errorCount,
			"error_rate":  float64(sqliteDB.errorCount) / float64(sqliteDB.queryCount+1),
		}
		sqliteDB.mu.RUnlock()

		// Get database statistics
		var pageCount, pageSize, cacheSize int
		sqliteDB.db.QueryRow("PRAGMA page_count").Scan(&pageCount)
		sqliteDB.db.QueryRow("PRAGMA page_size").Scan(&pageSize)
		sqliteDB.db.QueryRow("PRAGMA cache_size").Scan(&cacheSize)

		dbStatus["page_count"] = pageCount
		dbStatus["page_size"] = pageSize
		dbStatus["cache_size"] = cacheSize
		dbStatus["size_bytes"] = pageCount * pageSize

		status[name] = dbStatus
	}

	return status
}

// truncateQuery truncates a query for logging
func truncateQuery(query string, maxLen int) string {
	if len(query) <= maxLen {
		return query
	}
	return query[:maxLen] + "..."
}
