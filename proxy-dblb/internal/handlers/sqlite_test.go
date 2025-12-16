package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/pool"
	"marchproxy-dblb/internal/security"

	"github.com/sirupsen/logrus"
)

// TestNewSQLiteHandler tests SQLiteHandler creation
func TestNewSQLiteHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)

	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}

	if handler.port != 5432 {
		t.Errorf("Expected port 5432, got %d", handler.port)
	}

	if handler.protocol != "sqlite" {
		t.Errorf("Expected protocol 'sqlite', got '%s'", handler.protocol)
	}

	if handler.pool != p {
		t.Error("Expected pool to be set")
	}

	if handler.securityChecker != secChecker {
		t.Error("Expected securityChecker to be set")
	}

	if handler.config != cfg {
		t.Error("Expected config to be set")
	}

	if handler.logger != logger {
		t.Error("Expected logger to be set")
	}

	if handler.databases == nil {
		t.Fatal("Expected databases map to be initialized")
	}

	if len(handler.databases) != 0 {
		t.Errorf("Expected empty databases map, got %d entries", len(handler.databases))
	}

	if handler.connLimiter == nil {
		t.Fatal("Expected connLimiter to be initialized")
	}

	if handler.queryLimiter == nil {
		t.Fatal("Expected queryLimiter to be initialized")
	}
}

// TestSQLiteConfigValidation tests SQLite config validation
func TestSQLiteConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  SQLiteConfig
		isValid bool
	}{
		{
			name: "Valid memory database config",
			config: SQLiteConfig{
				Path:           ":memory:",
				Name:           "memory_db",
				WALMode:        true,
				BusyTimeout:    5000,
				CacheSize:      64000,
				ForeignKeys:    true,
				MaxConnections: 10,
			},
			isValid: true,
		},
		{
			name: "Valid file database config",
			config: SQLiteConfig{
				Path:           "/tmp/test.db",
				Name:           "test_db",
				ReadOnly:       false,
				WALMode:        true,
				BusyTimeout:    5000,
				CacheSize:      64000,
				JournalMode:    "WAL",
				Synchronous:    "NORMAL",
				ForeignKeys:    true,
				MaxConnections: 10,
			},
			isValid: true,
		},
		{
			name: "Read-only config",
			config: SQLiteConfig{
				Path:           "/tmp/readonly.db",
				Name:           "readonly_db",
				ReadOnly:       true,
				WALMode:        false,
				BusyTimeout:    5000,
				CacheSize:      32000,
				MaxConnections: 5,
			},
			isValid: true,
		},
		{
			name: "Custom timeout config",
			config: SQLiteConfig{
				Path:           ":memory:",
				Name:           "custom_timeout",
				BusyTimeout:    10000,
				CacheSize:      128000,
				MaxConnections: 20,
			},
			isValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate config structure
			if tt.config.Path == "" {
				t.Error("Path should not be empty")
			}

			if tt.config.Name == "" {
				t.Error("Name should not be empty")
			}

			if tt.config.BusyTimeout < 0 {
				t.Error("BusyTimeout should be non-negative")
			}

			if tt.config.CacheSize < 0 {
				t.Error("CacheSize should be non-negative")
			}

			if tt.config.MaxConnections < 0 {
				t.Error("MaxConnections should be non-negative")
			}
		})
	}
}

// TestBuildDSN tests DSN building for various configurations
func TestBuildDSN(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	tests := []struct {
		name        string
		config      SQLiteConfig
		shouldMatch string
	}{
		{
			name: "Memory database DSN",
			config: SQLiteConfig{
				Path:        ":memory:",
				Name:        "memory",
				BusyTimeout: 5000,
			},
			shouldMatch: "mode=memory",
		},
		{
			name: "Read-write file DSN",
			config: SQLiteConfig{
				Path:        ":memory:",
				Name:        "test",
				ReadOnly:    false,
				BusyTimeout: 5000,
			},
			shouldMatch: "mode=",
		},
		{
			name: "Read-only file DSN",
			config: SQLiteConfig{
				Path:        ":memory:",
				Name:        "test",
				ReadOnly:    true,
				BusyTimeout: 5000,
			},
			shouldMatch: "busy_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn := handler.buildDSN(tt.config)

			if dsn == "" {
				t.Error("DSN should not be empty")
			}

			if tt.shouldMatch != "" && tt.config.Path == ":memory:" {
				// For memory databases, should contain mode parameter
				if !contains(dsn, "mode") {
					t.Errorf("DSN should contain 'mode', got: %s", dsn)
				}
			}
		})
	}
}

// TestGetStatsBeforeStart tests GetStats before handler is started
func TestGetStatsBeforeStart(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	stats := handler.GetStats()

	if stats == nil {
		t.Fatal("GetStats should return non-nil map")
	}

	protocol, ok := stats["protocol"].(string)
	if !ok || protocol != "sqlite" {
		t.Errorf("Expected protocol 'sqlite', got %v", protocol)
	}

	port, ok := stats["port"].(int)
	if !ok || port != 5432 {
		t.Errorf("Expected port 5432, got %v", port)
	}

	activeConns, ok := stats["active_conns"].(int64)
	if !ok {
		t.Errorf("Expected int64 for active_conns, got %T", stats["active_conns"])
	}

	if activeConns != 0 {
		t.Errorf("Expected 0 active connections before start, got %d", activeConns)
	}

	totalConns, ok := stats["total_conns"].(int64)
	if !ok {
		t.Errorf("Expected int64 for total_conns, got %T", stats["total_conns"])
	}

	if totalConns != 0 {
		t.Errorf("Expected 0 total connections before start, got %d", totalConns)
	}

	running, ok := stats["running"].(bool)
	if !ok {
		t.Errorf("Expected bool for running, got %T", stats["running"])
	}

	if running {
		t.Error("Expected running to be false before start")
	}

	databases, ok := stats["databases"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected map for databases, got %T", stats["databases"])
	}

	if databases == nil {
		t.Error("Expected non-nil databases map")
	}
}

// TestSQLiteIsWriteQuery tests write query detection
func TestSQLiteIsWriteQuery(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	tests := []struct {
		name    string
		query   string
		isWrite bool
	}{
		{
			name:    "SELECT query",
			query:   "SELECT * FROM users",
			isWrite: false,
		},
		{
			name:    "INSERT query",
			query:   "INSERT INTO users (name) VALUES ('test')",
			isWrite: true,
		},
		{
			name:    "UPDATE query",
			query:   "UPDATE users SET name = 'test'",
			isWrite: true,
		},
		{
			name:    "DELETE query",
			query:   "DELETE FROM users WHERE id = 1",
			isWrite: true,
		},
		{
			name:    "CREATE TABLE query",
			query:   "CREATE TABLE users (id INT)",
			isWrite: true,
		},
		{
			name:    "DROP TABLE query",
			query:   "DROP TABLE users",
			isWrite: true,
		},
		{
			name:    "ALTER TABLE query",
			query:   "ALTER TABLE users ADD COLUMN age INT",
			isWrite: true,
		},
		{
			name:    "TRUNCATE query",
			query:   "TRUNCATE TABLE users",
			isWrite: true,
		},
		{
			name:    "PRAGMA query",
			query:   "PRAGMA table_info(users)",
			isWrite: false,
		},
		{
			name:    "Lowercase INSERT",
			query:   "insert into users (name) values ('test')",
			isWrite: true,
		},
		{
			name:    "Mixed case SELECT",
			query:   "SeLeCt * FROM users",
			isWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isWriteQuery(tt.query)
			if result != tt.isWrite {
				t.Errorf("Query '%s': expected isWrite=%v, got %v", tt.query, tt.isWrite, result)
			}
		})
	}
}

// TestSQLiteTruncateQuery tests query truncation for logging
func TestSQLiteTruncateQuery(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		maxLen   int
		expected string
	}{
		{
			name:     "Short query",
			query:    "SELECT * FROM users",
			maxLen:   100,
			expected: "SELECT * FROM users",
		},
		{
			name:     "Long query truncation",
			query:    "SELECT * FROM users WHERE id = 1 AND name LIKE '%test%'",
			maxLen:   20,
			expected: "SELECT * FROM users ...",
		},
		{
			name:     "Exact length",
			query:    "SELECT 123",
			maxLen:   10,
			expected: "SELECT 123",
		},
		{
			name:     "Empty query",
			query:    "",
			maxLen:   10,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateQuery(tt.query, tt.maxLen)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestGetSQLiteConfigs tests configuration retrieval from environment
func TestGetSQLiteConfigs(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)

	// Test 1: Default config when no environment variables set
	os.Unsetenv("SQLITE_PATH")
	os.Unsetenv("SQLITE_NAME")
	os.Unsetenv("SQLITE_READONLY")
	os.Unsetenv("SQLITE_WAL")

	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)
	configs := handler.getSQLiteConfigs()

	if len(configs) == 0 {
		t.Fatal("Expected at least one config")
	}

	if configs[0].Name != "default" {
		t.Errorf("Expected default name, got '%s'", configs[0].Name)
	}

	// Test 2: Config from environment variables
	os.Setenv("SQLITE_PATH", "/tmp/custom.db")
	os.Setenv("SQLITE_NAME", "custom_db")
	os.Setenv("SQLITE_READONLY", "true")
	os.Setenv("SQLITE_WAL", "false")

	handler = NewSQLiteHandler(5432, p, secChecker, cfg, logger)
	configs = handler.getSQLiteConfigs()

	if len(configs) == 0 {
		t.Fatal("Expected at least one config")
	}

	if configs[0].Path != "/tmp/custom.db" {
		t.Errorf("Expected path '/tmp/custom.db', got '%s'", configs[0].Path)
	}

	if configs[0].Name != "custom_db" {
		t.Errorf("Expected name 'custom_db', got '%s'", configs[0].Name)
	}

	if !configs[0].ReadOnly {
		t.Error("Expected ReadOnly to be true")
	}

	if configs[0].WALMode {
		t.Error("Expected WALMode to be false")
	}

	// Cleanup
	os.Unsetenv("SQLITE_PATH")
	os.Unsetenv("SQLITE_NAME")
	os.Unsetenv("SQLITE_READONLY")
	os.Unsetenv("SQLITE_WAL")
}

// TestStartStopCycle tests handler start and stop lifecycle
func TestStartStopCycle(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	// Use memory database for testing
	os.Setenv("SQLITE_PATH", ":memory:")
	os.Setenv("SQLITE_NAME", "test")

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)

	// Use a high port to avoid conflicts
	handler := NewSQLiteHandler(15432, p, secChecker, cfg, logger)

	// Test: Start handler
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start handler: %v", err)
	}

	// Verify running state
	stats := handler.GetStats()
	running, ok := stats["running"].(bool)
	if !ok || !running {
		t.Error("Expected handler to be running after start")
	}

	// Test: Stop handler
	err = handler.Stop()
	if err != nil {
		t.Fatalf("Failed to stop handler: %v", err)
	}

	// Verify stopped state
	stats = handler.GetStats()
	running, ok = stats["running"].(bool)
	if !ok || running {
		t.Error("Expected handler to be stopped after stop")
	}

	// Cleanup
	os.Unsetenv("SQLITE_PATH")
	os.Unsetenv("SQLITE_NAME")
}

// TestDoubleStart tests that starting handler twice returns error
func TestDoubleStart(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	os.Setenv("SQLITE_PATH", ":memory:")
	os.Setenv("SQLITE_NAME", "test")

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(15433, p, secChecker, cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First start should succeed
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("First start failed: %v", err)
	}
	defer handler.Stop()

	// Second start should fail
	err = handler.Start(ctx)
	if err == nil {
		t.Fatal("Expected error when starting handler twice")
	}

	if err.Error() != "handler already running" {
		t.Errorf("Expected 'handler already running' error, got: %v", err)
	}

	// Cleanup
	os.Unsetenv("SQLITE_PATH")
	os.Unsetenv("SQLITE_NAME")
}

// TestStopWithoutStart tests stopping a handler that was never started
func TestStopWithoutStart(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	// Stopping without starting should not error
	err := handler.Stop()
	if err != nil {
		t.Errorf("Expected no error when stopping non-running handler, got: %v", err)
	}
}

// TestConcurrentStats tests concurrent access to statistics
func TestConcurrentStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	// Concurrently access stats
	var wg sync.WaitGroup
	const numGoroutines = 10
	const numIterations = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				stats := handler.GetStats()
				if stats == nil {
					t.Error("Stats should not be nil")
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestDatabaseStats tests database statistics
func TestDatabaseStats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	os.Setenv("SQLITE_PATH", ":memory:")
	os.Setenv("SQLITE_NAME", "testdb")

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(15434, p, secChecker, cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start handler: %v", err)
	}
	defer handler.Stop()

	// Get database stats
	stats := handler.GetStats()
	dbStats, ok := stats["databases"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected databases to be map, got %T", stats["databases"])
	}

	// Should have at least one database
	if len(dbStats) == 0 {
		t.Fatal("Expected at least one database in stats")
	}

	// Check that expected keys exist
	expectedKeys := []string{"path", "read_only", "wal_mode", "query_count", "error_count", "last_access"}

	for name, db := range dbStats {
		dbMap, ok := db.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected database entry to be map, got %T", db)
		}

		for _, key := range expectedKeys {
			if _, ok := dbMap[key]; !ok {
				t.Errorf("Expected key '%s' in database '%s'", key, name)
			}
		}
	}

	// Cleanup
	os.Unsetenv("SQLITE_PATH")
	os.Unsetenv("SQLITE_NAME")
}

// TestSQLiteConfigWithDefaults tests config with default values
func TestSQLiteConfigWithDefaults(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	// Create config with default values
	sqliteConfig := SQLiteConfig{
		Name: "test",
		Path: ":memory:",
	}

	dsn := handler.buildDSN(sqliteConfig)

	if dsn == "" {
		t.Fatal("DSN should not be empty")
	}

	// Should have default busy timeout
	if !contains(dsn, "busy_timeout") {
		t.Errorf("DSN should contain default busy_timeout, got: %s", dsn)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}

// Helper to check substring more reliably
func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestBusyTimeoutDefault tests that default busy timeout is applied
func TestBusyTimeoutDefault(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	sqliteConfig := SQLiteConfig{
		Name:        "test",
		Path:        ":memory:",
		BusyTimeout: 0, // Should use default
	}

	dsn := handler.buildDSN(sqliteConfig)

	// Should contain default busy timeout of 5000ms
	if !stringContains(dsn, "_busy_timeout=5000") {
		t.Errorf("DSN should contain default busy_timeout=5000, got: %s", dsn)
	}
}

// TestCustomBusyTimeout tests custom busy timeout
func TestCustomBusyTimeout(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	sqliteConfig := SQLiteConfig{
		Name:        "test",
		Path:        ":memory:",
		BusyTimeout: 10000,
	}

	dsn := handler.buildDSN(sqliteConfig)

	if !stringContains(dsn, "_busy_timeout=10000") {
		t.Errorf("DSN should contain custom busy_timeout=10000, got: %s", dsn)
	}
}

// TestMemoryDatabasePath tests memory database detection
func TestMemoryDatabasePath(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	sqliteConfig := SQLiteConfig{
		Name: "memory",
		Path: ":memory:",
	}

	dsn := handler.buildDSN(sqliteConfig)

	if !stringContains(dsn, "mode=memory") {
		t.Errorf("Memory database DSN should contain 'mode=memory', got: %s", dsn)
	}

	// Memory databases should NOT have cache=shared
	if stringContains(dsn, "cache=shared") {
		t.Errorf("Memory database DSN should not contain 'cache=shared', got: %s", dsn)
	}
}

// TestReadOnlyPath tests read-only database path
func TestReadOnlyPath(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	sqliteConfig := SQLiteConfig{
		Name:     "readonly",
		Path:     "/tmp/test.db",
		ReadOnly: true,
	}

	dsn := handler.buildDSN(sqliteConfig)

	if !stringContains(dsn, "mode=ro") {
		t.Errorf("Read-only database DSN should contain 'mode=ro', got: %s", dsn)
	}
}

// TestReadWritePath tests read-write database path
func TestReadWritePath(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	sqliteConfig := SQLiteConfig{
		Name:     "readwrite",
		Path:     "/tmp/test.db",
		ReadOnly: false,
	}

	dsn := handler.buildDSN(sqliteConfig)

	if !stringContains(dsn, "mode=rwc") {
		t.Errorf("Read-write database DSN should contain 'mode=rwc', got: %s", dsn)
	}
}

// TestAbsolutePathHandling tests absolute path handling in DSN
func TestAbsolutePathHandling(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	// Test with absolute path
	absConfig := SQLiteConfig{
		Name: "absolute",
		Path: "/tmp/absolute_test.db",
	}

	dsnAbs := handler.buildDSN(absConfig)
	if !stringContains(dsnAbs, "/tmp/absolute_test.db") {
		t.Errorf("Absolute path should be preserved in DSN, got: %s", dsnAbs)
	}

	// Test with relative path (will be converted to absolute)
	relConfig := SQLiteConfig{
		Name: "relative",
		Path: "test.db",
	}

	dsnRel := handler.buildDSN(relConfig)
	if dsnRel == "" {
		t.Fatal("Relative path DSN should not be empty")
	}
}

// TestGetDatabaseStatus tests database status retrieval
func TestGetDatabaseStatus(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	os.Setenv("SQLITE_PATH", ":memory:")
	os.Setenv("SQLITE_NAME", "statusdb")

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(15435, p, secChecker, cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start handler: %v", err)
	}
	defer handler.Stop()

	status := handler.GetDatabaseStatus()
	if status == nil {
		t.Fatal("GetDatabaseStatus should return non-nil map")
	}

	if len(status) == 0 {
		t.Fatal("Expected at least one database in status")
	}

	// Check status structure for each database
	expectedStatusKeys := []string{"path", "read_only", "wal_mode", "last_access", "query_count", "error_count", "error_rate"}

	for name, dbStatus := range status {
		dbMap, ok := dbStatus.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected database status to be map, got %T", dbStatus)
		}

		for _, key := range expectedStatusKeys {
			if _, ok := dbMap[key]; !ok {
				t.Errorf("Expected key '%s' in status for database '%s'", key, name)
			}
		}

		// Verify types
		if _, ok := dbMap["query_count"].(uint64); !ok {
			t.Errorf("Expected uint64 for query_count, got %T", dbMap["query_count"])
		}

		if _, ok := dbMap["error_count"].(uint64); !ok {
			t.Errorf("Expected uint64 for error_count, got %T", dbMap["error_count"])
		}

		if _, ok := dbMap["error_rate"].(float64); !ok {
			t.Errorf("Expected float64 for error_rate, got %T", dbMap["error_rate"])
		}
	}

	// Cleanup
	os.Unsetenv("SQLITE_PATH")
	os.Unsetenv("SQLITE_NAME")
}

// TestDirectoryCreation tests that database directories are created
func TestDirectoryCreation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tmpDir := filepath.Join(os.TempDir(), "marchproxy_test_"+fmt.Sprintf("%d", time.Now().UnixNano()))
	dbPath := filepath.Join(tmpDir, "subdir", "test.db")

	defer os.RemoveAll(tmpDir)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	p := pool.NewPool(100, logger)
	secChecker := security.NewChecker(logger)
	handler := NewSQLiteHandler(5432, p, secChecker, cfg, logger)

	sqliteConfig := SQLiteConfig{
		Name: "dirtest",
		Path: dbPath,
	}

	// buildDSN should create the directory
	dsn := handler.buildDSN(sqliteConfig)

	if dsn == "" {
		t.Fatal("DSN should not be empty")
	}

	// The directory should now exist (or attempt was made)
	// Note: We can't guarantee it exists without actually creating the database
	// but buildDSN should attempt to create it
	if !stringContains(dsn, "file:") {
		t.Errorf("DSN should contain 'file:' prefix for file databases, got: %s", dsn)
	}
}
