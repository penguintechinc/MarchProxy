package handlers

import (
	"testing"
	"time"

	"marchproxy-dblb/internal/config"
	"marchproxy-dblb/internal/security"

	"github.com/sirupsen/logrus"
)

// TestGaleraHandlerImplementsInterface verifies GaleraHandler implements Handler interface
func TestGaleraHandlerImplementsInterface(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	secChecker := security.NewChecker(logger)

	galeraConfig := &GaleraConfig{
		HealthCheckInterval:  10 * time.Second,
		MaxConsecutiveErrors: 3,
		FlowControlThreshold: 100,
		ReadOnlyNodes:        false,
		WriteBalancing:       true,
		NodeWeightEnabled:    true,
		ConnectionTimeout:    5 * time.Second,
		QueryTimeout:         30 * time.Second,
		Backends: []*GaleraBackend{
			{
				Host:     "localhost",
				Port:     3306,
				User:     "test",
				Password: "test",
				Database: "test",
				TLS:      false,
				Weight:   1.0,
			},
		},
	}

	handler := NewGaleraHandler("galera", 3306, galeraConfig, secChecker, cfg, logger)

	// Verify handler implements Handler interface
	var _ Handler = handler

	// Test GetStats before starting
	stats := handler.GetStats()
	if stats == nil {
		t.Fatal("GetStats should return non-nil stats")
	}

	protocol, ok := stats["protocol"].(string)
	if !ok || protocol != "galera" {
		t.Errorf("Expected protocol 'galera', got %v", protocol)
	}
}

// TestGaleraNodeStates tests node state enum
func TestGaleraNodeStates(t *testing.T) {
	tests := []struct {
		state    GaleraNodeState
		expected string
	}{
		{GaleraStateUndefined, "Undefined"},
		{GaleraStateJoining, "Joining"},
		{GaleraStateDonor, "Donor/Desynced"},
		{GaleraStateJoined, "Joined"},
		{GaleraStateSynced, "Synced"},
		{GaleraStateError, "Error"},
		{GaleraStateDisconnected, "Disconnected"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("State %d: expected %s, got %s", tt.state, tt.expected, got)
		}
	}
}

// TestGaleraNodeHealth tests node health checking logic
func TestGaleraNodeHealth(t *testing.T) {
	tests := []struct {
		name      string
		node      *GaleraNodeInfo
		healthy   bool
		canRead   bool
		canWrite  bool
	}{
		{
			name: "Healthy synced node",
			node: &GaleraNodeInfo{
				State:             GaleraStateSynced,
				Ready:             true,
				FlowControlPaused: false,
				ConsecutiveErrors: 0,
				LastHealthCheck:   time.Now(),
			},
			healthy:  true,
			canRead:  true,
			canWrite: true,
		},
		{
			name: "Synced but flow control paused",
			node: &GaleraNodeInfo{
				State:             GaleraStateSynced,
				Ready:             true,
				FlowControlPaused: true,
				ConsecutiveErrors: 0,
				LastHealthCheck:   time.Now(),
			},
			healthy:  false,
			canRead:  false,
			canWrite: false,
		},
		{
			name: "Joined but not synced",
			node: &GaleraNodeInfo{
				State:             GaleraStateJoined,
				Ready:             true,
				FlowControlPaused: false,
				ConsecutiveErrors: 0,
				LastHealthCheck:   time.Now(),
			},
			healthy:  false,
			canRead:  true,
			canWrite: false,
		},
		{
			name: "Too many consecutive errors",
			node: &GaleraNodeInfo{
				State:             GaleraStateSynced,
				Ready:             true,
				FlowControlPaused: false,
				ConsecutiveErrors: 5,
				LastHealthCheck:   time.Now(),
			},
			healthy:  false,
			canRead:  false,
			canWrite: false,
		},
		{
			name: "Stale health check",
			node: &GaleraNodeInfo{
				State:             GaleraStateSynced,
				Ready:             true,
				FlowControlPaused: false,
				ConsecutiveErrors: 0,
				LastHealthCheck:   time.Now().Add(-1 * time.Minute),
			},
			healthy:  false,
			canRead:  false,
			canWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.node.IsHealthy(); got != tt.healthy {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.healthy)
			}
			if got := tt.node.CanServeReads(); got != tt.canRead {
				t.Errorf("CanServeReads() = %v, want %v", got, tt.canRead)
			}
			if got := tt.node.CanServeWrites(); got != tt.canWrite {
				t.Errorf("CanServeWrites() = %v, want %v", got, tt.canWrite)
			}
		})
	}
}

// TestIsWriteQuery tests write query detection
func TestIsWriteQuery(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	secChecker := security.NewChecker(logger)

	handler := NewGaleraHandler("galera", 3306, nil, secChecker, cfg, logger)

	tests := []struct {
		query    string
		isWrite  bool
	}{
		{"SELECT * FROM users", false},
		{"select id from orders", false},
		{"INSERT INTO users VALUES (1, 'test')", true},
		{"UPDATE users SET name='test'", true},
		{"DELETE FROM users WHERE id=1", true},
		{"CREATE TABLE test (id INT)", true},
		{"ALTER TABLE test ADD COLUMN name VARCHAR(255)", true},
		{"DROP TABLE test", true},
		{"TRUNCATE TABLE test", true},
		{"REPLACE INTO users VALUES (1, 'test')", true},
		{"SHOW TABLES", false},
		{"DESCRIBE users", false},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			if got := handler.isWriteQuery(tt.query); got != tt.isWrite {
				t.Errorf("isWriteQuery(%q) = %v, want %v", tt.query, got, tt.isWrite)
			}
		})
	}
}

// TestGaleraBackendSelection tests backend selection logic
func TestGaleraBackendSelection(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	secChecker := security.NewChecker(logger)

	galeraConfig := &GaleraConfig{
		HealthCheckInterval:  10 * time.Second,
		MaxConsecutiveErrors: 3,
		WriteBalancing:       true,
		NodeWeightEnabled:    false, // Test round-robin
		Backends: []*GaleraBackend{
			{Host: "node1", Port: 3306, Weight: 1.0},
			{Host: "node2", Port: 3306, Weight: 1.0},
			{Host: "node3", Port: 3306, Weight: 2.0},
		},
	}

	handler := NewGaleraHandler("galera", 3306, galeraConfig, secChecker, cfg, logger)

	// Set up node info
	handler.nodeInfo = map[string]*GaleraNodeInfo{
		"node1:3306": {
			Backend:         galeraConfig.Backends[0],
			State:           GaleraStateSynced,
			Ready:           true,
			Weight:          1.0,
			LastHealthCheck: time.Now(),
		},
		"node2:3306": {
			Backend:           galeraConfig.Backends[1],
			State:             GaleraStateSynced,
			Ready:             true,
			FlowControlPaused: true, // This node should be avoided
			Weight:            1.0,
			LastHealthCheck:   time.Now(),
		},
		"node3:3306": {
			Backend:         galeraConfig.Backends[2],
			State:           GaleraStateSynced,
			Ready:           true,
			Weight:          2.0,
			LastHealthCheck: time.Now(),
		},
	}

	// Test write query backend selection
	backend := handler.selectGaleraBackend(true)
	if backend == nil {
		t.Fatal("Expected backend, got nil")
	}

	// Should not select node2 because of flow control
	if backend.Host == "node2" {
		t.Error("Should not select node with flow control paused for writes")
	}

	// Test read query backend selection
	backend = handler.selectGaleraBackend(false)
	if backend == nil {
		t.Fatal("Expected backend for read, got nil")
	}
}

// TestGaleraHandlerLifecycle tests Start and Stop methods
func TestGaleraHandlerLifecycle(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &config.Config{
		MaxConnectionsPerRoute: 100,
		DefaultConnectionRate:  100.0,
		DefaultQueryRate:       1000.0,
	}

	secChecker := security.NewChecker(logger)

	// Use a high port to avoid conflicts
	galeraConfig := &GaleraConfig{
		HealthCheckInterval:  10 * time.Second,
		MaxConsecutiveErrors: 3,
		Backends:             []*GaleraBackend{}, // No backends for this test
	}

	handler := NewGaleraHandler("galera", 33060, galeraConfig, secChecker, cfg, logger)

	// Test Stop before Start
	if err := handler.Stop(); err != nil {
		t.Errorf("Stop before Start should not error: %v", err)
	}

	// Note: We skip actual Start/Stop test because it requires a real port
	// and backend connections. In production, use integration tests.

	stats := handler.GetStats()
	if stats["running"].(bool) {
		t.Error("Handler should not be running")
	}
}
