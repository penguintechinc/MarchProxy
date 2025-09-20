// +build !numa

package numa

import (
	"log"
	"time"
)

// NUMAManager handles NUMA topology management (fallback implementation)
type NUMAManager struct {
	config  *NUMAConfig
	running bool
}

// NUMAConfig holds NUMA configuration
type NUMAConfig struct {
	Enabled      bool
	PreferredNode int
	MemoryPolicy  string
}

// NUMAStats holds NUMA statistics
type NUMAStats struct {
	MemoryAllocations map[int]uint64
	PageFaults        uint64
	Migrations        uint64
	LastUpdate        time.Time
}

// NewNUMAManager creates a new NUMA manager (fallback)
func NewNUMAManager(config *NUMAConfig) (*NUMAManager, error) {
	return &NUMAManager{
		config: config,
	}, nil
}

// Initialize initializes NUMA (fallback - no-op)
func (nm *NUMAManager) Initialize() error {
	log.Printf("NUMA: Using fallback implementation (NUMA not available)")
	return nil
}

// Start starts NUMA management (fallback - no-op)
func (nm *NUMAManager) Start() error {
	nm.running = true
	log.Printf("NUMA: Fallback implementation started")
	return nil
}

// Stop stops NUMA management (fallback - no-op)
func (nm *NUMAManager) Stop() error {
	nm.running = false
	log.Printf("NUMA: Fallback implementation stopped")
	return nil
}

// IsRunning returns whether NUMA is running
func (nm *NUMAManager) IsRunning() bool {
	return nm.running
}

// GetStats returns NUMA statistics (fallback - empty stats)
func (nm *NUMAManager) GetStats() *NUMAStats {
	return &NUMAStats{
		MemoryAllocations: make(map[int]uint64),
		LastUpdate:        time.Now(),
	}
}

// GetConfig returns NUMA configuration
func (nm *NUMAManager) GetConfig() *NUMAConfig {
	return nm.config
}