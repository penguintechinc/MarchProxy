// +build !afxdp

package afxdp

import (
	"log"
	"time"
)

// AFXDPManager handles AF_XDP acceleration (fallback implementation)
type AFXDPManager struct {
	config  *AFXDPConfig
	running bool
}

// AFXDPConfig holds AF_XDP configuration
type AFXDPConfig struct {
	InterfaceName string
	QueueID      int
	FrameSize    uint32
	FrameCount   uint32
	BatchSize    int
	ZeroCopy     bool
	WakeupFlag   bool
	PollTimeout  time.Duration
}

// AFXDPStats holds AF_XDP statistics
type AFXDPStats struct {
	RxPackets     uint64
	TxPackets     uint64
	RxBytes       uint64
	TxBytes       uint64
	RxDropped     uint64
	TxDropped     uint64
	LastUpdate    time.Time
}

// NewAFXDPManager creates a new AF_XDP manager (fallback)
func NewAFXDPManager(config *AFXDPConfig) (*AFXDPManager, error) {
	return &AFXDPManager{
		config: config,
	}, nil
}

// Initialize initializes AF_XDP (fallback - no-op)
func (am *AFXDPManager) Initialize() error {
	log.Printf("AF_XDP: Using fallback implementation (AF_XDP not available)")
	return nil
}

// Start starts AF_XDP processing (fallback - no-op)
func (am *AFXDPManager) Start() error {
	am.running = true
	log.Printf("AF_XDP: Fallback implementation started")
	return nil
}

// Stop stops AF_XDP processing (fallback - no-op)
func (am *AFXDPManager) Stop() error {
	am.running = false
	log.Printf("AF_XDP: Fallback implementation stopped")
	return nil
}

// IsRunning returns whether AF_XDP is running
func (am *AFXDPManager) IsRunning() bool {
	return am.running
}

// GetStats returns AF_XDP statistics (fallback - empty stats)
func (am *AFXDPManager) GetStats() *AFXDPStats {
	return &AFXDPStats{
		LastUpdate: time.Now(),
	}
}

// GetConfig returns AF_XDP configuration
func (am *AFXDPManager) GetConfig() *AFXDPConfig {
	return am.config
}