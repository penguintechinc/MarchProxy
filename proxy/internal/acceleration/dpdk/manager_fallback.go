// +build !dpdk

package dpdk

import (
	"log"
	"time"
)

// DPDKManager handles DPDK acceleration (fallback implementation)
type DPDKManager struct {
	config  *DPDKConfig
	running bool
}

// DPDKConfig holds DPDK configuration
type DPDKConfig struct {
	Enabled      bool
	DriverType   string
	HugePages    int
	Cores        []int
	MemChannels  int
	PciDevices   []string
}

// DPDKStats holds DPDK statistics
type DPDKStats struct {
	RxPackets     uint64
	TxPackets     uint64
	RxBytes       uint64
	TxBytes       uint64
	DroppedPackets uint64
	ErrorPackets  uint64
	LastUpdate    time.Time
}

// NewDPDKManager creates a new DPDK manager (fallback)
func NewDPDKManager(config *DPDKConfig) (*DPDKManager, error) {
	return &DPDKManager{
		config: config,
	}, nil
}

// Initialize initializes DPDK (fallback - no-op)
func (dm *DPDKManager) Initialize() error {
	log.Printf("DPDK: Using fallback implementation (DPDK not available)")
	return nil
}

// Start starts DPDK processing (fallback - no-op)
func (dm *DPDKManager) Start() error {
	dm.running = true
	log.Printf("DPDK: Fallback implementation started")
	return nil
}

// Stop stops DPDK processing (fallback - no-op)
func (dm *DPDKManager) Stop() error {
	dm.running = false
	log.Printf("DPDK: Fallback implementation stopped")
	return nil
}

// IsRunning returns whether DPDK is running
func (dm *DPDKManager) IsRunning() bool {
	return dm.running
}

// GetStats returns DPDK statistics (fallback - empty stats)
func (dm *DPDKManager) GetStats() *DPDKStats {
	return &DPDKStats{
		LastUpdate: time.Now(),
	}
}

// GetConfig returns DPDK configuration
func (dm *DPDKManager) GetConfig() *DPDKConfig {
	return dm.config
}