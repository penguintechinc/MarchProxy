// +build !afxdp

package afxdp

import (
	"log"
	"time"
)

// AFXDPSocket represents an AF_XDP socket (fallback implementation)
type AFXDPSocket struct {
	config    *AFXDPConfig
	running   bool
	stats     *AFXDPSocketStats
}

// AFXDPSocketStats holds socket statistics
type AFXDPSocketStats struct {
	RxPackets  uint64
	TxPackets  uint64
	RxBytes    uint64
	TxBytes    uint64
	RxDropped  uint64
	TxDropped  uint64
	LastUpdate time.Time
}

// XDPPacket represents a packet from XDP
type XDPPacket struct {
	Data      []byte
	Length    uint32
	Timestamp time.Time
}

// PacketHandler is a function that processes packets
type PacketHandler func(*XDPPacket) bool

// NewAFXDPSocket creates a new AF_XDP socket (fallback)
func NewAFXDPSocket(config *AFXDPConfig) (*AFXDPSocket, error) {
	return &AFXDPSocket{
		config: config,
		stats: &AFXDPSocketStats{
			LastUpdate: time.Now(),
		},
	}, nil
}

// Initialize initializes the AF_XDP socket (fallback - no-op)
func (s *AFXDPSocket) Initialize() error {
	log.Printf("AF_XDP Socket: Using fallback implementation")
	return nil
}

// Start starts packet processing (fallback - no-op)
func (s *AFXDPSocket) Start(handler PacketHandler) error {
	s.running = true
	log.Printf("AF_XDP Socket: Fallback implementation started")
	return nil
}

// Stop stops packet processing (fallback - no-op)
func (s *AFXDPSocket) Stop() error {
	s.running = false
	log.Printf("AF_XDP Socket: Fallback implementation stopped")
	return nil
}

// GetStats returns socket statistics
func (s *AFXDPSocket) GetStats() *AFXDPSocketStats {
	stats := *s.stats
	stats.LastUpdate = time.Now()
	return &stats
}

// IsRunning returns whether the socket is running
func (s *AFXDPSocket) IsRunning() bool {
	return s.running
}