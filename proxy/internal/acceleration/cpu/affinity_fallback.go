// +build !linux

package cpu

import (
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/penguintech/marchproxy/internal/manager"
)

// AffinityManager handles CPU affinity and core isolation (fallback implementation)
type AffinityManager struct {
	enabled        bool
	config         *AffinityConfig
	topology       *CPUTopology
	coreGroups     map[string]*CoreGroup
	isolatedCores  []int
	stats          *AffinityStats
	initialized    bool
}

// AffinityConfig holds CPU affinity configuration
type AffinityConfig struct {
	Enabled       bool
	IsolatedCores []int
	CoreGroups    map[string][]int
	AutoDetect    bool
}

// CPUTopology represents the CPU topology
type CPUTopology struct {
	NumCPUs      int
	NumCores     int
	NumSockets   int
	CPUInfo      map[int]*CPUInfo
	CoreSiblings map[int][]int
	NUMANodes    map[int][]int
	SocketCPUs   map[int][]int
}

// CPUInfo represents information about a single CPU
type CPUInfo struct {
	ID           int
	CoreID       int
	SocketID     int
	NUMANode     int
	Frequency    float64
	Governor     string
	CurrentLoad  float64
	LastUpdate   time.Time
}

// CoreGroup represents a group of CPU cores
type CoreGroup struct {
	Name        string
	Cores       []int
	Priority    int
	Isolated    bool
	ServiceType string
}

// AffinityStats holds affinity statistics
type AffinityStats struct {
	ThreadAffinityChanges uint64
	ProcessAffinityChanges uint64
	IsolationViolations   uint64
	LoadBalancingEvents   uint64
	LastUpdate            time.Time
}

// NewAffinityManager creates a new affinity manager (fallback)
func NewAffinityManager(config *AffinityConfig) *AffinityManager {
	if config == nil {
		config = &AffinityConfig{
			Enabled:    false,
			AutoDetect: true,
		}
	}

	return &AffinityManager{
		enabled:     config.Enabled,
		config:      config,
		coreGroups:  make(map[string]*CoreGroup),
		stats:       &AffinityStats{LastUpdate: time.Now()},
	}
}

// Initialize initializes the affinity manager (fallback - no-op)
func (am *AffinityManager) Initialize() error {
	log.Printf("CPU: Using fallback affinity implementation (not supported on this platform)")

	// Basic topology detection
	am.topology = &CPUTopology{
		NumCPUs:      runtime.NumCPU(),
		NumCores:     runtime.NumCPU(),
		NumSockets:   1,
		CPUInfo:      make(map[int]*CPUInfo),
		CoreSiblings: make(map[int][]int),
		NUMANodes:    make(map[int][]int),
		SocketCPUs:   make(map[int][]int),
	}

	// Create basic CPU info
	for i := 0; i < runtime.NumCPU(); i++ {
		am.topology.CPUInfo[i] = &CPUInfo{
			ID:         i,
			CoreID:     i,
			SocketID:   0,
			NUMANode:   0,
			LastUpdate: time.Now(),
		}
	}

	am.initialized = true
	return nil
}

// SetThreadAffinity sets CPU affinity for a thread (fallback - no-op)
func (am *AffinityManager) SetThreadAffinity(threadID int, groupName string) error {
	log.Printf("CPU: SetThreadAffinity not supported on this platform")
	return nil
}

// SetProcessAffinity sets CPU affinity for a process (fallback - no-op)
func (am *AffinityManager) SetProcessAffinity(processID int, groupName string) error {
	log.Printf("CPU: SetProcessAffinity not supported on this platform")
	return nil
}

// CreateCoreGroup creates a new core group
func (am *AffinityManager) CreateCoreGroup(name string, cores []int, priority int, serviceType string) error {
	am.coreGroups[name] = &CoreGroup{
		Name:        name,
		Cores:       cores,
		Priority:    priority,
		ServiceType: serviceType,
	}
	log.Printf("CPU: Created core group '%s' with cores %v", name, cores)
	return nil
}

// GetTopology returns the CPU topology
func (am *AffinityManager) GetTopology() *CPUTopology {
	return am.topology
}

// GetStats returns affinity statistics
func (am *AffinityManager) GetStats() *AffinityStats {
	stats := *am.stats
	stats.LastUpdate = time.Now()
	return &stats
}

// IsInitialized returns whether the manager is initialized
func (am *AffinityManager) IsInitialized() bool {
	return am.initialized
}

// Cleanup cleans up affinity management (fallback - no-op)
func (am *AffinityManager) Cleanup() error {
	log.Printf("CPU: Cleanup not needed on this platform")
	am.initialized = false
	return nil
}