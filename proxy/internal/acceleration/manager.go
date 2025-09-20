package acceleration

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/penguintech/marchproxy/internal/acceleration/afxdp"
	"github.com/penguintech/marchproxy/internal/acceleration/dpdk"
	"github.com/penguintech/marchproxy/internal/acceleration/sriov"
	"github.com/penguintech/marchproxy/internal/acceleration/xdp"
	"github.com/penguintech/marchproxy/internal/proxy"
)

// AccelerationManager coordinates all network acceleration technologies
type AccelerationManager struct {
	config           *AccelerationConfig
	detectedCapabilities *HardwareCapabilities

	// Technology managers
	xdpManager       *xdp.XDPManager
	sriovManager     *sriov.SRIOVManager
	afxdpBridge      *afxdp.XDPAFXDPBridge

	// Go proxy integration
	goProxy          *proxy.GoProxy

	// State
	initialized      bool
	running          bool
	mu               sync.RWMutex

	// Statistics
	stats            *AccelerationStats
}

// AccelerationConfig holds configuration for all acceleration technologies
type AccelerationConfig struct {
	// General settings
	InterfaceName    string
	EnabledTechnologies []AccelerationType
	FallbackMode     FallbackMode
	PerformanceMode  PerformanceMode

	// XDP settings
	XDPConfig        *xdp.XDPConfig

	// AF_XDP settings
	AFXDPConfig      *afxdp.BridgeConfig

	// SR-IOV settings
	SRIOVConfig      *sriov.SRIOVConfig

	// Performance tuning
	PacketBatchSize  int
	CPUAffinity      []int
	NUMANode         int
	HugePages        bool
	StatsInterval    time.Duration
}

// AccelerationType represents different acceleration technologies
type AccelerationType int

const (
	AccelNone AccelerationType = iota
	AccelXDP
	AccelAFXDP
	AccelSRIOV
)

// FallbackMode defines fallback behavior
type FallbackMode int

const (
	FallbackGoProxy FallbackMode = iota
	FallbackKernel
	FallbackDrop
)

// PerformanceMode defines performance optimization level
type PerformanceMode int

const (
	PerformanceBalanced PerformanceMode = iota
	PerformanceLatency
	PerformanceThroughput
	PerformanceEfficiency
)

// AccelerationStats holds overall acceleration statistics
type AccelerationStats struct {
	// Technology usage
	XDPPackets       uint64
	AFXDPPackets     uint64
	GoProxyPackets   uint64
	KernelPackets    uint64

	// Performance metrics
	AvgLatency       time.Duration
	TotalThroughput  uint64
	PacketsPerSecond uint64

	// Technology-specific stats
	XDPStats         *xdp.XDPStats
	AFXDPStats       *afxdp.BridgeStats
	SRIOVStats       *sriov.SRIOVStats

	LastUpdate       time.Time
}

// NewAccelerationManager creates a new acceleration manager
func NewAccelerationManager(config *AccelerationConfig) *AccelerationManager {
	if config == nil {
		config = &AccelerationConfig{
			EnabledTechnologies: []AccelerationType{AccelXDP, AccelAFXDP},
			FallbackMode:        FallbackGoProxy,
			PerformanceMode:     PerformanceBalanced,
			PacketBatchSize:     64,
			StatsInterval:       time.Second * 5,
		}
	}

	return &AccelerationManager{
		config: config,
		stats:  &AccelerationStats{LastUpdate: time.Now()},
	}
}

// Initialize discovers hardware capabilities and initializes acceleration
func (am *AccelerationManager) Initialize() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.initialized {
		return fmt.Errorf("acceleration manager already initialized")
	}

	log.Printf("Acceleration: Initializing hardware acceleration")

	// Detect hardware capabilities
	detector := NewHardwareDetector()
	capabilities, err := detector.DetectCapabilities()
	if err != nil {
		return fmt.Errorf("failed to detect hardware capabilities: %w", err)
	}
	am.detectedCapabilities = capabilities

	// Initialize enabled technologies in order of performance
	for _, tech := range am.config.EnabledTechnologies {
		if err := am.initializeTechnology(tech); err != nil {
			log.Printf("Acceleration: Failed to initialize %s: %v", am.techToString(tech), err)
			// Continue with other technologies
		}
	}

	// Initialize XDP-AF_XDP bridge if both are enabled
	if am.isEnabled(AccelXDP) && am.isEnabled(AccelAFXDP) {
		if err := am.initializeXDPAFXDPBridge(); err != nil {
			log.Printf("Acceleration: Failed to initialize XDP-AF_XDP bridge: %v", err)
		}
	}

	am.initialized = true

	// Start statistics collection
	go am.statsCollector()

	log.Printf("Acceleration: Initialized with capabilities: %s", am.getCapabilitiesSummary())
	return nil
}

// initializeTechnology initializes a specific acceleration technology
func (am *AccelerationManager) initializeTechnology(tech AccelerationType) error {
	switch tech {
	case AccelXDP:
		return am.initializeXDP()
	case AccelSRIOV:
		return am.initializeSRIOV()
	case AccelAFXDP:
		// AF_XDP is initialized as part of the bridge
		return nil
	default:
		return fmt.Errorf("unknown acceleration technology: %d", tech)
	}
}


// initializeXDP initializes XDP acceleration
func (am *AccelerationManager) initializeXDP() error {
	if !am.detectedCapabilities.XDP.Available {
		return fmt.Errorf("XDP not available")
	}

	xdpConfig := am.config.XDPConfig
	if xdpConfig == nil {
		// Use default XDP configuration
		xdpConfig = &xdp.XDPConfig{
			InterfaceName: am.config.InterfaceName,
			Mode:          "native",
			ProgramPath:   "/app/ebpf/proxy_xdp.o",
			MapPinPath:    "/sys/fs/bpf/marchproxy",
		}
	}

	manager, err := xdp.NewXDPManager(xdpConfig)
	if err != nil {
		return fmt.Errorf("failed to create XDP manager: %w", err)
	}

	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize XDP: %w", err)
	}

	am.xdpManager = manager
	log.Printf("Acceleration: XDP initialized")
	return nil
}

// initializeSRIOV initializes SR-IOV acceleration
func (am *AccelerationManager) initializeSRIOV() error {
	if !am.detectedCapabilities.SRIOV.Available {
		return fmt.Errorf("SR-IOV not available")
	}

	sriovConfig := am.config.SRIOVConfig
	if sriovConfig == nil {
		// Use default SR-IOV configuration
		sriovConfig = &sriov.SRIOVConfig{
			EnabledPFs:        []string{am.config.InterfaceName},
			MaxVFsPerPF:       8,
			VLANMode:          "disabled",
			SecurityMode:      "strict",
			EnableSpoofCheck:  true,
			EnableTrustMode:   false,
			AutoConfiguration: true,
			PCIPassthrough:    false,
		}
	}

	manager := sriov.NewSRIOVManager(true, sriovConfig)
	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize SR-IOV: %w", err)
	}

	am.sriovManager = manager
	log.Printf("Acceleration: SR-IOV initialized")
	return nil
}

// initializeXDPAFXDPBridge initializes the XDP-AF_XDP bridge
func (am *AccelerationManager) initializeXDPAFXDPBridge() error {
	afxdpConfig := am.config.AFXDPConfig
	if afxdpConfig == nil {
		// Use default AF_XDP configuration with enhanced processing
		afxdpConfig = &afxdp.BridgeConfig{
			InterfaceName:           am.config.InterfaceName,
			NumQueues:               4,
			AFXDPFrameSize:          2048,
			AFXDPFrameCount:         4096,
			AFXDPBatchSize:          64,
			ZeroCopy:                true,
			SlowPathThreshold:       20.0,
			StatsInterval:           time.Second * 5,
			EnableEnhancedProcessor: true,
			ProcessorConfig: &afxdp.ProcessorConfig{
				MaxCacheSize:         10000,
				CacheTTL:            time.Minute * 5,
				EnableDeepInspection: true,
				MaxPacketSize:       65536,
				AuthTokenTTL:        time.Hour,
			},
		}
	}

	bridge := afxdp.NewXDPAFXDPBridge(afxdpConfig)
	if err := bridge.Initialize(am.xdpManager, am.goProxy); err != nil {
		return fmt.Errorf("failed to initialize XDP-AF_XDP bridge: %w", err)
	}

	am.afxdpBridge = bridge
	log.Printf("Acceleration: XDP-AF_XDP bridge initialized with enhanced processing")
	return nil
}

// SetGoProxy sets the Go proxy for fallback processing
func (am *AccelerationManager) SetGoProxy(goProxy *proxy.GoProxy) {
	am.goProxy = goProxy
	if am.afxdpBridge != nil {
		// Update bridge with Go proxy reference
		am.afxdpBridge.Initialize(am.xdpManager, goProxy)
	}
}

// Start begins acceleration processing
func (am *AccelerationManager) Start() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return fmt.Errorf("acceleration manager not initialized")
	}

	if am.running {
		return fmt.Errorf("acceleration manager already running")
	}

	// Start enabled technologies
	if am.xdpManager != nil {
		if err := am.xdpManager.Start(); err != nil {
			log.Printf("Acceleration: Failed to start XDP: %v", err)
		}
	}

	if am.afxdpBridge != nil {
		if err := am.afxdpBridge.Start(); err != nil {
			log.Printf("Acceleration: Failed to start XDP-AF_XDP bridge: %v", err)
		}
	}

	am.running = true
	log.Printf("Acceleration: Started processing")
	return nil
}

// isEnabled checks if a technology is enabled
func (am *AccelerationManager) isEnabled(tech AccelerationType) bool {
	for _, enabledTech := range am.config.EnabledTechnologies {
		if enabledTech == tech {
			return true
		}
	}
	return false
}

// techToString converts AccelerationType to string
func (am *AccelerationManager) techToString(tech AccelerationType) string {
	switch tech {
	case AccelXDP:
		return "XDP"
	case AccelAFXDP:
		return "AF_XDP"
	case AccelSRIOV:
		return "SR-IOV"
	default:
		return "Unknown"
	}
}

// getCapabilitiesSummary returns a summary of detected capabilities
func (am *AccelerationManager) getCapabilitiesSummary() string {
	var capabilities []string

	if am.detectedCapabilities.DPDK.Available {
		capabilities = append(capabilities, "DPDK")
	}
	if am.detectedCapabilities.XDP.Available {
		capabilities = append(capabilities, "XDP")
	}
	if am.detectedCapabilities.AFXDP.Available {
		capabilities = append(capabilities, "AF_XDP")
	}
	if am.detectedCapabilities.SRIOV.Available {
		capabilities = append(capabilities, "SR-IOV")
	}

	if len(capabilities) == 0 {
		return "None"
	}

	return fmt.Sprintf("%v", capabilities)
}

// statsCollector collects statistics from all acceleration technologies
func (am *AccelerationManager) statsCollector() {
	ticker := time.NewTicker(am.config.StatsInterval)
	defer ticker.Stop()

	for am.running {
		select {
		case <-ticker.C:
			am.updateStats()
		}
	}
}

// updateStats updates overall acceleration statistics
func (am *AccelerationManager) updateStats() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Collect stats from each technology
	if am.dpdkManager != nil {
		am.stats.DPDKStats = am.dpdkManager.GetStats()
		am.stats.DPDKPackets = am.stats.DPDKStats.RxPackets
	}

	if am.xdpManager != nil {
		am.stats.XDPStats = am.xdpManager.GetStats()
		am.stats.XDPPackets = am.stats.XDPStats.TotalPackets
	}

	if am.afxdpBridge != nil {
		am.stats.AFXDPStats = am.afxdpBridge.GetStats()
		am.stats.AFXDPPackets = am.stats.AFXDPStats.SlowPathPackets
	}

	if am.sriovManager != nil {
		am.stats.SRIOVStats = am.sriovManager.GetStats()
	}

	// Calculate overall metrics
	totalPackets := am.stats.DPDKPackets + am.stats.XDPPackets +
	               am.stats.AFXDPPackets + am.stats.GoProxyPackets

	if totalPackets > 0 {
		timeDiff := time.Since(am.stats.LastUpdate)
		if timeDiff > 0 {
			am.stats.PacketsPerSecond = uint64(float64(totalPackets) / timeDiff.Seconds())
		}
	}

	am.stats.LastUpdate = time.Now()
}

// GetStats returns current acceleration statistics
func (am *AccelerationManager) GetStats() *AccelerationStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := *am.stats
	return &stats
}

// GetCapabilities returns detected hardware capabilities
func (am *AccelerationManager) GetCapabilities() *HardwareCapabilities {
	return am.detectedCapabilities
}

// Stop stops all acceleration technologies
func (am *AccelerationManager) Stop() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.running {
		return nil
	}

	am.running = false

	// Stop all technologies
	if am.afxdpBridge != nil {
		am.afxdpBridge.Stop()
	}

	if am.xdpManager != nil {
		am.xdpManager.Stop()
	}

	if am.dpdkManager != nil {
		am.dpdkManager.Stop()
	}

	if am.sriovManager != nil {
		am.sriovManager.Stop()
	}

	log.Printf("Acceleration: Stopped all technologies")
	return nil
}

// IsInitialized returns whether the manager is initialized
func (am *AccelerationManager) IsInitialized() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.initialized
}

// IsRunning returns whether the manager is running
func (am *AccelerationManager) IsRunning() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.running
}

// GetActiveTechnologies returns a list of active acceleration technologies
func (am *AccelerationManager) GetActiveTechnologies() []string {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var active []string

	if am.dpdkManager != nil && am.dpdkManager.IsRunning() {
		active = append(active, "DPDK")
	}
	if am.xdpManager != nil && am.xdpManager.IsRunning() {
		active = append(active, "XDP")
	}
	if am.afxdpBridge != nil && am.afxdpBridge.IsRunning() {
		active = append(active, "AF_XDP")
	}
	if am.sriovManager != nil && am.sriovManager.IsEnabled() {
		active = append(active, "SR-IOV")
	}

	return active
}

// UpdateConfig updates acceleration configuration
func (am *AccelerationManager) UpdateConfig(newConfig *AccelerationConfig) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Validate new configuration
	if newConfig == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Update configuration
	am.config = newConfig

	// Restart if running to apply new configuration
	if am.running {
		log.Printf("Acceleration: Restarting to apply new configuration")
		am.running = false
		// Stop and restart would be implemented here
		am.running = true
	}

	return nil
}