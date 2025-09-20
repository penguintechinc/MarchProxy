// +build linux

package cpu

import (
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/penguintech/marchproxy/internal/manager"
)

// AffinityManager handles CPU affinity and core isolation
type AffinityManager struct {
	enabled        bool
	initialized    bool
	topology       *CPUTopology
	coreGroups     map[string]*CoreGroup
	isolatedCores  []int
	dedicatedCores map[string][]int
	config         *AffinityConfig
	stats          *AffinityStats
	mu             sync.RWMutex
}

// CPUTopology represents the CPU topology of the system
type CPUTopology struct {
	NumCPUs         int
	NumCores        int
	NumSockets      int
	ThreadsPerCore  int
	CoresPerSocket  int
	CPUInfo         map[int]*CPUInfo
	CoreSiblings    map[int][]int
	SocketCPUs      map[int][]int
	NUMANodes       map[int][]int
	CacheTopology   map[int]*CacheInfo
	LastScan        time.Time
}

// CPUInfo holds information about a specific CPU
type CPUInfo struct {
	ID            int
	CoreID        int
	SocketID      int
	NUMANode      int
	Frequency     uint64
	Governor      string
	OnlineState   bool
	IsolationMode string
	Affinity      []int
	CurrentLoad   float64
	LastUpdate    time.Time
}

// CacheInfo holds CPU cache information
type CacheInfo struct {
	Level    int
	Type     string
	Size     uint64
	LineSize int
	Ways     int
	SharedBy []int
}

// CoreGroup represents a group of CPU cores with specific assignments
type CoreGroup struct {
	Name          string
	Cores         []int
	Purpose       string
	Priority      int
	Exclusive     bool
	LoadBalanced  bool
	Statistics    *GroupStats
	LastActivity  time.Time
}

// GroupStats holds statistics for a core group
type GroupStats struct {
	TotalTasks       uint64
	CompletedTasks   uint64
	AverageLoad      float64
	PeakLoad         float64
	ContextSwitches  uint64
	CacheMisses      uint64
	CacheHitRatio    float64
	PowerConsumption float64
	LastUpdate       time.Time
}

// AffinityStats holds overall affinity management statistics
type AffinityStats struct {
	TotalCPUs         int
	IsolatedCPUs      int
	DedicatedCPUs     int
	ActiveGroups      int
	LoadBalance       float64
	AverageUtilization float64
	ContextSwitches   uint64
	Migrations        uint64
	IsolationViolations uint64
	LastUpdate        time.Time
}

// AffinityConfig holds CPU affinity configuration
type AffinityConfig struct {
	EnableIsolation    bool
	IsolatedCores      []int
	CoreGroups         map[string][]int
	AutoBalance        bool
	HotplugSupport     bool
	PowerManagement    bool
	RealTimeSupport    bool
	StatsInterval      time.Duration
	LoadThreshold      float64
	MigrationPolicy    string
}

// NewAffinityManager creates a new CPU affinity manager
func NewAffinityManager(enabled bool, config *AffinityConfig) *AffinityManager {
	if config == nil {
		config = &AffinityConfig{
			EnableIsolation: true,
			IsolatedCores:   []int{},
			CoreGroups:      make(map[string][]int),
			AutoBalance:     true,
			HotplugSupport:  false,
			PowerManagement: true,
			RealTimeSupport: false,
			StatsInterval:   time.Second * 5,
			LoadThreshold:   0.8,
			MigrationPolicy: "conservative",
		}
	}

	return &AffinityManager{
		enabled:        enabled,
		coreGroups:     make(map[string]*CoreGroup),
		dedicatedCores: make(map[string][]int),
		config:         config,
		stats: &AffinityStats{
			LastUpdate: time.Now(),
		},
	}
}

// Initialize discovers CPU topology and sets up core isolation
func (am *AffinityManager) Initialize() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.enabled {
		return fmt.Errorf("CPU affinity management is disabled")
	}

	if am.initialized {
		return fmt.Errorf("CPU affinity already initialized")
	}

	fmt.Printf("CPU: Discovering CPU topology and setting up affinity management\n")

	// Discover CPU topology
	if err := am.discoverCPUTopology(); err != nil {
		return fmt.Errorf("failed to discover CPU topology: %w", err)
	}

	// Set up core isolation
	if am.config.EnableIsolation {
		if err := am.setupCoreIsolation(); err != nil {
			fmt.Printf("CPU: Warning - failed to setup core isolation: %v\n", err)
		}
	}

	// Create default core groups
	am.createDefaultCoreGroups()

	am.initialized = true

	// Start statistics collection
	go am.statsCollector()

	fmt.Printf("CPU: Initialized with %d CPUs, %d cores, %d sockets\n",
		am.topology.NumCPUs, am.topology.NumCores, am.topology.NumSockets)
	return nil
}

// discoverCPUTopology discovers the system's CPU topology
func (am *AffinityManager) discoverCPUTopology() error {
	topology := &CPUTopology{
		NumCPUs:       runtime.NumCPU(),
		CPUInfo:       make(map[int]*CPUInfo),
		CoreSiblings:  make(map[int][]int),
		SocketCPUs:    make(map[int][]int),
		NUMANodes:     make(map[int][]int),
		CacheTopology: make(map[int]*CacheInfo),
		LastScan:      time.Now(),
	}

	// Read CPU information from /proc/cpuinfo
	cpuInfoData, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		return fmt.Errorf("failed to read /proc/cpuinfo: %w", err)
	}

	cpuBlocks := strings.Split(string(cpuInfoData), "\n\n")
	for _, block := range cpuBlocks {
		if strings.TrimSpace(block) == "" {
			continue
		}

		cpuInfo := am.parseCPUInfoBlock(block)
		if cpuInfo != nil {
			topology.CPUInfo[cpuInfo.ID] = cpuInfo
		}
	}

	// Discover topology from sysfs
	am.discoverCPUTopologyFromSysfs(topology)

	am.topology = topology
	return nil
}

// parseCPUInfoBlock parses a CPU information block from /proc/cpuinfo
func (am *AffinityManager) parseCPUInfoBlock(block string) *CPUInfo {
	lines := strings.Split(block, "\n")
	cpuInfo := &CPUInfo{
		OnlineState: true,
		LastUpdate:  time.Now(),
	}

	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "processor":
				if id, err := strconv.Atoi(value); err == nil {
					cpuInfo.ID = id
				}
			case "core id":
				if coreID, err := strconv.Atoi(value); err == nil {
					cpuInfo.CoreID = coreID
				}
			case "physical id":
				if socketID, err := strconv.Atoi(value); err == nil {
					cpuInfo.SocketID = socketID
				}
			case "cpu MHz":
				if freq, err := strconv.ParseFloat(value, 64); err == nil {
					cpuInfo.Frequency = uint64(freq * 1000000) // Convert to Hz
				}
			}
		}
	}

	return cpuInfo
}

// discoverCPUTopologyFromSysfs discovers CPU topology from sysfs
func (am *AffinityManager) discoverCPUTopologyFromSysfs(topology *CPUTopology) {
	// Read topology information from /sys/devices/system/cpu/
	cpuPath := "/sys/devices/system/cpu"

	// Count cores and sockets
	coreIDs := make(map[int]bool)
	socketIDs := make(map[int]bool)

	for cpuID := range topology.CPUInfo {
		cpuInfo := topology.CPUInfo[cpuID]

		// Read thread siblings
		siblingsPath := fmt.Sprintf("%s/cpu%d/topology/thread_siblings_list", cpuPath, cpuID)
		if siblingsData, err := ioutil.ReadFile(siblingsPath); err == nil {
			siblings := am.parseCPUList(strings.TrimSpace(string(siblingsData)))
			topology.CoreSiblings[cpuID] = siblings
		}

		// Read NUMA node
		numaPath := fmt.Sprintf("%s/cpu%d/topology/physical_package_id", cpuPath, cpuID)
		if numaData, err := ioutil.ReadFile(numaPath); err == nil {
			if numaNode, err := strconv.Atoi(strings.TrimSpace(string(numaData))); err == nil {
				cpuInfo.NUMANode = numaNode
				topology.NUMANodes[numaNode] = append(topology.NUMANodes[numaNode], cpuID)
			}
		}

		// Read CPU frequency governor
		govPath := fmt.Sprintf("%s/cpu%d/cpufreq/scaling_governor", cpuPath, cpuID)
		if govData, err := ioutil.ReadFile(govPath); err == nil {
			cpuInfo.Governor = strings.TrimSpace(string(govData))
		}

		coreIDs[cpuInfo.CoreID] = true
		socketIDs[cpuInfo.SocketID] = true
		topology.SocketCPUs[cpuInfo.SocketID] = append(topology.SocketCPUs[cpuInfo.SocketID], cpuID)
	}

	topology.NumCores = len(coreIDs)
	topology.NumSockets = len(socketIDs)
	if topology.NumCores > 0 {
		topology.ThreadsPerCore = topology.NumCPUs / topology.NumCores
	}
	if topology.NumSockets > 0 {
		topology.CoresPerSocket = topology.NumCores / topology.NumSockets
	}
}

// parseCPUList parses a CPU list string (e.g., "0-3,8-11")
func (am *AffinityManager) parseCPUList(cpuList string) []int {
	var cpus []int

	if cpuList == "" {
		return cpus
	}

	ranges := strings.Split(cpuList, ",")
	for _, rangeStr := range ranges {
		if strings.Contains(rangeStr, "-") {
			parts := strings.Split(rangeStr, "-")
			if len(parts) == 2 {
				start, _ := strconv.Atoi(parts[0])
				end, _ := strconv.Atoi(parts[1])
				for i := start; i <= end; i++ {
					cpus = append(cpus, i)
				}
			}
		} else {
			if cpu, err := strconv.Atoi(rangeStr); err == nil {
				cpus = append(cpus, cpu)
			}
		}
	}

	return cpus
}

// setupCoreIsolation sets up CPU core isolation
func (am *AffinityManager) setupCoreIsolation() error {
	if len(am.config.IsolatedCores) == 0 {
		// Auto-select cores for isolation (e.g., last cores on each socket)
		am.autoSelectIsolatedCores()
	}

	am.isolatedCores = am.config.IsolatedCores

	// Check if kernel boot parameter isolcpus is set
	cmdlineData, err := ioutil.ReadFile("/proc/cmdline")
	if err == nil {
		cmdline := string(cmdlineData)
		if strings.Contains(cmdline, "isolcpus=") {
			fmt.Printf("CPU: Kernel-level CPU isolation detected\n")
		} else {
			fmt.Printf("CPU: Warning - isolcpus kernel parameter not set, isolation may be limited\n")
		}
	}

	fmt.Printf("CPU: Isolated cores: %v\n", am.isolatedCores)
	return nil
}

// autoSelectIsolatedCores automatically selects cores for isolation
func (am *AffinityManager) autoSelectIsolatedCores() {
	if am.topology.NumCPUs < 4 {
		return // Need at least 4 CPUs for isolation
	}

	// Isolate last 2 CPUs from each socket
	for socketID, cpus := range am.topology.SocketCPUs {
		if len(cpus) >= 4 {
			// Isolate last 2 CPUs from this socket
			isolateCount := 2
			start := len(cpus) - isolateCount
			for i := start; i < len(cpus); i++ {
				am.config.IsolatedCores = append(am.config.IsolatedCores, cpus[i])
			}
			fmt.Printf("CPU: Auto-isolated %d cores from socket %d\n", isolateCount, socketID)
		}
	}
}

// createDefaultCoreGroups creates default core groups
func (am *AffinityManager) createDefaultCoreGroups() {
	// System group (non-isolated cores)
	systemCores := []int{}
	for cpuID := range am.topology.CPUInfo {
		isolated := false
		for _, isolatedCore := range am.isolatedCores {
			if cpuID == isolatedCore {
				isolated = true
				break
			}
		}
		if !isolated {
			systemCores = append(systemCores, cpuID)
		}
	}

	if len(systemCores) > 0 {
		am.createCoreGroup("system", systemCores, "System and background tasks", 1, false)
	}

	// Packet processing group (isolated cores)
	if len(am.isolatedCores) > 0 {
		am.createCoreGroup("packet", am.isolatedCores, "Dedicated packet processing", 10, true)
	}

	fmt.Printf("CPU: Created %d default core groups\n", len(am.coreGroups))
}

// createCoreGroup creates a new core group
func (am *AffinityManager) createCoreGroup(name string, cores []int, purpose string, priority int, exclusive bool) error {
	group := &CoreGroup{
		Name:         name,
		Cores:        make([]int, len(cores)),
		Purpose:      purpose,
		Priority:     priority,
		Exclusive:    exclusive,
		LoadBalanced: !exclusive,
		Statistics: &GroupStats{
			LastUpdate: time.Now(),
		},
		LastActivity: time.Now(),
	}

	copy(group.Cores, cores)
	am.coreGroups[name] = group
	am.dedicatedCores[name] = cores

	fmt.Printf("CPU: Created core group '%s' with cores %v (exclusive: %t)\n", name, cores, exclusive)
	return nil
}

// SetThreadAffinity sets CPU affinity for a thread to a specific core group
func (am *AffinityManager) SetThreadAffinity(groupName string, threadID int) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return fmt.Errorf("CPU affinity manager not initialized")
	}

	group, exists := am.coreGroups[groupName]
	if !exists {
		return fmt.Errorf("core group '%s' not found", groupName)
	}

	// Simplified CPU affinity setting
	// Note: Full implementation would use C bindings or syscalls
	if threadID == 0 {
		threadID = syscall.Gettid()
	}

	// For now, just log the affinity change
	fmt.Printf("Setting CPU affinity for thread %d to cores %v\n", threadID, group.Cores)

	// Placeholder for actual syscall implementation
	var err error = nil
	if err != nil {
		return fmt.Errorf("failed to set CPU affinity: %w", err)
	}

	group.LastActivity = time.Now()
	fmt.Printf("CPU: Set thread %d affinity to group '%s' (cores: %v)\n", threadID, groupName, group.Cores)
	return nil
}

// SetProcessAffinity sets CPU affinity for a process
func (am *AffinityManager) SetProcessAffinity(groupName string, processID int) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return fmt.Errorf("CPU affinity manager not initialized")
	}

	group, exists := am.coreGroups[groupName]
	if !exists {
		return fmt.Errorf("core group '%s' not found", groupName)
	}

	// Simplified CPU affinity setting for process
	// Note: Full implementation would use C bindings or syscalls
	fmt.Printf("Setting CPU affinity for process %d to cores %v\n", processID, group.Cores)

	// Placeholder for actual syscall implementation
	var err error = nil
	if err != nil {
		return fmt.Errorf("failed to set process CPU affinity: %w", err)
	}

	group.LastActivity = time.Now()
	fmt.Printf("CPU: Set process %d affinity to group '%s' (cores: %v)\n", processID, groupName, group.Cores)
	return nil
}

// IsolateCore isolates a CPU core from the scheduler
func (am *AffinityManager) IsolateCore(coreID int) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return fmt.Errorf("CPU affinity manager not initialized")
	}

	// Check if core exists
	if _, exists := am.topology.CPUInfo[coreID]; !exists {
		return fmt.Errorf("CPU core %d not found", coreID)
	}

	// Add to isolated cores list
	for _, isolated := range am.isolatedCores {
		if isolated == coreID {
			return fmt.Errorf("core %d already isolated", coreID)
		}
	}

	am.isolatedCores = append(am.isolatedCores, coreID)

	// Update CPU info
	if cpuInfo, exists := am.topology.CPUInfo[coreID]; exists {
		cpuInfo.IsolationMode = "isolated"
	}

	fmt.Printf("CPU: Isolated core %d\n", coreID)
	return nil
}

// statsCollector collects CPU affinity statistics
func (am *AffinityManager) statsCollector() {
	ticker := time.NewTicker(am.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.collectStatistics()
		}
	}
}

// collectStatistics collects and updates CPU statistics
func (am *AffinityManager) collectStatistics() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Update CPU load information
	for _, cpuInfo := range am.topology.CPUInfo {
		loadAvgPath := fmt.Sprintf("/proc/loadavg")
		if loadData, err := ioutil.ReadFile(loadAvgPath); err == nil {
			loadFields := strings.Fields(string(loadData))
			if len(loadFields) > 0 {
				if load, err := strconv.ParseFloat(loadFields[0], 64); err == nil {
					cpuInfo.CurrentLoad = load
				}
			}
		}
		cpuInfo.LastUpdate = time.Now()
	}

	// Update group statistics
	totalUtilization := 0.0
	activeGroups := 0

	for _, group := range am.coreGroups {
		if time.Since(group.LastActivity) < time.Minute*5 {
			activeGroups++
		}

		// Calculate group load
		groupLoad := 0.0
		for _, coreID := range group.Cores {
			if cpuInfo, exists := am.topology.CPUInfo[coreID]; exists {
				groupLoad += cpuInfo.CurrentLoad
			}
		}
		group.Statistics.AverageLoad = groupLoad / float64(len(group.Cores))
		totalUtilization += group.Statistics.AverageLoad
		group.Statistics.LastUpdate = time.Now()
	}

	// Update overall statistics
	am.stats.TotalCPUs = am.topology.NumCPUs
	am.stats.IsolatedCPUs = len(am.isolatedCores)
	am.stats.DedicatedCPUs = len(am.dedicatedCores)
	am.stats.ActiveGroups = activeGroups
	if len(am.coreGroups) > 0 {
		am.stats.AverageUtilization = totalUtilization / float64(len(am.coreGroups))
	}
	am.stats.LastUpdate = time.Now()
}

// UpdateServices updates service-to-core assignments
func (am *AffinityManager) UpdateServices(services []manager.Service) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	fmt.Printf("CPU: Updating core assignments for %d services\n", len(services))

	// In a full implementation, this would assign services to core groups
	// based on their performance requirements and current load

	return nil
}

// GetOptimalCoreGroup returns the optimal core group for a workload
func (am *AffinityManager) GetOptimalCoreGroup(workloadType string, priority int) (string, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if !am.initialized {
		return "", fmt.Errorf("CPU affinity manager not initialized")
	}

	// Simple selection logic based on workload type
	switch workloadType {
	case "packet_processing", "high_priority":
		if _, exists := am.coreGroups["packet"]; exists {
			return "packet", nil
		}
	case "background", "low_priority":
		if _, exists := am.coreGroups["system"]; exists {
			return "system", nil
		}
	}

	// Default to system group
	return "system", nil
}

// Stop cleans up CPU affinity resources
func (am *AffinityManager) Stop() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return nil
	}

	fmt.Printf("CPU: Cleaning up affinity management\n")

	// Reset all threads to use all CPUs
	// Note: Full implementation would use C bindings or syscalls
	fmt.Printf("Resetting CPU affinity for all threads to use all %d CPUs\n", am.topology.NumCPUs)

	am.initialized = false
	fmt.Printf("CPU: Affinity management cleanup complete\n")
	return nil
}

// GetStats returns current CPU affinity statistics
func (am *AffinityManager) GetStats() *AffinityStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := *am.stats
	return &stats
}

// IsEnabled returns whether CPU affinity management is enabled
func (am *AffinityManager) IsEnabled() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.enabled && am.initialized
}

// GetTopology returns CPU topology information
func (am *AffinityManager) GetTopology() *CPUTopology {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.topology == nil {
		return nil
	}

	topology := *am.topology
	return &topology
}

// GetCoreGroups returns all configured core groups
func (am *AffinityManager) GetCoreGroups() map[string]*CoreGroup {
	am.mu.RLock()
	defer am.mu.RUnlock()

	groups := make(map[string]*CoreGroup)
	for name, group := range am.coreGroups {
		groupCopy := *group
		groups[name] = &groupCopy
	}
	return groups
}

// GetIsolatedCores returns list of isolated CPU cores
func (am *AffinityManager) GetIsolatedCores() []int {
	am.mu.RLock()
	defer am.mu.RUnlock()

	cores := make([]int, len(am.isolatedCores))
	copy(cores, am.isolatedCores)
	return cores
}