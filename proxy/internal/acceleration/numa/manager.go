// +build numa

package numa

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/penguintech/marchproxy/internal/manager"
)

// #include <sys/syscall.h>
// #include <unistd.h>
// #include <numa.h>
// #include <numaif.h>
// #include <errno.h>
//
// #cgo LDFLAGS: -lnuma
//
// int get_mempolicy_wrapper(int *policy, unsigned long *nmask, unsigned long maxnode, void *addr, unsigned long flags);
// int set_mempolicy_wrapper(int policy, unsigned long *nmask, unsigned long maxnode);
// int mbind_wrapper(void *start, unsigned long len, int policy, unsigned long *nmask, unsigned long maxnode, unsigned flags);
// long get_numa_node_of_cpu(int cpu);
// int migrate_pages_wrapper(int pid, unsigned long maxnode, unsigned long *old_nodes, unsigned long *new_nodes);
// void *numa_alloc_onnode_wrapper(size_t size, int node);
// void numa_free_wrapper(void *start, size_t size);
import "C"

// NUMAManager handles NUMA-aware memory management and CPU affinity
type NUMAManager struct {
	enabled      bool
	initialized  bool
	topology     *NUMATopology
	nodes        map[int]*NUMANode
	policies     map[string]*MemoryPolicy
	allocations  map[uintptr]*MemoryAllocation
	config       *NUMAConfig
	stats        *NUMAStats
	mu           sync.RWMutex
}

// NUMATopology represents the NUMA topology of the system
type NUMATopology struct {
	NumNodes     int
	NumCPUs      int
	NodesOnline  []int
	CPUsOnline   []int
	NodeCPUMap   map[int][]int
	CPUNodeMap   map[int]int
	Distances    map[int]map[int]int
	MemoryInfo   map[int]*NodeMemoryInfo
	LastScan     time.Time
}

// NUMANode represents a NUMA node with its resources
type NUMANode struct {
	ID           int
	CPUs         []int
	MemoryTotal  uint64
	MemoryFree   uint64
	MemoryUsed   uint64
	HugePagesTotal int
	HugePagesFree  int
	HugePagesSize  int
	Allocations  []*MemoryAllocation
	LoadAverage  float64
	Utilization  float64
	LastUpdate   time.Time
}

// NodeMemoryInfo holds detailed memory information for a NUMA node
type NodeMemoryInfo struct {
	MemTotal     uint64
	MemFree      uint64
	MemAvailable uint64
	Buffers      uint64
	Cached       uint64
	Active       uint64
	Inactive     uint64
	Dirty        uint64
	WriteBack    uint64
	Slab         uint64
	PageTables   uint64
	LastUpdate   time.Time
}

// MemoryPolicy defines memory allocation and binding policies
type MemoryPolicy struct {
	Name        string
	Policy      int    // MPOL_BIND, MPOL_INTERLEAVE, MPOL_PREFERRED, MPOL_DEFAULT
	NodeMask    uint64
	Flags       uint32
	Description string
}

// MemoryAllocation tracks a NUMA-aware memory allocation
type MemoryAllocation struct {
	Address     uintptr
	Size        uint64
	Node        int
	Policy      string
	Timestamp   time.Time
	ProcessID   int
	ThreadID    int
	Purpose     string
}

// NUMAStats holds NUMA performance statistics
type NUMAStats struct {
	TotalAllocations    uint64
	TotalDeallocations  uint64
	CrossNodeAccesses   uint64
	LocalNodeAccesses   uint64
	NumaHitRatio        float64
	MemoryMigrations    uint64
	PageFaults          uint64
	RemotePageFaults    uint64
	InterleaveHit       uint64
	InterleaveMiss      uint64
	PreferredNodeHit    uint64
	PreferredNodeMiss   uint64
	LastUpdate          time.Time
}

// NUMAConfig holds NUMA configuration parameters
type NUMAConfig struct {
	EnableAutoBinding     bool
	DefaultPolicy         string
	HugePagesEnabled      bool
	HugePagesSize         int
	PreferredNodes        []int
	ExcludedNodes         []int
	MemoryMigration       bool
	AutoBalance           bool
	StatsInterval         time.Duration
	AllocationThreshold   uint64
	LocalityThreshold     float64
}

// NewNUMAManager creates a new NUMA manager
func NewNUMAManager(enabled bool, config *NUMAConfig) *NUMAManager {
	if config == nil {
		config = &NUMAConfig{
			EnableAutoBinding:   true,
			DefaultPolicy:       "local",
			HugePagesEnabled:    false,
			HugePagesSize:       2048, // 2MB
			MemoryMigration:     false,
			AutoBalance:         true,
			StatsInterval:       time.Second * 10,
			AllocationThreshold: 1024 * 1024, // 1MB
			LocalityThreshold:   0.8,
		}
	}

	return &NUMAManager{
		enabled:     enabled,
		nodes:       make(map[int]*NUMANode),
		policies:    make(map[string]*MemoryPolicy),
		allocations: make(map[uintptr]*MemoryAllocation),
		config:      config,
		stats: &NUMAStats{
			LastUpdate: time.Now(),
		},
	}
}

// Initialize discovers NUMA topology and initializes memory policies
func (nm *NUMAManager) Initialize() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.enabled {
		return fmt.Errorf("NUMA is disabled")
	}

	if nm.initialized {
		return fmt.Errorf("NUMA already initialized")
	}

	fmt.Printf("NUMA: Discovering NUMA topology\n")

	// Check if NUMA is available
	if !nm.checkNUMAAvailable() {
		return fmt.Errorf("NUMA not available on this system")
	}

	// Discover NUMA topology
	if err := nm.discoverTopology(); err != nil {
		return fmt.Errorf("failed to discover NUMA topology: %w", err)
	}

	// Initialize memory policies
	nm.initializeMemoryPolicies()

	// Initialize NUMA nodes
	if err := nm.initializeNodes(); err != nil {
		return fmt.Errorf("failed to initialize NUMA nodes: %w", err)
	}

	nm.initialized = true

	// Start statistics collection
	go nm.statsCollector()

	fmt.Printf("NUMA: Initialized with %d nodes and %d CPUs\n", 
		nm.topology.NumNodes, nm.topology.NumCPUs)
	return nil
}

// checkNUMAAvailable checks if NUMA is available on the system
func (nm *NUMAManager) checkNUMAAvailable() bool {
	// Check for /sys/devices/system/node directory
	if _, err := os.Stat("/sys/devices/system/node"); os.IsNotExist(err) {
		return false
	}

	// Check for libnuma availability
	if C.numa_available() < 0 {
		return false
	}

	return true
}

// discoverTopology discovers the NUMA topology of the system
func (nm *NUMAManager) discoverTopology() error {
	topology := &NUMATopology{
		NodeCPUMap:  make(map[int][]int),
		CPUNodeMap:  make(map[int]int),
		Distances:   make(map[int]map[int]int),
		MemoryInfo:  make(map[int]*NodeMemoryInfo),
		LastScan:    time.Now(),
	}

	// Get number of NUMA nodes
	topology.NumNodes = int(C.numa_num_configured_nodes())
	topology.NumCPUs = runtime.NumCPU()

	// Discover online nodes
	nodeDir := "/sys/devices/system/node"
	nodeDirs, err := ioutil.ReadDir(nodeDir)
	if err != nil {
		return fmt.Errorf("failed to read node directory: %w", err)
	}

	for _, dir := range nodeDirs {
		if strings.HasPrefix(dir.Name(), "node") {
			nodeIDStr := strings.TrimPrefix(dir.Name(), "node")
			nodeID, err := strconv.Atoi(nodeIDStr)
			if err != nil {
				continue
			}
			
			topology.NodesOnline = append(topology.NodesOnline, nodeID)
			
			// Read CPUs for this node
			cpuListPath := filepath.Join(nodeDir, dir.Name(), "cpulist")
			if cpuListData, err := ioutil.ReadFile(cpuListPath); err == nil {
				cpus := nm.parseCPUList(strings.TrimSpace(string(cpuListData)))
				topology.NodeCPUMap[nodeID] = cpus
				
				for _, cpu := range cpus {
					topology.CPUNodeMap[cpu] = nodeID
					topology.CPUsOnline = append(topology.CPUsOnline, cpu)
				}
			}
			
			// Read memory information
			memInfoPath := filepath.Join(nodeDir, dir.Name(), "meminfo")
			if memInfo, err := nm.parseNodeMemInfo(memInfoPath); err == nil {
				topology.MemoryInfo[nodeID] = memInfo
			}
		}
	}

	// Read NUMA distances
	nm.readNUMADistances(topology)

	nm.topology = topology
	return nil
}

// parseCPUList parses a CPU list string (e.g., "0-3,8-11")
func (nm *NUMAManager) parseCPUList(cpuList string) []int {
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

// parseNodeMemInfo parses node memory information
func (nm *NUMAManager) parseNodeMemInfo(memInfoPath string) (*NodeMemoryInfo, error) {
	data, err := ioutil.ReadFile(memInfoPath)
	if err != nil {
		return nil, err
	}

	memInfo := &NodeMemoryInfo{
		LastUpdate: time.Now(),
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				if val, err := strconv.ParseUint(parts[3], 10, 64); err == nil {
					memInfo.MemTotal = val * 1024 // Convert from kB to bytes
				}
			}
		} else if strings.Contains(line, "MemFree:") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				if val, err := strconv.ParseUint(parts[3], 10, 64); err == nil {
					memInfo.MemFree = val * 1024
				}
			}
		}
		// Parse other memory fields as needed
	}

	return memInfo, nil
}

// readNUMADistances reads NUMA node distances
func (nm *NUMAManager) readNUMADistances(topology *NUMATopology) {
	for _, nodeID := range topology.NodesOnline {
		distanceFile := fmt.Sprintf("/sys/devices/system/node/node%d/distance", nodeID)
		if distanceData, err := ioutil.ReadFile(distanceFile); err == nil {
			distances := strings.Fields(strings.TrimSpace(string(distanceData)))
			topology.Distances[nodeID] = make(map[int]int)
			
			for i, distStr := range distances {
				if dist, err := strconv.Atoi(distStr); err == nil {
					if i < len(topology.NodesOnline) {
						targetNode := topology.NodesOnline[i]
						topology.Distances[nodeID][targetNode] = dist
					}
				}
			}
		}
	}
}

// initializeMemoryPolicies initializes predefined memory policies
func (nm *NUMAManager) initializeMemoryPolicies() {
	// Define standard NUMA memory policies
	policies := []*MemoryPolicy{
		{
			Name:        "default",
			Policy:      0, // MPOL_DEFAULT
			NodeMask:    0,
			Flags:       0,
			Description: "System default policy",
		},
		{
			Name:        "local",
			Policy:      3, // MPOL_PREFERRED
			NodeMask:    0, // Will be set per-thread
			Flags:       0,
			Description: "Prefer local node",
		},
		{
			Name:        "interleave",
			Policy:      1, // MPOL_INTERLEAVE
			NodeMask:    ^uint64(0), // All nodes
			Flags:       0,
			Description: "Interleave across all nodes",
		},
		{
			Name:        "bind",
			Policy:      2, // MPOL_BIND
			NodeMask:    0, // Will be set as needed
			Flags:       0,
			Description: "Bind to specific nodes",
		},
	}

	for _, policy := range policies {
		nm.policies[policy.Name] = policy
	}

	fmt.Printf("NUMA: Initialized %d memory policies\n", len(nm.policies))
}

// initializeNodes initializes NUMA node structures
func (nm *NUMAManager) initializeNodes() error {
	for _, nodeID := range nm.topology.NodesOnline {
		node := &NUMANode{
			ID:          nodeID,
			CPUs:        nm.topology.NodeCPUMap[nodeID],
			Allocations: make([]*MemoryAllocation, 0),
			LastUpdate:  time.Now(),
		}

		// Set memory information if available
		if memInfo, exists := nm.topology.MemoryInfo[nodeID]; exists {
			node.MemoryTotal = memInfo.MemTotal
			node.MemoryFree = memInfo.MemFree
			node.MemoryUsed = node.MemoryTotal - node.MemoryFree
		}

		// Read hugepages information
		nm.readHugePagesInfo(node)

		nm.nodes[nodeID] = node
		fmt.Printf("NUMA: Initialized node %d with %d CPUs, %d MB memory\n", 
			nodeID, len(node.CPUs), node.MemoryTotal/(1024*1024))
	}

	return nil
}

// readHugePagesInfo reads hugepages information for a node
func (nm *NUMAManager) readHugePagesInfo(node *NUMANode) {
	hugePagesPath := fmt.Sprintf("/sys/devices/system/node/node%d/hugepages", node.ID)
	
	if hugePagesDir, err := ioutil.ReadDir(hugePagesPath); err == nil {
		for _, dir := range hugePagesDir {
			if strings.HasPrefix(dir.Name(), "hugepages-") {
				// Read hugepages total
				totalPath := filepath.Join(hugePagesPath, dir.Name(), "nr_hugepages")
				if totalData, err := ioutil.ReadFile(totalPath); err == nil {
					if total, err := strconv.Atoi(strings.TrimSpace(string(totalData))); err == nil {
						node.HugePagesTotal = total
					}
				}
				
				// Read hugepages free
				freePath := filepath.Join(hugePagesPath, dir.Name(), "free_hugepages")
				if freeData, err := ioutil.ReadFile(freePath); err == nil {
					if free, err := strconv.Atoi(strings.TrimSpace(string(freeData))); err == nil {
						node.HugePagesFree = free
					}
				}
				
				// Extract hugepage size from directory name
				sizeStr := strings.TrimPrefix(dir.Name(), "hugepages-")
				sizeStr = strings.TrimSuffix(sizeStr, "kB")
				if size, err := strconv.Atoi(sizeStr); err == nil {
					node.HugePagesSize = size
				}
				
				break // Use first (usually only) hugepage size
			}
		}
	}
}

// AllocateMemory allocates memory with NUMA awareness
func (nm *NUMAManager) AllocateMemory(size uint64, policy string, nodeHint int) (unsafe.Pointer, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.initialized {
		return nil, fmt.Errorf("NUMA not initialized")
	}

	var targetNode int = -1
	
	// Determine target node based on policy and hint
	switch policy {
	case "local":
		targetNode = nm.getCurrentCPUNode()
	case "specific":
		if nodeHint >= 0 && nodeHint < nm.topology.NumNodes {
			targetNode = nodeHint
		}
	case "interleave":
		// Let the system handle interleaving
		targetNode = -1
	default:
		targetNode = nm.selectOptimalNode(size)
	}

	var ptr unsafe.Pointer
	var err error

	if targetNode >= 0 {
		// Allocate on specific node
		ptr = unsafe.Pointer(C.numa_alloc_onnode_wrapper(C.size_t(size), C.int(targetNode)))
		if ptr == nil {
			err = fmt.Errorf("failed to allocate memory on node %d", targetNode)
		}
	} else {
		// Use system default allocation
		ptr = unsafe.Pointer(C.malloc(C.size_t(size)))
		if ptr == nil {
			err = fmt.Errorf("failed to allocate memory")
		}
		targetNode = nm.getMemoryNode(uintptr(ptr))
	}

	if err != nil {
		return nil, err
	}

	// Track allocation
	allocation := &MemoryAllocation{
		Address:   uintptr(ptr),
		Size:      size,
		Node:      targetNode,
		Policy:    policy,
		Timestamp: time.Now(),
		ProcessID: os.Getpid(),
		ThreadID:  nm.getCurrentThreadID(),
		Purpose:   "packet_buffer",
	}

	nm.allocations[uintptr(ptr)] = allocation
	if targetNode >= 0 {
		nm.nodes[targetNode].Allocations = append(nm.nodes[targetNode].Allocations, allocation)
		nm.nodes[targetNode].MemoryUsed += size
	}

	nm.stats.TotalAllocations++
	
	fmt.Printf("NUMA: Allocated %d bytes on node %d (policy: %s)\n", size, targetNode, policy)
	return ptr, nil
}

// FreeMemory frees NUMA-aware allocated memory
func (nm *NUMAManager) FreeMemory(ptr unsafe.Pointer) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.initialized {
		return fmt.Errorf("NUMA not initialized")
	}

	addr := uintptr(ptr)
	allocation, exists := nm.allocations[addr]
	if !exists {
		return fmt.Errorf("allocation not tracked")
	}

	// Free memory
	C.numa_free_wrapper(ptr, C.size_t(allocation.Size))

	// Update node statistics
	if node, exists := nm.nodes[allocation.Node]; exists {
		node.MemoryUsed -= allocation.Size
		
		// Remove allocation from node
		for i, alloc := range node.Allocations {
			if alloc.Address == addr {
				node.Allocations = append(node.Allocations[:i], node.Allocations[i+1:]...)
				break
			}
		}
	}

	// Remove from tracking
	delete(nm.allocations, addr)
	nm.stats.TotalDeallocations++

	fmt.Printf("NUMA: Freed %d bytes from node %d\n", allocation.Size, allocation.Node)
	return nil
}

// getCurrentCPUNode gets the NUMA node of the current CPU
func (nm *NUMAManager) getCurrentCPUNode() int {
	cpu := nm.getCurrentCPU()
	if node, exists := nm.topology.CPUNodeMap[cpu]; exists {
		return node
	}
	return 0 // Default to node 0
}

// getCurrentCPU gets the current CPU number
func (nm *NUMAManager) getCurrentCPU() int {
	// This is a simplified approach - in practice, you'd use sched_getcpu()
	return 0
}

// getCurrentThreadID gets the current thread ID
func (nm *NUMAManager) getCurrentThreadID() int {
	return int(syscall.Gettid())
}

// getMemoryNode determines which NUMA node contains a memory address
func (nm *NUMAManager) getMemoryNode(addr uintptr) int {
	// This would use get_mempolicy() to determine the actual node
	// For now, return node 0 as default
	return 0
}

// selectOptimalNode selects the optimal NUMA node for allocation
func (nm *NUMAManager) selectOptimalNode(size uint64) int {
	bestNode := 0
	bestScore := float64(0)

	for nodeID, node := range nm.nodes {
		// Score based on free memory and current utilization
		freeRatio := float64(node.MemoryFree) / float64(node.MemoryTotal)
		utilizationPenalty := node.Utilization * 0.5
		
		score := freeRatio - utilizationPenalty
		
		if score > bestScore {
			bestScore = score
			bestNode = nodeID
		}
	}

	return bestNode
}

// SetThreadAffinity sets CPU affinity for the current thread to a NUMA node
func (nm *NUMAManager) SetThreadAffinity(nodeID int) error {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if !nm.initialized {
		return fmt.Errorf("NUMA not initialized")
	}

	node, exists := nm.nodes[nodeID]
	if !exists {
		return fmt.Errorf("NUMA node %d not found", nodeID)
	}

	// Set CPU affinity to CPUs in the specified NUMA node
	var cpuSet syscall.CPUSet
	cpuSet.Zero()
	
	for _, cpu := range node.CPUs {
		cpuSet.Set(cpu)
	}

	err := syscall.SchedSetaffinity(0, &cpuSet)
	if err != nil {
		return fmt.Errorf("failed to set CPU affinity: %w", err)
	}

	fmt.Printf("NUMA: Set thread affinity to node %d (CPUs: %v)\n", nodeID, node.CPUs)
	return nil
}

// statsCollector collects NUMA statistics
func (nm *NUMAManager) statsCollector() {
	ticker := time.NewTicker(nm.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nm.collectStatistics()
		}
	}
}

// collectStatistics collects and updates NUMA statistics
func (nm *NUMAManager) collectStatistics() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Update node memory statistics
	for nodeID, node := range nm.nodes {
		if memInfo, err := nm.parseNodeMemInfo(fmt.Sprintf("/sys/devices/system/node/node%d/meminfo", nodeID)); err == nil {
			node.MemoryFree = memInfo.MemFree
			node.MemoryUsed = memInfo.MemTotal - memInfo.MemFree
			node.Utilization = float64(node.MemoryUsed) / float64(memInfo.MemTotal)
			node.LastUpdate = time.Now()
		}

		// Update hugepages information
		nm.readHugePagesInfo(node)
	}

	// Calculate NUMA hit ratio and other statistics
	nm.calculateAdvancedStatistics()

	nm.stats.LastUpdate = time.Now()
}

// calculateAdvancedStatistics calculates advanced NUMA statistics
func (nm *NUMAManager) calculateAdvancedStatistics() {
	// Read NUMA statistics from /proc/vmstat or /sys/devices/system/node/*/numastat
	
	totalAccesses := nm.stats.LocalNodeAccesses + nm.stats.CrossNodeAccesses
	if totalAccesses > 0 {
		nm.stats.NumaHitRatio = float64(nm.stats.LocalNodeAccesses) / float64(totalAccesses)
	}

	// This is simplified - in practice, you'd read actual NUMA counters
	// from the kernel
}

// UpdateServices updates service placement for NUMA optimization
func (nm *NUMAManager) UpdateServices(services []manager.Service) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	fmt.Printf("NUMA: Optimizing service placement for %d services\n", len(services))

	// In a full implementation, this would analyze service requirements
	// and distribute them optimally across NUMA nodes
	
	return nil
}

// GetOptimalNode returns the optimal NUMA node for a given workload
func (nm *NUMAManager) GetOptimalNode(workloadType string, requiredMemory uint64) (int, error) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if !nm.initialized {
		return -1, fmt.Errorf("NUMA not initialized")
	}

	return nm.selectOptimalNode(requiredMemory), nil
}

// Stop cleans up NUMA resources
func (nm *NUMAManager) Stop() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.initialized {
		return nil
	}

	fmt.Printf("NUMA: Cleaning up allocations\n")

	// Free all tracked allocations
	for addr, allocation := range nm.allocations {
		ptr := unsafe.Pointer(addr)
		C.numa_free_wrapper(ptr, C.size_t(allocation.Size))
		delete(nm.allocations, addr)
	}

	nm.initialized = false
	fmt.Printf("NUMA: Cleanup complete\n")
	return nil
}

// GetStats returns current NUMA statistics
func (nm *NUMAManager) GetStats() *NUMAStats {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	stats := *nm.stats
	return &stats
}

// IsEnabled returns whether NUMA is enabled and initialized
func (nm *NUMAManager) IsEnabled() bool {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.enabled && nm.initialized
}

// GetTopology returns the NUMA topology information
func (nm *NUMAManager) GetTopology() *NUMATopology {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if nm.topology == nil {
		return nil
	}

	topology := *nm.topology
	return &topology
}

// GetNodes returns information about all NUMA nodes
func (nm *NUMAManager) GetNodes() map[int]*NUMANode {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	nodes := make(map[int]*NUMANode)
	for id, node := range nm.nodes {
		nodeCopy := *node
		nodes[id] = &nodeCopy
	}
	return nodes
}

// GetNodeDistance returns the distance between two NUMA nodes
func (nm *NUMAManager) GetNodeDistance(node1, node2 int) (int, error) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if nm.topology == nil {
		return -1, fmt.Errorf("topology not available")
	}

	if distances, exists := nm.topology.Distances[node1]; exists {
		if distance, exists := distances[node2]; exists {
			return distance, nil
		}
	}

	return -1, fmt.Errorf("distance information not available")
}