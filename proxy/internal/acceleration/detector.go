package acceleration

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// AccelerationCapability represents hardware acceleration features available
type AccelerationCapability struct {
	Technology    string
	Available     bool
	Reason        string
	Performance   string // Expected performance tier
	Prerequisites []string
}

// HardwareCapabilities represents overall hardware capabilities
type HardwareCapabilities struct {
	DPDK   AccelerationCapability
	XDP    AccelerationCapability
	AFXDP  AccelerationCapability
	SRIOV  AccelerationCapability
	NUMA   AccelerationCapability
}

// NetworkInterface represents a network interface and its capabilities
type NetworkInterface struct {
	Name         string
	Driver       string
	PCIAddress   string
	NumaNode     int
	MaxQueues    int
	Capabilities map[string]bool
	Features     []string
}

// HardwareDetector detects available acceleration technologies
type HardwareDetector struct {
	interfaces map[string]*NetworkInterface
	capabilities map[string]*AccelerationCapability
	cpuInfo    *CPUInfo
}

// CPUInfo contains CPU information relevant to acceleration
type CPUInfo struct {
	NumCores     int
	NumSockets   int
	NumaNodes    int
	HugePages    bool
	HugePagesSize int
	Architecture string
	HasAVX      bool
	HasAVX2     bool
	HasAVX512   bool
}

// NewHardwareDetector creates a new hardware capability detector
func NewHardwareDetector() *HardwareDetector {
	return &HardwareDetector{
		interfaces:   make(map[string]*NetworkInterface),
		capabilities: make(map[string]*AccelerationCapability),
	}
}

// Detect performs comprehensive hardware capability detection
func (hd *HardwareDetector) Detect() error {
	log.Printf("Starting hardware acceleration capability detection...")

	// Detect CPU capabilities
	if err := hd.detectCPUCapabilities(); err != nil {
		log.Printf("CPU detection error: %v", err)
	}

	// Detect network interfaces
	if err := hd.detectNetworkInterfaces(); err != nil {
		log.Printf("Network interface detection error: %v", err)
	}

	// Evaluate acceleration technologies
	hd.evaluateAccelerationTechnologies()

	// Print detection results
	hd.printResults()

	return nil
}

// detectCPUCapabilities detects CPU features relevant to acceleration
func (hd *HardwareDetector) detectCPUCapabilities() error {
	hd.cpuInfo = &CPUInfo{
		NumCores:     runtime.NumCPU(),
		Architecture: runtime.GOARCH,
	}

	// Check for NUMA nodes
	numaPath := "/sys/devices/system/node"
	if entries, err := ioutil.ReadDir(numaPath); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "node") {
				hd.cpuInfo.NumaNodes++
			}
		}
	}

	// Check for huge pages support
	if data, err := ioutil.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "HugePages_Total:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 && parts[1] != "0" {
					hd.cpuInfo.HugePages = true
				}
			}
			if strings.Contains(line, "Hugepagesize:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					// Parse size (usually in kB)
					fmt.Sscanf(parts[1], "%d", &hd.cpuInfo.HugePagesSize)
				}
			}
		}
	}

	// Check CPU features from /proc/cpuinfo
	if data, err := ioutil.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
				flags := strings.ToLower(line)
				hd.cpuInfo.HasAVX = strings.Contains(flags, "avx")
				hd.cpuInfo.HasAVX2 = strings.Contains(flags, "avx2")
				hd.cpuInfo.HasAVX512 = strings.Contains(flags, "avx512")
				break
			}
		}
	}

	return nil
}

// detectNetworkInterfaces detects network interfaces and their capabilities
func (hd *HardwareDetector) detectNetworkInterfaces() error {
	sysNetPath := "/sys/class/net"
	entries, err := ioutil.ReadDir(sysNetPath)
	if err != nil {
		return fmt.Errorf("failed to read network interfaces: %w", err)
	}

	for _, entry := range entries {
		ifName := entry.Name()
		if ifName == "lo" {
			continue // Skip loopback
		}

		iface := &NetworkInterface{
			Name:         ifName,
			Capabilities: make(map[string]bool),
			Features:     []string{},
		}

		// Get driver information
		driverPath := filepath.Join(sysNetPath, ifName, "device/driver")
		if linkDest, err := os.Readlink(driverPath); err == nil {
			iface.Driver = filepath.Base(linkDest)
		}

		// Get PCI address
		devicePath := filepath.Join(sysNetPath, ifName, "device")
		if linkDest, err := os.Readlink(devicePath); err == nil {
			iface.PCIAddress = filepath.Base(linkDest)
		}

		// Get NUMA node
		numaPath := filepath.Join(sysNetPath, ifName, "device/numa_node")
		if data, err := ioutil.ReadFile(numaPath); err == nil {
			fmt.Sscanf(string(data), "%d", &iface.NumaNode)
		}

		// Get number of queues
		queuesPath := filepath.Join(sysNetPath, ifName, "queues")
		if entries, err := ioutil.ReadDir(queuesPath); err == nil {
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "tx-") {
					iface.MaxQueues++
				}
			}
		}

		// Check interface features
		hd.detectInterfaceFeatures(iface)

		hd.interfaces[ifName] = iface
	}

	return nil
}

// detectInterfaceFeatures detects specific NIC features
func (hd *HardwareDetector) detectInterfaceFeatures(iface *NetworkInterface) {
	// Check for XDP support
	iface.Capabilities["xdp"] = hd.checkXDPSupport(iface)

	// Check for AF_XDP support
	iface.Capabilities["af_xdp"] = hd.checkAFXDPSupport(iface)

	// Check for DPDK support based on driver
	iface.Capabilities["dpdk"] = hd.checkDPDKSupport(iface)

	// Check for SR-IOV support
	iface.Capabilities["sriov"] = hd.checkSRIOVSupport(iface)

	// Check for offload capabilities
	hd.checkOffloadCapabilities(iface)
}

// checkXDPSupport checks if interface supports XDP
func (hd *HardwareDetector) checkXDPSupport(iface *NetworkInterface) bool {
	// XDP is supported on most modern NICs with appropriate drivers
	supportedDrivers := []string{
		"i40e", "ixgbe", "mlx4_en", "mlx5_core",
		"nfp", "qede", "bnxt_en", "thunderx_nicvf",
		"virtio_net", "tun", "veth",
	}

	for _, driver := range supportedDrivers {
		if strings.Contains(iface.Driver, driver) {
			iface.Features = append(iface.Features, "XDP native support")
			return true
		}
	}

	// Generic XDP is available for most interfaces
	iface.Features = append(iface.Features, "XDP generic support")
	return true
}

// checkAFXDPSupport checks if interface supports AF_XDP
func (hd *HardwareDetector) checkAFXDPSupport(iface *NetworkInterface) bool {
	// AF_XDP requires kernel 4.18+ and driver support
	if !iface.Capabilities["xdp"] {
		return false
	}

	// Check kernel version
	if !hd.checkKernelVersion(4, 18) {
		return false
	}

	iface.Features = append(iface.Features, "AF_XDP zero-copy capable")
	return true
}

// checkDPDKSupport checks if interface supports DPDK
func (hd *HardwareDetector) checkDPDKSupport(iface *NetworkInterface) bool {
	// DPDK Poll Mode Drivers
	dpdkDrivers := []string{
		"igb_uio", "vfio-pci", "uio_pci_generic",
		"i40e", "ixgbe", "e1000", "e1000e",
		"mlx4_core", "mlx5_core", "bnxt_en",
		"virtio-pci", "vmxnet3",
	}

	for _, driver := range dpdkDrivers {
		if strings.Contains(iface.Driver, driver) {
			iface.Features = append(iface.Features, "DPDK PMD available")
			return true
		}
	}

	return false
}

// checkSRIOVSupport checks if interface supports SR-IOV
func (hd *HardwareDetector) checkSRIOVSupport(iface *NetworkInterface) bool {
	// Check for SR-IOV capability
	sriovPath := fmt.Sprintf("/sys/class/net/%s/device/sriov_totalvfs", iface.Name)
	if data, err := ioutil.ReadFile(sriovPath); err == nil {
		var totalVFs int
		fmt.Sscanf(string(data), "%d", &totalVFs)
		if totalVFs > 0 {
			iface.Features = append(iface.Features, fmt.Sprintf("SR-IOV capable (%d VFs)", totalVFs))
			return true
		}
	}

	return false
}

// checkOffloadCapabilities checks various offload features
func (hd *HardwareDetector) checkOffloadCapabilities(iface *NetworkInterface) {
	features := []string{
		"rx-checksumming",
		"tx-checksumming",
		"scatter-gather",
		"tcp-segmentation-offload",
		"generic-segmentation-offload",
		"generic-receive-offload",
		"large-receive-offload",
		"rx-vlan-offload",
		"tx-vlan-offload",
	}

	featuresPath := fmt.Sprintf("/sys/class/net/%s/features", iface.Name)
	if _, err := os.Stat(featuresPath); err == nil {
		for _, feature := range features {
			featurePath := filepath.Join(featuresPath, feature)
			if data, err := ioutil.ReadFile(featurePath); err == nil {
				if strings.TrimSpace(string(data)) == "on" {
					iface.Capabilities[feature] = true
				}
			}
		}
	}
}

// checkKernelVersion checks if kernel version meets requirements
func (hd *HardwareDetector) checkKernelVersion(majorReq, minorReq int) bool {
	if data, err := ioutil.ReadFile("/proc/version"); err == nil {
		var major, minor int
		if _, err := fmt.Sscanf(string(data), "Linux version %d.%d", &major, &minor); err == nil {
			if major > majorReq || (major == majorReq && minor >= minorReq) {
				return true
			}
		}
	}
	return false
}

// evaluateAccelerationTechnologies determines which acceleration technologies can be used
func (hd *HardwareDetector) evaluateAccelerationTechnologies() {
	// XDP evaluation
	xdpCap := &AccelerationCapability{
		Technology:  "XDP (eXpress Data Path)",
		Performance: "10-100 Gbps",
		Prerequisites: []string{
			"Linux kernel 4.8+",
			"XDP-capable network driver",
		},
	}

	hasXDP := false
	for _, iface := range hd.interfaces {
		if iface.Capabilities["xdp"] {
			hasXDP = true
			break
		}
	}

	if hasXDP {
		xdpCap.Available = true
		xdpCap.Reason = "XDP-capable interfaces detected"
	} else {
		xdpCap.Reason = "No XDP-capable interfaces found"
	}
	hd.capabilities["xdp"] = xdpCap

	// AF_XDP evaluation
	afxdpCap := &AccelerationCapability{
		Technology:  "AF_XDP (Address Family XDP)",
		Performance: "20-40 Gbps with zero-copy",
		Prerequisites: []string{
			"Linux kernel 4.18+",
			"AF_XDP driver support",
			"libbpf library",
		},
	}

	hasAFXDP := false
	for _, iface := range hd.interfaces {
		if iface.Capabilities["af_xdp"] {
			hasAFXDP = true
			break
		}
	}

	if hasAFXDP {
		afxdpCap.Available = true
		afxdpCap.Reason = "AF_XDP capable interfaces detected"
	} else {
		afxdpCap.Reason = "No AF_XDP capable interfaces or kernel too old"
	}
	hd.capabilities["af_xdp"] = afxdpCap

	// DPDK evaluation
	dpdkCap := &AccelerationCapability{
		Technology:  "DPDK (Data Plane Development Kit)",
		Performance: "100+ Gbps with dedicated cores",
		Prerequisites: []string{
			"Huge pages configured",
			"IOMMU/VFIO support",
			"Dedicated CPU cores",
			"DPDK-compatible NIC",
		},
	}

	hasDPDK := false
	for _, iface := range hd.interfaces {
		if iface.Capabilities["dpdk"] {
			hasDPDK = true
			break
		}
	}

	if hasDPDK && hd.cpuInfo.HugePages {
		dpdkCap.Available = true
		dpdkCap.Reason = "DPDK requirements met"
	} else {
		reasons := []string{}
		if !hasDPDK {
			reasons = append(reasons, "No DPDK-compatible NICs")
		}
		if !hd.cpuInfo.HugePages {
			reasons = append(reasons, "Huge pages not configured")
		}
		dpdkCap.Reason = strings.Join(reasons, "; ")
	}
	hd.capabilities["dpdk"] = dpdkCap

	// SR-IOV evaluation
	sriovCap := &AccelerationCapability{
		Technology:  "SR-IOV (Single Root I/O Virtualization)",
		Performance: "Near line-rate per VF",
		Prerequisites: []string{
			"SR-IOV capable NIC",
			"IOMMU enabled",
			"VT-d/AMD-Vi support",
		},
	}

	hasSRIOV := false
	for _, iface := range hd.interfaces {
		if iface.Capabilities["sriov"] {
			hasSRIOV = true
			break
		}
	}

	if hasSRIOV {
		sriovCap.Available = true
		sriovCap.Reason = "SR-IOV capable interfaces detected"
	} else {
		sriovCap.Reason = "No SR-IOV capable interfaces found"
	}
	hd.capabilities["sriov"] = sriovCap
}

// printResults prints the detection results
func (hd *HardwareDetector) printResults() {
	fmt.Println("\n=== Hardware Acceleration Capability Report ===\n")

	// CPU Information
	fmt.Println("CPU Information:")
	fmt.Printf("  Cores: %d\n", hd.cpuInfo.NumCores)
	fmt.Printf("  NUMA Nodes: %d\n", hd.cpuInfo.NumaNodes)
	fmt.Printf("  Huge Pages: %v", hd.cpuInfo.HugePages)
	if hd.cpuInfo.HugePages {
		fmt.Printf(" (size: %d kB)", hd.cpuInfo.HugePagesSize)
	}
	fmt.Println()
	fmt.Printf("  CPU Features: ")
	features := []string{}
	if hd.cpuInfo.HasAVX {
		features = append(features, "AVX")
	}
	if hd.cpuInfo.HasAVX2 {
		features = append(features, "AVX2")
	}
	if hd.cpuInfo.HasAVX512 {
		features = append(features, "AVX512")
	}
	fmt.Println(strings.Join(features, ", "))

	// Network Interfaces
	fmt.Println("\nNetwork Interfaces:")
	for name, iface := range hd.interfaces {
		fmt.Printf("\n  %s:\n", name)
		fmt.Printf("    Driver: %s\n", iface.Driver)
		if iface.PCIAddress != "" {
			fmt.Printf("    PCI: %s\n", iface.PCIAddress)
		}
		fmt.Printf("    NUMA Node: %d\n", iface.NumaNode)
		fmt.Printf("    Queues: %d\n", iface.MaxQueues)
		if len(iface.Features) > 0 {
			fmt.Printf("    Features: %s\n", strings.Join(iface.Features, ", "))
		}
	}

	// Acceleration Technologies
	fmt.Println("\nAcceleration Technologies:")
	for _, cap := range hd.capabilities {
		fmt.Printf("\n  %s:\n", cap.Technology)
		fmt.Printf("    Available: %v\n", cap.Available)
		fmt.Printf("    Performance: %s\n", cap.Performance)
		fmt.Printf("    Status: %s\n", cap.Reason)
		if !cap.Available && len(cap.Prerequisites) > 0 {
			fmt.Println("    Prerequisites needed:")
			for _, prereq := range cap.Prerequisites {
				fmt.Printf("      - %s\n", prereq)
			}
		}
	}

	// Recommendations
	fmt.Println("\n=== Recommendations ===")
	hd.printRecommendations()
}

// printRecommendations provides actionable recommendations
func (hd *HardwareDetector) printRecommendations() {
	recommendations := []string{}

	// XDP recommendation
	if cap := hd.capabilities["xdp"]; cap != nil && cap.Available {
		recommendations = append(recommendations,
			"✓ XDP is available and recommended for high-performance packet filtering")
	}

	// AF_XDP recommendation
	if cap := hd.capabilities["af_xdp"]; cap != nil && cap.Available {
		recommendations = append(recommendations,
			"✓ AF_XDP can provide zero-copy packet processing with good performance")
	}

	// DPDK recommendation
	if cap := hd.capabilities["dpdk"]; cap != nil {
		if cap.Available {
			recommendations = append(recommendations,
				"✓ DPDK is available for ultra-high performance (100+ Gbps)")
		} else if hd.cpuInfo.NumCores >= 8 {
			recommendations = append(recommendations,
				"→ Consider enabling huge pages and DPDK for maximum performance")
		}
	}

	// Huge pages recommendation
	if !hd.cpuInfo.HugePages && hd.cpuInfo.NumCores >= 4 {
		recommendations = append(recommendations,
			"→ Enable huge pages for better memory performance:")
		recommendations = append(recommendations,
			"  echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages")
	}

	// Print recommendations
	for _, rec := range recommendations {
		fmt.Println(rec)
	}

	// Best technology selection
	fmt.Println("\nRecommended Technology Stack:")
	if cap := hd.capabilities["xdp"]; cap != nil && cap.Available {
		fmt.Println("  Primary: XDP for fast-path packet filtering")
	}
	if cap := hd.capabilities["af_xdp"]; cap != nil && cap.Available {
		fmt.Println("  Secondary: AF_XDP for zero-copy userspace processing")
	}
	if cap := hd.capabilities["dpdk"]; cap != nil && cap.Available {
		fmt.Println("  Optional: DPDK for ultra-high performance scenarios")
	}
}

// GetBestAcceleration returns the best available acceleration technology
func (hd *HardwareDetector) GetBestAcceleration() string {
	// Priority order: DPDK > AF_XDP > XDP > None
	if cap := hd.capabilities["dpdk"]; cap != nil && cap.Available {
		return "dpdk"
	}
	if cap := hd.capabilities["af_xdp"]; cap != nil && cap.Available {
		return "af_xdp"
	}
	if cap := hd.capabilities["xdp"]; cap != nil && cap.Available {
		return "xdp"
	}
	return "none"
}

// GetCapabilities returns all detected capabilities
func (hd *HardwareDetector) GetCapabilities() map[string]*AccelerationCapability {
	return hd.capabilities
}

// GetInterfaces returns all detected network interfaces
func (hd *HardwareDetector) GetInterfaces() map[string]*NetworkInterface {
	return hd.interfaces
}

// DetectCapabilities detects and returns hardware capabilities
func (hd *HardwareDetector) DetectCapabilities() (*HardwareCapabilities, error) {
	// Detect all capabilities
	if err := hd.Detect(); err != nil {
		return nil, err
	}

	// Convert to HardwareCapabilities struct
	caps := &HardwareCapabilities{}

	if dpdk, exists := hd.capabilities["DPDK"]; exists {
		caps.DPDK = *dpdk
	}
	if xdp, exists := hd.capabilities["XDP"]; exists {
		caps.XDP = *xdp
	}
	if afxdp, exists := hd.capabilities["AF_XDP"]; exists {
		caps.AFXDP = *afxdp
	}
	if sriov, exists := hd.capabilities["SR-IOV"]; exists {
		caps.SRIOV = *sriov
	}
	if numa, exists := hd.capabilities["NUMA"]; exists {
		caps.NUMA = *numa
	}

	return caps, nil
}