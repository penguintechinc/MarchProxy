// +build xdp

package xdp

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/penguintech/marchproxy/internal/manager"
)

// #cgo CFLAGS: -I/usr/include/bpf -I.
// #cgo LDFLAGS: -lbpf -lelf -lz
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <errno.h>
// #include <unistd.h>
// #include <sys/socket.h>
// #include <linux/if.h>
// #include <linux/if_link.h>
// #include <linux/if_xdp.h>
// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <bpf/xsk.h>
//
// struct bpf_object* load_xdp_program(const char *filename);
// int attach_xdp_program(const char *ifname, int prog_fd, __u32 flags);
// int detach_xdp_program(const char *ifname);
// int update_service_rule_xdp(int map_fd, __u32 key, void *rule);
// int get_xdp_stats(int map_fd, void *stats);
// void close_bpf_object(struct bpf_object *obj);
// int get_map_fd_by_name(struct bpf_object *obj, const char *name);
import "C"

// XDPManager handles XDP program lifecycle and management
type XDPManager struct {
	enabled       bool
	programLoaded bool
	attachedIfs   map[string]*XDPInterface
	program       *C.struct_bpf_object
	stats         *XDPStats
	config        *XDPConfig
	serviceMaps   map[string]int // map file descriptors
	mu            sync.RWMutex
}

// XDPInterface represents an interface with XDP attached
type XDPInterface struct {
	Name          string
	Index         int
	ProgramFD     int
	AttachFlags   uint32
	RxPackets     uint64
	TxPackets     uint64
	DroppedPkts   uint64
	RedirectPkts  uint64
	LastUpdate    time.Time
}

// XDPStats holds XDP performance statistics
type XDPStats struct {
	TotalPackets      uint64
	PassedPackets     uint64
	DroppedPackets    uint64
	RedirectedPackets uint64
	TCPPackets        uint64
	UDPPackets        uint64
	OtherPackets      uint64
	MalformedPackets  uint64
	PacketsPerSecond  uint64
	LastUpdate        time.Time
}

// XDPConfig holds XDP configuration parameters
type XDPConfig struct {
	ProgramPath     string
	Interfaces      []string
	AttachMode      string // "generic", "native", "offload"
	ForceReplace    bool
	EnableStats     bool
	StatsInterval   time.Duration
	BurstSize       uint32
	BatchTimeout    time.Duration
}

// ServiceRule represents a service filtering rule for XDP
type ServiceRule struct {
	ServiceID   uint32
	IPAddr      uint32
	Port        uint16
	Protocol    uint8
	Action      uint8  // 0=drop, 1=pass, 2=redirect
	RedirectIP  uint32
	RedirectPort uint16
	AuthRequired uint8
	Reserved    uint8
}

// NewXDPManager creates a new XDP manager
func NewXDPManager(enabled bool, config *XDPConfig) *XDPManager {
	if config == nil {
		config = &XDPConfig{
			ProgramPath:   "xdp_filter.o",
			Interfaces:    []string{"eth0"},
			AttachMode:    "generic",
			ForceReplace:  true,
			EnableStats:   true,
			StatsInterval: time.Second,
			BurstSize:     64,
			BatchTimeout:  time.Millisecond,
		}
	}

	return &XDPManager{
		enabled:     enabled,
		attachedIfs: make(map[string]*XDPInterface),
		config:      config,
		serviceMaps: make(map[string]int),
		stats: &XDPStats{
			LastUpdate: time.Now(),
		},
	}
}

// Initialize loads the XDP program
func (xm *XDPManager) Initialize() error {
	xm.mu.Lock()
	defer xm.mu.Unlock()

	if !xm.enabled {
		return fmt.Errorf("XDP is disabled")
	}

	if xm.programLoaded {
		return fmt.Errorf("XDP program already loaded")
	}

	// Check if program file exists
	if _, err := os.Stat(xm.config.ProgramPath); os.IsNotExist(err) {
		return fmt.Errorf("XDP program file not found: %s", xm.config.ProgramPath)
	}

	fmt.Printf("XDP: Loading program from %s\n", xm.config.ProgramPath)

	// Load XDP program
	programPath := C.CString(xm.config.ProgramPath)
	defer C.free(unsafe.Pointer(programPath))

	xm.program = C.load_xdp_program(programPath)
	if xm.program == nil {
		return fmt.Errorf("failed to load XDP program")
	}

	// Get map file descriptors
	serviceMapName := C.CString("service_rules")
	defer C.free(unsafe.Pointer(serviceMapName))
	
	statsMapName := C.CString("stats_map")
	defer C.free(unsafe.Pointer(statsMapName))

	xm.serviceMaps["service_rules"] = int(C.get_map_fd_by_name(xm.program, serviceMapName))
	xm.serviceMaps["stats_map"] = int(C.get_map_fd_by_name(xm.program, statsMapName))

	if xm.serviceMaps["service_rules"] < 0 {
		return fmt.Errorf("failed to get service_rules map file descriptor")
	}

	xm.programLoaded = true
	fmt.Printf("XDP: Program loaded successfully\n")

	// Start statistics collection if enabled
	if xm.config.EnableStats {
		go xm.statsCollector()
	}

	return nil
}

// AttachToInterface attaches XDP program to a network interface
func (xm *XDPManager) AttachToInterface(interfaceName string) error {
	xm.mu.Lock()
	defer xm.mu.Unlock()

	if !xm.programLoaded {
		return fmt.Errorf("XDP program not loaded")
	}

	if _, exists := xm.attachedIfs[interfaceName]; exists {
		return fmt.Errorf("XDP already attached to interface %s", interfaceName)
	}

	// Get interface index
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", interfaceName, err)
	}

	fmt.Printf("XDP: Attaching to interface %s (index %d)\n", interfaceName, iface.Index)

	// Convert attach mode to flags
	var flags uint32
	switch xm.config.AttachMode {
	case "generic":
		flags = C.XDP_FLAGS_SKB_MODE
	case "native":
		flags = C.XDP_FLAGS_DRV_MODE
	case "offload":
		flags = C.XDP_FLAGS_HW_MODE
	default:
		flags = C.XDP_FLAGS_SKB_MODE
	}

	if xm.config.ForceReplace {
		flags |= C.XDP_FLAGS_REPLACE
	}

	// Attach XDP program
	ifname := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(ifname))

	ret := C.attach_xdp_program(ifname, C.int(-1), C.uint(flags)) // -1 means use program from object
	if ret != 0 {
		return fmt.Errorf("failed to attach XDP program to interface %s: %d", interfaceName, ret)
	}

	// Create interface tracking structure
	xdpIf := &XDPInterface{
		Name:        interfaceName,
		Index:       iface.Index,
		AttachFlags: flags,
		LastUpdate:  time.Now(),
	}

	xm.attachedIfs[interfaceName] = xdpIf
	fmt.Printf("XDP: Successfully attached to interface %s\n", interfaceName)
	return nil
}

// DetachFromInterface detaches XDP program from a network interface
func (xm *XDPManager) DetachFromInterface(interfaceName string) error {
	xm.mu.Lock()
	defer xm.mu.Unlock()

	if _, exists := xm.attachedIfs[interfaceName]; !exists {
		return fmt.Errorf("XDP not attached to interface %s", interfaceName)
	}

	fmt.Printf("XDP: Detaching from interface %s\n", interfaceName)

	// Detach XDP program
	ifname := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(ifname))

	ret := C.detach_xdp_program(ifname)
	if ret != 0 {
		fmt.Printf("XDP: Warning - failed to detach from interface %s: %d\n", interfaceName, ret)
	}

	delete(xm.attachedIfs, interfaceName)
	fmt.Printf("XDP: Detached from interface %s\n", interfaceName)
	return nil
}

// UpdateServices synchronizes services with XDP maps
func (xm *XDPManager) UpdateServices(services []manager.Service) error {
	xm.mu.RLock()
	defer xm.mu.RUnlock()

	if !xm.programLoaded {
		return fmt.Errorf("XDP program not loaded")
	}

	serviceMapFD, exists := xm.serviceMaps["service_rules"]
	if !exists || serviceMapFD < 0 {
		return fmt.Errorf("service rules map not available")
	}

	fmt.Printf("XDP: Updating %d services in maps\n", len(services))

	// Update service rules in XDP map
	for _, service := range services {
		rule := &ServiceRule{
			ServiceID: uint32(service.ID),
			IPAddr:    ipToUint32(resolveServiceIP(service.IPFQDN)),
			Port:      80, // Default port - would be parsed from service config
			Protocol:  6,  // TCP
			Action:    1,  // Pass
		}

		// Set auth configuration
		if service.AuthType != "" {
			rule.AuthRequired = 1
			rule.Action = 2 // Redirect to userspace for authentication
		}

		// Create map key from IP and protocol
		key := rule.IPAddr&0xFFFFFF00 | uint32(rule.Protocol)

		// Update XDP map
		ret := C.update_service_rule_xdp(
			C.int(serviceMapFD),
			C.uint(key),
			unsafe.Pointer(rule),
		)
		if ret != 0 {
			fmt.Printf("XDP: Warning - failed to update service rule for %s: %d\n", service.IPFQDN, ret)
		}
	}

	fmt.Printf("XDP: Services updated in XDP maps\n")
	return nil
}

// statsCollector collects XDP statistics
func (xm *XDPManager) statsCollector() {
	ticker := time.NewTicker(xm.config.StatsInterval)
	defer ticker.Stop()

	var lastTotal uint64
	lastUpdate := time.Now()

	for {
		select {
		case <-ticker.C:
			xm.mu.RLock()
			
			// Get statistics from XDP map
			if statsMapFD, exists := xm.serviceMaps["stats_map"]; exists && statsMapFD >= 0 {
				var stats XDPStats
				ret := C.get_xdp_stats(C.int(statsMapFD), unsafe.Pointer(&stats))
				if ret == 0 {
					// Calculate packets per second
					now := time.Now()
					duration := now.Sub(lastUpdate).Seconds()
					if duration > 0 && stats.TotalPackets > lastTotal {
						xm.stats.PacketsPerSecond = uint64(float64(stats.TotalPackets-lastTotal) / duration)
					}

					// Update statistics
					*xm.stats = stats
					xm.stats.LastUpdate = now
					
					lastTotal = stats.TotalPackets
					lastUpdate = now
				}
			}
			
			xm.mu.RUnlock()
		}
	}
}

// Stop detaches from all interfaces and unloads the program
func (xm *XDPManager) Stop() error {
	xm.mu.Lock()
	defer xm.mu.Unlock()

	if !xm.programLoaded {
		return nil
	}

	fmt.Printf("XDP: Stopping and cleaning up\n")

	// Detach from all interfaces
	for ifname := range xm.attachedIfs {
		ifnameC := C.CString(ifname)
		C.detach_xdp_program(ifnameC)
		C.free(unsafe.Pointer(ifnameC))
		fmt.Printf("XDP: Detached from interface %s\n", ifname)
	}
	xm.attachedIfs = make(map[string]*XDPInterface)

	// Close BPF object
	if xm.program != nil {
		C.close_bpf_object(xm.program)
		xm.program = nil
	}

	xm.programLoaded = false
	fmt.Printf("XDP: Cleanup complete\n")
	return nil
}

// GetStats returns current XDP statistics
func (xm *XDPManager) GetStats() *XDPStats {
	xm.mu.RLock()
	defer xm.mu.RUnlock()

	stats := *xm.stats
	return &stats
}

// IsEnabled returns whether XDP is enabled
func (xm *XDPManager) IsEnabled() bool {
	xm.mu.RLock()
	defer xm.mu.RUnlock()
	return xm.enabled && xm.programLoaded
}

// GetAttachedInterfaces returns list of interfaces with XDP attached
func (xm *XDPManager) GetAttachedInterfaces() []string {
	xm.mu.RLock()
	defer xm.mu.RUnlock()

	interfaces := make([]string, 0, len(xm.attachedIfs))
	for ifname := range xm.attachedIfs {
		interfaces = append(interfaces, ifname)
	}
	return interfaces
}

// GetInterfaceStats returns statistics for a specific interface
func (xm *XDPManager) GetInterfaceStats(interfaceName string) (*XDPInterface, error) {
	xm.mu.RLock()
	defer xm.mu.RUnlock()

	iface, exists := xm.attachedIfs[interfaceName]
	if !exists {
		return nil, fmt.Errorf("XDP not attached to interface %s", interfaceName)
	}

	// Create a copy
	ifaceCopy := *iface
	return &ifaceCopy, nil
}

// Helper functions
func ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func resolveServiceIP(ipfqdn string) net.IP {
	// First try to parse as IP address
	if ip := net.ParseIP(ipfqdn); ip != nil {
		return ip.To4()
	}

	// Try to resolve as hostname
	ips, err := net.LookupIP(ipfqdn)
	if err != nil {
		fmt.Printf("XDP: Warning - failed to resolve %s: %v\n", ipfqdn, err)
		return net.IPv4(127, 0, 0, 1)
	}

	// Return first IPv4 address found
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}

	return net.IPv4(127, 0, 0, 1)
}