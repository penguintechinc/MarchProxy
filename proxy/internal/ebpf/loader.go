package ebpf

import (
	"fmt"
	"os"
	"unsafe"
)

/*
#cgo LDFLAGS: -lbpf -lelf -lz
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <unistd.h>

// C struct definition matching Go ServiceRule
struct service_rule {
    __u32 service_id;
    __be32 ip_addr;  // Network byte order
    __u16 port;
    __u8 protocol;
    __u8 action;     // 0=drop, 1=allow, 2=userspace
};

// Helper function to load eBPF program from file
struct bpf_object *load_bpf_program(const char *filename) {
    struct bpf_object *obj;
    int err;

    obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
        return NULL;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return NULL;
    }

    return obj;
}

// Helper function to find and get program fd
int get_program_fd(struct bpf_object *obj, const char *prog_name) {
    struct bpf_program *prog;
    
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "Failed to find program: %s\n", prog_name);
        return -1;
    }
    
    return bpf_program__fd(prog);
}

// Helper function to find and get map fd
int get_map_fd(struct bpf_object *obj, const char *map_name) {
    struct bpf_map *map;
    
    map = bpf_object__find_map_by_name(obj, map_name);
    if (!map) {
        fprintf(stderr, "Failed to find map: %s\n", map_name);
        return -1;
    }
    
    return bpf_map__fd(map);
}

// Update map element
int update_map_element(int map_fd, void *key, void *value) {
    return bpf_map_update_elem(map_fd, key, value, BPF_ANY);
}

// Lookup map element
int lookup_map_element(int map_fd, void *key, void *value) {
    return bpf_map_lookup_elem(map_fd, key, value);
}

// Delete map element
int delete_map_element(int map_fd, void *key) {
    return bpf_map_delete_elem(map_fd, key);
}
*/
import "C"

// BPFLoader manages eBPF program loading and map operations
type BPFLoader struct {
	programPath string
	obj         *C.struct_bpf_object
	progFD      C.int
	statsFD     C.int
	rulesFD     C.int
}

// NewBPFLoader creates a new eBPF program loader
func NewBPFLoader(programPath string) *BPFLoader {
	return &BPFLoader{
		programPath: programPath,
		obj:         nil,
		progFD:      -1,
		statsFD:     -1,
		rulesFD:     -1,
	}
}

// LoadProgram loads the eBPF program from the specified file
func (l *BPFLoader) LoadProgram() error {
	if l.obj != nil {
		return fmt.Errorf("program already loaded")
	}

	// Check if program file exists
	if _, err := os.Stat(l.programPath); os.IsNotExist(err) {
		return fmt.Errorf("eBPF program file not found: %s", l.programPath)
	}

	// Convert Go string to C string
	cPath := C.CString(l.programPath)
	defer C.free(unsafe.Pointer(cPath))

	// Load BPF object
	l.obj = C.load_bpf_program(cPath)
	if l.obj == nil {
		return fmt.Errorf("failed to load eBPF program from %s", l.programPath)
	}

	// Get program file descriptor
	cProgName := C.CString("marchproxy_filter")
	defer C.free(unsafe.Pointer(cProgName))
	
	l.progFD = C.get_program_fd(l.obj, cProgName)
	if l.progFD < 0 {
		l.UnloadProgram()
		return fmt.Errorf("failed to get program file descriptor")
	}

	// Get map file descriptors
	cStatsMapName := C.CString("stats_map")
	defer C.free(unsafe.Pointer(cStatsMapName))
	
	l.statsFD = C.get_map_fd(l.obj, cStatsMapName)
	if l.statsFD < 0 {
		l.UnloadProgram()
		return fmt.Errorf("failed to get stats map file descriptor")
	}

	cRulesMapName := C.CString("rules_map")
	defer C.free(unsafe.Pointer(cRulesMapName))
	
	l.rulesFD = C.get_map_fd(l.obj, cRulesMapName)
	if l.rulesFD < 0 {
		l.UnloadProgram()
		return fmt.Errorf("failed to get rules map file descriptor")
	}

	fmt.Printf("eBPF program loaded successfully: %s\n", l.programPath)
	return nil
}

// UnloadProgram unloads the eBPF program and cleans up resources
func (l *BPFLoader) UnloadProgram() error {
	if l.obj != nil {
		C.bpf_object__close(l.obj)
		l.obj = nil
	}

	l.progFD = -1
	l.statsFD = -1
	l.rulesFD = -1

	fmt.Printf("eBPF program unloaded\n")
	return nil
}

// UpdateServiceRule updates a service rule in the eBPF rules map
func (l *BPFLoader) UpdateServiceRule(ruleID uint32, rule *ServiceRule) error {
	if l.obj == nil || l.rulesFD < 0 {
		return fmt.Errorf("eBPF program not loaded")
	}

	// Convert Go struct to C struct
	var cRule C.struct_service_rule
	cRule.service_id = C.__u32(rule.ServiceID)
	cRule.ip_addr = C.__be32(rule.IPAddr)
	cRule.port = C.__u16(rule.Port)
	cRule.protocol = C.__u8(rule.Protocol)
	cRule.action = C.__u8(rule.Action)

	cRuleID := C.__u32(ruleID)
	
	ret := C.update_map_element(l.rulesFD, unsafe.Pointer(&cRuleID), unsafe.Pointer(&cRule))
	if ret != 0 {
		return fmt.Errorf("failed to update service rule %d: %d", ruleID, ret)
	}

	return nil
}

// DeleteServiceRule deletes a service rule from the eBPF rules map
func (l *BPFLoader) DeleteServiceRule(ruleID uint32) error {
	if l.obj == nil || l.rulesFD < 0 {
		return fmt.Errorf("eBPF program not loaded")
	}

	cRuleID := C.__u32(ruleID)
	ret := C.delete_map_element(l.rulesFD, unsafe.Pointer(&cRuleID))
	if ret != 0 {
		return fmt.Errorf("failed to delete service rule %d: %d", ruleID, ret)
	}

	return nil
}

// GetStatistics retrieves statistics from the eBPF stats map
func (l *BPFLoader) GetStatistics() (*EBPFStatistics, error) {
	if l.obj == nil || l.statsFD < 0 {
		return nil, fmt.Errorf("eBPF program not loaded")
	}

	stats := &EBPFStatistics{}

	// Read each statistic from the map
	for i := 0; i < 8; i++ {
		key := C.__u32(i)
		var value C.__u64
		
		ret := C.lookup_map_element(l.statsFD, unsafe.Pointer(&key), unsafe.Pointer(&value))
		if ret != 0 {
			continue // Skip missing entries
		}

		switch i {
		case 0: // STAT_TOTAL_PACKETS
			stats.TotalPackets = uint64(value)
		case 1: // STAT_TCP_PACKETS
			stats.TCPPackets = uint64(value)
		case 2: // STAT_UDP_PACKETS
			stats.UDPPackets = uint64(value)
		case 3: // STAT_DROPPED_PACKETS
			stats.DroppedPackets = uint64(value)
		case 4: // STAT_ALLOWED_PACKETS
			stats.AllowedPackets = uint64(value)
		case 5: // STAT_USERSPACE_PACKETS
			stats.UserspacePackets = uint64(value)
		}
	}

	return stats, nil
}

// IsLoaded returns true if the eBPF program is loaded
func (l *BPFLoader) IsLoaded() bool {
	return l.obj != nil && l.progFD >= 0
}

// GetProgramFD returns the program file descriptor
func (l *BPFLoader) GetProgramFD() int {
	return int(l.progFD)
}

// ServiceRule represents a service rule for eBPF map
type ServiceRule struct {
	ServiceID uint32
	IPAddr    uint32 // Network byte order
	Port      uint16
	Protocol  uint8
	Action    uint8 // 0=drop, 1=allow, 2=userspace
}

// EBPFStatistics represents statistics from eBPF program
type EBPFStatistics struct {
	TotalPackets     uint64
	TCPPackets       uint64
	UDPPackets       uint64
	DroppedPackets   uint64
	AllowedPackets   uint64
	UserspacePackets uint64
}