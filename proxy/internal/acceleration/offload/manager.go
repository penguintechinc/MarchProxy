package offload

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"hash/crc32"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/penguintech/marchproxy/internal/manager"
)

// #cgo CFLAGS: -I/usr/include
// #cgo LDFLAGS: -lcrypto -lssl
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <linux/if.h>
// #include <linux/ethtool.h>
// #include <linux/sockios.h>
// #include <openssl/evp.h>
// #include <openssl/aes.h>
//
// int check_hardware_offload_support(const char *ifname, int feature);
// int enable_hardware_offload(const char *ifname, int feature, int enable);
// int hardware_checksum_offload(void *data, int len, int type);
// int hardware_crypto_encrypt(void *plaintext, int len, void *key, int keylen, void *ciphertext);
// int hardware_crypto_decrypt(void *ciphertext, int len, void *key, int keylen, void *plaintext);
// int get_nic_capabilities(const char *ifname, int *features);
import "C"

// OffloadManager handles hardware offloading capabilities
type OffloadManager struct {
	enabled         bool
	initialized     bool
	interfaces      map[string]*OffloadInterface
	capabilities    *HardwareCapabilities
	config          *OffloadConfig
	stats           *OffloadStats
	cryptoEngines   map[string]*CryptoEngine
	checksumEngines map[string]*ChecksumEngine
	mu              sync.RWMutex
}

// OffloadInterface represents a network interface with offload capabilities
type OffloadInterface struct {
	Name         string
	Driver       string
	Features     *InterfaceFeatures
	Enabled      map[string]bool
	Statistics   *InterfaceStats
	LastActivity time.Time
}

// InterfaceFeatures holds supported hardware features
type InterfaceFeatures struct {
	TxChecksumOffload   bool
	RxChecksumOffload   bool
	TCPSegmentOffload   bool
	GenericSegmentOffload bool
	GenericReceiveOffload bool
	LargeReceiveOffload bool
	ScatterGatherIO     bool
	TxVLANOffload       bool
	RxVLANOffload       bool
	IPsecOffload        bool
	TLSOffload          bool
	MACsecOffload       bool
	RSSSupport          bool
	FlowDirector        bool
	NTupleFiltering     bool
	ADQSupport          bool
	QoSOffload          bool
}

// InterfaceStats holds statistics for an interface
type InterfaceStats struct {
	TxOffloadPackets     uint64
	RxOffloadPackets     uint64
	TxOffloadBytes       uint64
	RxOffloadBytes       uint64
	OffloadErrors        uint64
	HardwareOverruns     uint64
	FirmwareErrors       uint64
	ChecksumOperations   uint64
	CryptoOperations     uint64
	LastUpdate           time.Time
}

// HardwareCapabilities represents system-wide hardware capabilities
type HardwareCapabilities struct {
	AESNISupport         bool
	AVXSupport           bool
	SHA1Support          bool
	SHA256Support        bool
	CRC32CSupport        bool
	IntelQATSupport      bool
	NvidiaGPUSupport     bool
	FPGASupport          bool
	SmartNICSupport      bool
	CryptoAccelerators   []string
	NetworkAccelerators  []string
	LastScan             time.Time
}

// CryptoEngine represents a hardware crypto acceleration engine
type CryptoEngine struct {
	Name           string
	Type           string
	Algorithms     []string
	MaxKeySize     int
	MaxBlockSize   int
	ThroughputMbps uint64
	Latency        time.Duration
	Utilization    float64
	Statistics     *CryptoStats
	LastUpdate     time.Time
}

// CryptoStats holds crypto engine statistics
type CryptoStats struct {
	TotalOperations    uint64
	EncryptOperations  uint64
	DecryptOperations  uint64
	KeyGenerations     uint64
	SignOperations     uint64
	VerifyOperations   uint64
	TotalBytes         uint64
	AverageLatency     time.Duration
	ErrorCount         uint64
	LastUpdate         time.Time
}

// ChecksumEngine represents a hardware checksum engine
type ChecksumEngine struct {
	Name         string
	Type         string
	Algorithms   []string
	Performance  uint64 // Operations per second
	Utilization  float64
	Statistics   *ChecksumStats
	LastUpdate   time.Time
}

// ChecksumStats holds checksum engine statistics
type ChecksumStats struct {
	TotalOperations   uint64
	IPv4Checksums     uint64
	TCPChecksums      uint64
	UDPChecksums      uint64
	CRC32Operations   uint64
	TotalBytes        uint64
	ErrorCount        uint64
	LastUpdate        time.Time
}

// OffloadStats holds overall offload statistics
type OffloadStats struct {
	TotalInterfaces       int
	OffloadEnabledIfs     int
	HardwareAccelerated   uint64
	SoftwareFallback      uint64
	PowerSavedWatts       float64
	PerformanceGainPercent float64
	ErrorRate             float64
	LastUpdate            time.Time
}

// OffloadConfig holds offload configuration
type OffloadConfig struct {
	EnabledFeatures      []string
	DisabledFeatures     []string
	AutoDetection        bool
	PreferHardware       bool
	FallbackToSoftware   bool
	StatsInterval        time.Duration
	PowerOptimization    bool
	SecurityOffload      bool
	CompressionOffload   bool
	DecompressionOffload bool
}

// NewOffloadManager creates a new hardware offload manager
func NewOffloadManager(enabled bool, config *OffloadConfig) *OffloadManager {
	if config == nil {
		config = &OffloadConfig{
			EnabledFeatures:      []string{"tx-checksum-offload", "rx-checksum-offload", "tso", "gso"},
			DisabledFeatures:     []string{},
			AutoDetection:        true,
			PreferHardware:       true,
			FallbackToSoftware:   true,
			StatsInterval:        time.Second * 5,
			PowerOptimization:    true,
			SecurityOffload:      true,
			CompressionOffload:   false,
			DecompressionOffload: false,
		}
	}

	return &OffloadManager{
		enabled:         enabled,
		interfaces:      make(map[string]*OffloadInterface),
		cryptoEngines:   make(map[string]*CryptoEngine),
		checksumEngines: make(map[string]*ChecksumEngine),
		config:          config,
		capabilities: &HardwareCapabilities{
			LastScan: time.Now(),
		},
		stats: &OffloadStats{
			LastUpdate: time.Now(),
		},
	}
}

// Initialize discovers and configures hardware offload capabilities
func (om *OffloadManager) Initialize() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.enabled {
		return fmt.Errorf("hardware offload is disabled")
	}

	if om.initialized {
		return fmt.Errorf("hardware offload already initialized")
	}

	fmt.Printf("Offload: Discovering hardware offload capabilities\n")

	// Detect hardware capabilities
	if err := om.detectHardwareCapabilities(); err != nil {
		return fmt.Errorf("failed to detect hardware capabilities: %w", err)
	}

	// Discover network interfaces with offload support
	if err := om.discoverOffloadInterfaces(); err != nil {
		return fmt.Errorf("failed to discover offload interfaces: %w", err)
	}

	// Initialize crypto engines
	if err := om.initializeCryptoEngines(); err != nil {
		fmt.Printf("Offload: Warning - failed to initialize crypto engines: %v\n", err)
	}

	// Initialize checksum engines
	if err := om.initializeChecksumEngines(); err != nil {
		fmt.Printf("Offload: Warning - failed to initialize checksum engines: %v\n", err)
	}

	om.initialized = true

	// Start statistics collection
	go om.statsCollector()

	fmt.Printf("Offload: Initialized with %d interfaces and %d crypto engines\n",
		len(om.interfaces), len(om.cryptoEngines))
	return nil
}

// detectHardwareCapabilities detects available hardware acceleration capabilities
func (om *OffloadManager) detectHardwareCapabilities() error {
	capabilities := om.capabilities

	// Check for CPU-based acceleration features
	capabilities.AESNISupport = om.checkCPUFeature("aes")
	capabilities.AVXSupport = om.checkCPUFeature("avx")
	capabilities.SHA1Support = om.checkCPUFeature("sha1")
	capabilities.SHA256Support = om.checkCPUFeature("sha256")
	capabilities.CRC32CSupport = om.checkCPUFeature("crc32c")

	// Check for dedicated hardware accelerators
	capabilities.IntelQATSupport = om.checkAccelerator("qat")
	capabilities.NvidiaGPUSupport = om.checkAccelerator("nvidia")
	capabilities.FPGASupport = om.checkAccelerator("fpga")
	capabilities.SmartNICSupport = om.checkAccelerator("smartnic")

	// Populate accelerator lists
	capabilities.CryptoAccelerators = om.discoverCryptoAccelerators()
	capabilities.NetworkAccelerators = om.discoverNetworkAccelerators()

	fmt.Printf("Offload: Hardware capabilities - AES-NI: %t, AVX: %t, QAT: %t\n",
		capabilities.AESNISupport, capabilities.AVXSupport, capabilities.IntelQATSupport)

	return nil
}

// checkCPUFeature checks if a CPU feature is available
func (om *OffloadManager) checkCPUFeature(feature string) bool {
	// Read /proc/cpuinfo to check for CPU features
	// This is simplified - in practice would parse the flags field
	return true // Assume available for demo
}

// checkAccelerator checks if a hardware accelerator is available
func (om *OffloadManager) checkAccelerator(acceleratorType string) bool {
	// Check for specific accelerator hardware
	switch acceleratorType {
	case "qat":
		return om.checkForQAT()
	case "nvidia":
		return om.checkForNvidiaGPU()
	case "fpga":
		return om.checkForFPGA()
	case "smartnic":
		return om.checkForSmartNIC()
	}
	return false
}

// checkForQAT checks for Intel QuickAssist Technology
func (om *OffloadManager) checkForQAT() bool {
	// Check for QAT devices in /sys/bus/pci/devices/
	// or look for qat driver modules
	return false // Not available in most systems
}

// checkForNvidiaGPU checks for NVIDIA GPU with crypto capabilities
func (om *OffloadManager) checkForNvidiaGPU() bool {
	// Check for NVIDIA GPU devices
	return false // Simplified
}

// checkForFPGA checks for FPGA devices
func (om *OffloadManager) checkForFPGA() bool {
	// Check for FPGA devices and drivers
	return false // Simplified
}

// checkForSmartNIC checks for SmartNIC devices
func (om *OffloadManager) checkForSmartNIC() bool {
	// Check for SmartNIC devices with offload capabilities
	return false // Simplified
}

// discoverCryptoAccelerators discovers available crypto accelerators
func (om *OffloadManager) discoverCryptoAccelerators() []string {
	var accelerators []string

	if om.capabilities.AESNISupport {
		accelerators = append(accelerators, "AES-NI")
	}
	if om.capabilities.IntelQATSupport {
		accelerators = append(accelerators, "Intel QAT")
	}
	if om.capabilities.NvidiaGPUSupport {
		accelerators = append(accelerators, "NVIDIA GPU")
	}

	return accelerators
}

// discoverNetworkAccelerators discovers available network accelerators
func (om *OffloadManager) discoverNetworkAccelerators() []string {
	var accelerators []string

	if om.capabilities.SmartNICSupport {
		accelerators = append(accelerators, "SmartNIC")
	}
	if om.capabilities.FPGASupport {
		accelerators = append(accelerators, "FPGA NIC")
	}

	return accelerators
}

// discoverOffloadInterfaces discovers network interfaces with offload capabilities
func (om *OffloadManager) discoverOffloadInterfaces() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}

		offloadIf := &OffloadInterface{
			Name:         iface.Name,
			Features:     &InterfaceFeatures{},
			Enabled:      make(map[string]bool),
			Statistics:   &InterfaceStats{LastUpdate: time.Now()},
			LastActivity: time.Now(),
		}

		// Query interface capabilities using ethtool-like functionality
		om.queryInterfaceFeatures(offloadIf)

		// Enable supported offload features
		if om.config.AutoDetection {
			om.enableSupportedFeatures(offloadIf)
		}

		om.interfaces[iface.Name] = offloadIf
		fmt.Printf("Offload: Discovered interface %s with offload capabilities\n", iface.Name)
	}

	return nil
}

// queryInterfaceFeatures queries the offload features of an interface
func (om *OffloadManager) queryInterfaceFeatures(offloadIf *OffloadInterface) {
	ifname := C.CString(offloadIf.Name)
	defer C.free(unsafe.Pointer(ifname))

	var features C.int

	// Query NIC capabilities
	ret := C.get_nic_capabilities(ifname, &features)
	if ret == 0 {
		// Parse feature flags and set capabilities
		offloadIf.Features.TxChecksumOffload = (features & (1 << 0)) != 0
		offloadIf.Features.RxChecksumOffload = (features & (1 << 1)) != 0
		offloadIf.Features.TCPSegmentOffload = (features & (1 << 2)) != 0
		offloadIf.Features.GenericSegmentOffload = (features & (1 << 3)) != 0
		offloadIf.Features.GenericReceiveOffload = (features & (1 << 4)) != 0
		offloadIf.Features.LargeReceiveOffload = (features & (1 << 5)) != 0
		offloadIf.Features.ScatterGatherIO = (features & (1 << 6)) != 0
		offloadIf.Features.RSSSupport = (features & (1 << 7)) != 0
		offloadIf.Features.IPsecOffload = (features & (1 << 8)) != 0
		offloadIf.Features.TLSOffload = (features & (1 << 9)) != 0
	} else {
		// Set default conservative capabilities
		offloadIf.Features.TxChecksumOffload = true
		offloadIf.Features.RxChecksumOffload = true
		offloadIf.Features.GenericSegmentOffload = true
		offloadIf.Features.GenericReceiveOffload = true
	}
}

// enableSupportedFeatures enables supported offload features for an interface
func (om *OffloadManager) enableSupportedFeatures(offloadIf *OffloadInterface) {
	ifname := C.CString(offloadIf.Name)
	defer C.free(unsafe.Pointer(ifname))

	// Enable TX checksum offload
	if offloadIf.Features.TxChecksumOffload {
		ret := C.enable_hardware_offload(ifname, 0, 1) // Feature 0 = TX checksum
		if ret == 0 {
			offloadIf.Enabled["tx-checksum-offload"] = true
		}
	}

	// Enable RX checksum offload
	if offloadIf.Features.RxChecksumOffload {
		ret := C.enable_hardware_offload(ifname, 1, 1) // Feature 1 = RX checksum
		if ret == 0 {
			offloadIf.Enabled["rx-checksum-offload"] = true
		}
	}

	// Enable TSO if supported
	if offloadIf.Features.TCPSegmentOffload {
		ret := C.enable_hardware_offload(ifname, 2, 1) // Feature 2 = TSO
		if ret == 0 {
			offloadIf.Enabled["tso"] = true
		}
	}
}

// initializeCryptoEngines initializes hardware crypto engines
func (om *OffloadManager) initializeCryptoEngines() error {
	// Initialize AES-NI engine if available
	if om.capabilities.AESNISupport {
		aesEngine := &CryptoEngine{
			Name:           "AES-NI",
			Type:           "CPU",
			Algorithms:     []string{"AES-128", "AES-192", "AES-256"},
			MaxKeySize:     256,
			MaxBlockSize:   16,
			ThroughputMbps: 10000, // Approximate
			Latency:        time.Microsecond,
			Statistics:     &CryptoStats{LastUpdate: time.Now()},
			LastUpdate:     time.Now(),
		}
		om.cryptoEngines["aes-ni"] = aesEngine
		fmt.Printf("Offload: Initialized AES-NI crypto engine\n")
	}

	// Initialize other crypto engines as available
	// (QAT, GPU, etc. would be initialized here)

	return nil
}

// initializeChecksumEngines initializes hardware checksum engines
func (om *OffloadManager) initializeChecksumEngines() error {
	// Initialize CRC32C engine if available
	if om.capabilities.CRC32CSupport {
		crcEngine := &ChecksumEngine{
			Name:        "CRC32C",
			Type:        "CPU",
			Algorithms:  []string{"CRC32C", "CRC32"},
			Performance: 50000000, // Operations per second
			Statistics:  &ChecksumStats{LastUpdate: time.Now()},
			LastUpdate:  time.Now(),
		}
		om.checksumEngines["crc32c"] = crcEngine
		fmt.Printf("Offload: Initialized CRC32C checksum engine\n")
	}

	return nil
}

// OffloadChecksum performs hardware-accelerated checksum calculation
func (om *OffloadManager) OffloadChecksum(data []byte, checksumType string) (uint32, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	if !om.initialized {
		return 0, fmt.Errorf("offload manager not initialized")
	}

	// Try hardware acceleration first
	if engine, exists := om.checksumEngines["crc32c"]; exists && checksumType == "crc32" {
		engine.Statistics.TotalOperations++
		engine.Statistics.TotalBytes += uint64(len(data))
		engine.LastUpdate = time.Now()

		// Use hardware CRC32 if available
		csum := C.hardware_checksum_offload(unsafe.Pointer(&data[0]), C.int(len(data)), 0)
		if csum >= 0 {
			return uint32(csum), nil
		}
	}

	// Software fallback
	if checksumType == "crc32" {
		return crc32.ChecksumIEEE(data), nil
	}

	return 0, fmt.Errorf("unsupported checksum type: %s", checksumType)
}

// OffloadEncryption performs hardware-accelerated encryption
func (om *OffloadManager) OffloadEncryption(plaintext, key []byte, algorithm string) ([]byte, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	if !om.initialized {
		return nil, fmt.Errorf("offload manager not initialized")
	}

	// Try hardware acceleration first
	if engine, exists := om.cryptoEngines["aes-ni"]; exists && algorithm == "aes" {
		engine.Statistics.EncryptOperations++
		engine.Statistics.TotalBytes += uint64(len(plaintext))
		engine.LastUpdate = time.Now()

		// Use hardware AES if available
		ciphertext := make([]byte, len(plaintext))
		ret := C.hardware_crypto_encrypt(
			unsafe.Pointer(&plaintext[0]), C.int(len(plaintext)),
			unsafe.Pointer(&key[0]), C.int(len(key)),
			unsafe.Pointer(&ciphertext[0]))

		if ret == 0 {
			return ciphertext, nil
		}
	}

	// Software fallback using Go crypto
	return om.softwareEncryption(plaintext, key, algorithm)
}

// OffloadDecryption performs hardware-accelerated decryption
func (om *OffloadManager) OffloadDecryption(ciphertext, key []byte, algorithm string) ([]byte, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	if !om.initialized {
		return nil, fmt.Errorf("offload manager not initialized")
	}

	// Try hardware acceleration first
	if engine, exists := om.cryptoEngines["aes-ni"]; exists && algorithm == "aes" {
		engine.Statistics.DecryptOperations++
		engine.Statistics.TotalBytes += uint64(len(ciphertext))
		engine.LastUpdate = time.Now()

		// Use hardware AES if available
		plaintext := make([]byte, len(ciphertext))
		ret := C.hardware_crypto_decrypt(
			unsafe.Pointer(&ciphertext[0]), C.int(len(ciphertext)),
			unsafe.Pointer(&key[0]), C.int(len(key)),
			unsafe.Pointer(&plaintext[0]))

		if ret == 0 {
			return plaintext, nil
		}
	}

	// Software fallback
	return om.softwareDecryption(ciphertext, key, algorithm)
}

// softwareEncryption performs software-based encryption fallback
func (om *OffloadManager) softwareEncryption(plaintext, key []byte, algorithm string) ([]byte, error) {
	if algorithm == "aes" {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		// Use GCM mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, gcm.NonceSize())
		// In practice, nonce should be randomly generated
		
		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
		return append(nonce, ciphertext...), nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

// softwareDecryption performs software-based decryption fallback
func (om *OffloadManager) softwareDecryption(ciphertext, key []byte, algorithm string) ([]byte, error) {
	if algorithm == "aes" {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			return nil, fmt.Errorf("ciphertext too short")
		}

		nonce := ciphertext[:nonceSize]
		ciphertext = ciphertext[nonceSize:]

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

// statsCollector collects offload statistics
func (om *OffloadManager) statsCollector() {
	ticker := time.NewTicker(om.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			om.collectStatistics()
		}
	}
}

// collectStatistics collects and updates offload statistics
func (om *OffloadManager) collectStatistics() {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Update interface statistics
	for _, iface := range om.interfaces {
		// Read interface statistics from system
		// This is simplified - would read from /sys/class/net/<if>/statistics/
		iface.Statistics.LastUpdate = time.Now()
	}

	// Update overall statistics
	om.stats.TotalInterfaces = len(om.interfaces)
	om.stats.OffloadEnabledIfs = om.countEnabledInterfaces()

	// Calculate hardware acceleration usage
	totalOperations := uint64(0)
	hardwareOperations := uint64(0)

	for _, engine := range om.cryptoEngines {
		totalOperations += engine.Statistics.TotalOperations
		if engine.Type == "CPU" || engine.Type == "Hardware" {
			hardwareOperations += engine.Statistics.TotalOperations
		}
	}

	for _, engine := range om.checksumEngines {
		totalOperations += engine.Statistics.TotalOperations
		if engine.Type == "CPU" || engine.Type == "Hardware" {
			hardwareOperations += engine.Statistics.TotalOperations
		}
	}

	om.stats.HardwareAccelerated = hardwareOperations
	om.stats.SoftwareFallback = totalOperations - hardwareOperations

	if totalOperations > 0 {
		om.stats.PerformanceGainPercent = float64(hardwareOperations) / float64(totalOperations) * 100.0
	}

	om.stats.LastUpdate = time.Now()
}

// countEnabledInterfaces counts interfaces with offload enabled
func (om *OffloadManager) countEnabledInterfaces() int {
	count := 0
	for _, iface := range om.interfaces {
		if len(iface.Enabled) > 0 {
			count++
		}
	}
	return count
}

// UpdateServices updates hardware offload usage for services
func (om *OffloadManager) UpdateServices(services []manager.Service) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	fmt.Printf("Offload: Updating hardware offload for %d services\n", len(services))

	// In a full implementation, this would configure offload settings
	// based on service requirements (encryption, compression, etc.)

	return nil
}

// Stop cleans up hardware offload resources
func (om *OffloadManager) Stop() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.initialized {
		return nil
	}

	fmt.Printf("Offload: Cleaning up hardware offload\n")

	// Disable offload features on interfaces
	for _, iface := range om.interfaces {
		ifname := C.CString(iface.Name)
		for feature := range iface.Enabled {
			featureID := om.getFeatureID(feature)
			C.enable_hardware_offload(ifname, C.int(featureID), 0) // Disable
		}
		C.free(unsafe.Pointer(ifname))
	}

	om.initialized = false
	fmt.Printf("Offload: Cleanup complete\n")
	return nil
}

// getFeatureID returns the feature ID for a feature name
func (om *OffloadManager) getFeatureID(feature string) int {
	switch feature {
	case "tx-checksum-offload":
		return 0
	case "rx-checksum-offload":
		return 1
	case "tso":
		return 2
	case "gso":
		return 3
	default:
		return -1
	}
}

// GetStats returns current offload statistics
func (om *OffloadManager) GetStats() *OffloadStats {
	om.mu.RLock()
	defer om.mu.RUnlock()

	stats := *om.stats
	return &stats
}

// IsEnabled returns whether hardware offload is enabled
func (om *OffloadManager) IsEnabled() bool {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.enabled && om.initialized
}

// GetCapabilities returns hardware capabilities
func (om *OffloadManager) GetCapabilities() *HardwareCapabilities {
	om.mu.RLock()
	defer om.mu.RUnlock()

	capabilities := *om.capabilities
	return &capabilities
}

// GetInterfaces returns offload-capable interfaces
func (om *OffloadManager) GetInterfaces() map[string]*OffloadInterface {
	om.mu.RLock()
	defer om.mu.RUnlock()

	interfaces := make(map[string]*OffloadInterface)
	for name, iface := range om.interfaces {
		ifaceCopy := *iface
		interfaces[name] = &ifaceCopy
	}
	return interfaces
}

// GetCryptoEngines returns available crypto engines
func (om *OffloadManager) GetCryptoEngines() map[string]*CryptoEngine {
	om.mu.RLock()
	defer om.mu.RUnlock()

	engines := make(map[string]*CryptoEngine)
	for name, engine := range om.cryptoEngines {
		engineCopy := *engine
		engines[name] = &engineCopy
	}
	return engines
}