// +build dpdk

package dpdk

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/penguintech/marchproxy/internal/manager"
)

// #cgo CFLAGS: -I/usr/include/dpdk -mssse3
// #cgo LDFLAGS: -ldpdk -lrte_eal -lrte_mempool -lrte_mbuf -lrte_ring -lrte_ethdev -lrte_net -lrte_pci -lrte_bus_pci
// #include <rte_config.h>
// #include <rte_common.h>
// #include <rte_eal.h>
// #include <rte_ethdev.h>
// #include <rte_mbuf.h>
// #include <rte_mempool.h>
// #include <rte_ring.h>
// #include <rte_lcore.h>
// #include <rte_launch.h>
// #include <rte_atomic.h>
// #include <rte_cycles.h>
// #include <rte_prefetch.h>
// #include <rte_branch_prediction.h>
// #include <rte_interrupts.h>
// #include <rte_pci.h>
// #include <rte_random.h>
// #include <rte_debug.h>
// #include <rte_ether.h>
// #include <rte_ip.h>
// #include <rte_tcp.h>
// #include <rte_udp.h>
//
// int init_dpdk_eal(int argc, char **argv);
// int configure_dpdk_port(uint16_t port_id, uint16_t nb_rx_queues, uint16_t nb_tx_queues);
// struct rte_mempool* create_packet_mempool(const char *name, unsigned nb_mbufs, unsigned cache_size, uint16_t data_room_size, int socket_id);
// int start_dpdk_port(uint16_t port_id);
// uint16_t dpdk_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts);
// uint16_t dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts);
// void dpdk_free_packets(struct rte_mbuf **pkts, uint16_t nb_pkts);
// struct rte_mbuf* dpdk_alloc_packet(struct rte_mempool *mp);
// void* get_packet_data(struct rte_mbuf *pkt);
// uint16_t get_packet_len(struct rte_mbuf *pkt);
// void set_packet_len(struct rte_mbuf *pkt, uint16_t len);
// int dpdk_get_link_status(uint16_t port_id);
import "C"

// DPDKManager handles DPDK initialization and packet processing
type DPDKManager struct {
	enabled        bool
	initialized    bool
	ports          map[uint16]*DPDKPort
	mempool        *C.struct_rte_mempool
	stats          *DPDKStats
	config         *DPDKConfig
	workerChannels map[int]chan *DPDKPacket
	stopChannel    chan struct{}
	wg             sync.WaitGroup
	mu             sync.RWMutex
}

// DPDKPort represents a DPDK-enabled network port
type DPDKPort struct {
	ID            uint16
	NbRxQueues    uint16
	NbTxQueues    uint16
	RxRings       []*C.struct_rte_ring
	TxRings       []*C.struct_rte_ring
	LinkStatus    bool
	RxPackets     uint64
	TxPackets     uint64
	RxBytes       uint64
	TxBytes       uint64
	RxDropped     uint64
	TxDropped     uint64
}

// DPDKPacket represents a packet in DPDK format
type DPDKPacket struct {
	Mbuf      *C.struct_rte_mbuf
	Data      []byte
	Length    uint16
	PortID    uint16
	QueueID   uint16
	Timestamp time.Time
}

// DPDKStats holds DPDK performance statistics
type DPDKStats struct {
	TotalRxPackets    uint64
	TotalTxPackets    uint64
	TotalRxBytes      uint64
	TotalTxBytes      uint64
	TotalRxDropped    uint64
	TotalTxDropped    uint64
	WorkerUtilization []float64
	PacketsPerSecond  uint64
	BytesPerSecond    uint64
	LastUpdate        time.Time
}

// DPDKConfig holds DPDK configuration parameters
type DPDKConfig struct {
	EALArgs           []string
	NbMbufs           uint32
	MempoolCacheSize  uint32
	DataRoomSize      uint16
	RxDescriptors     uint16
	TxDescriptors     uint16
	RxQueuesPerPort   uint16
	TxQueuesPerPort   uint16
	WorkerCores       []int
	BurstSize         uint16
	PrefetchOffset    uint8
}

// NewDPDKManager creates a new DPDK manager
func NewDPDKManager(enabled bool, config *DPDKConfig) *DPDKManager {
	if config == nil {
		config = &DPDKConfig{
			EALArgs:          []string{"proxy", "-l", "0-3", "-n", "4", "--proc-type=primary"},
			NbMbufs:          8192,
			MempoolCacheSize: 256,
			DataRoomSize:     2048,
			RxDescriptors:    1024,
			TxDescriptors:    1024,
			RxQueuesPerPort:  4,
			TxQueuesPerPort:  4,
			WorkerCores:      []int{1, 2, 3},
			BurstSize:        32,
			PrefetchOffset:   3,
		}
	}

	return &DPDKManager{
		enabled:        enabled,
		initialized:    false,
		ports:          make(map[uint16]*DPDKPort),
		config:         config,
		workerChannels: make(map[int]chan *DPDKPacket),
		stopChannel:    make(chan struct{}),
		stats: &DPDKStats{
			WorkerUtilization: make([]float64, len(config.WorkerCores)),
			LastUpdate:        time.Now(),
		},
	}
}

// Initialize initializes DPDK EAL and sets up memory pools
func (dm *DPDKManager) Initialize() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.enabled {
		return fmt.Errorf("DPDK is disabled")
	}

	if dm.initialized {
		return fmt.Errorf("DPDK already initialized")
	}

	fmt.Printf("DPDK: Initializing EAL with args: %v\n", dm.config.EALArgs)

	// Convert Go strings to C strings for EAL initialization
	argc := C.int(len(dm.config.EALArgs))
	argv := C.malloc(C.size_t(len(dm.config.EALArgs)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	defer C.free(argv)

	// Convert argv to array of C strings
	argvSlice := (*[1 << 16]*C.char)(argv)[:len(dm.config.EALArgs):len(dm.config.EALArgs)]
	for i, arg := range dm.config.EALArgs {
		argvSlice[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argvSlice[i]))
	}

	// Initialize DPDK EAL
	ret := C.init_dpdk_eal(argc, (**C.char)(argv))
	if ret < 0 {
		return fmt.Errorf("failed to initialize DPDK EAL: %d", ret)
	}

	// Create packet mempool
	mempoolName := C.CString("packet_pool")
	defer C.free(unsafe.Pointer(mempoolName))

	dm.mempool = C.create_packet_mempool(
		mempoolName,
		C.uint(dm.config.NbMbufs),
		C.uint(dm.config.MempoolCacheSize),
		C.ushort(dm.config.DataRoomSize),
		C.SOCKET_ID_ANY,
	)

	if dm.mempool == nil {
		return fmt.Errorf("failed to create DPDK mempool")
	}

	dm.initialized = true
	fmt.Printf("DPDK: EAL initialized successfully\n")
	return nil
}

// AddPort configures and starts a DPDK port
func (dm *DPDKManager) AddPort(portID uint16) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.initialized {
		return fmt.Errorf("DPDK not initialized")
	}

	if _, exists := dm.ports[portID]; exists {
		return fmt.Errorf("port %d already configured", portID)
	}

	fmt.Printf("DPDK: Configuring port %d\n", portID)

	// Configure the port
	ret := C.configure_dpdk_port(
		C.ushort(portID),
		C.ushort(dm.config.RxQueuesPerPort),
		C.ushort(dm.config.TxQueuesPerPort),
	)
	if ret != 0 {
		return fmt.Errorf("failed to configure DPDK port %d: %d", portID, ret)
	}

	// Start the port
	ret = C.start_dpdk_port(C.ushort(portID))
	if ret != 0 {
		return fmt.Errorf("failed to start DPDK port %d: %d", portID, ret)
	}

	// Create port structure
	port := &DPDKPort{
		ID:         portID,
		NbRxQueues: dm.config.RxQueuesPerPort,
		NbTxQueues: dm.config.TxQueuesPerPort,
		LinkStatus: true,
	}

	dm.ports[portID] = port
	fmt.Printf("DPDK: Port %d configured and started successfully\n", portID)
	return nil
}

// StartWorkers starts DPDK worker threads for packet processing
func (dm *DPDKManager) StartWorkers() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.initialized {
		return fmt.Errorf("DPDK not initialized")
	}

	fmt.Printf("DPDK: Starting %d worker cores\n", len(dm.config.WorkerCores))

	// Create worker channels
	for _, coreID := range dm.config.WorkerCores {
		dm.workerChannels[coreID] = make(chan *DPDKPacket, 1024)
		dm.wg.Add(1)
		go dm.workerLoop(coreID)
	}

	// Start statistics collection
	dm.wg.Add(1)
	go dm.statsCollector()

	fmt.Printf("DPDK: All workers started\n")
	return nil
}

// workerLoop runs the packet processing loop for a worker core
func (dm *DPDKManager) workerLoop(coreID int) {
	defer dm.wg.Done()

	fmt.Printf("DPDK: Worker %d started\n", coreID)
	
	// Allocate burst array
	burstSize := dm.config.BurstSize
	rxPkts := make([]*C.struct_rte_mbuf, burstSize)
	txPkts := make([]*C.struct_rte_mbuf, burstSize)

	ticker := time.NewTicker(time.Microsecond * 100) // 10kHz polling
	defer ticker.Stop()

	packetsProcessed := uint64(0)
	startTime := time.Now()

	for {
		select {
		case <-dm.stopChannel:
			fmt.Printf("DPDK: Worker %d stopping\n", coreID)
			return
		case <-ticker.C:
			// Process all configured ports
			for portID, port := range dm.ports {
				if !port.LinkStatus {
					continue
				}

				// Round-robin through queues
				queueID := uint16(packetsProcessed % uint64(port.NbRxQueues))

				// Receive packets
				nbRx := C.dpdk_rx_burst(
					C.ushort(portID),
					C.ushort(queueID),
					(**C.struct_rte_mbuf)(unsafe.Pointer(&rxPkts[0])),
					C.ushort(burstSize),
				)

				if nbRx > 0 {
					dm.processPacketBurst(rxPkts[:nbRx], portID, queueID, txPkts)
					packetsProcessed += uint64(nbRx)
					
					// Update port statistics
					atomic.AddUint64(&port.RxPackets, uint64(nbRx))
				}
			}

			// Update worker utilization
			if packetsProcessed%10000 == 0 {
				duration := time.Since(startTime)
				utilization := float64(packetsProcessed) / duration.Seconds() / 1000000.0 // MPPS
				dm.updateWorkerUtilization(coreID, utilization)
			}
		}
	}
}

// processPacketBurst processes a burst of received packets
func (dm *DPDKManager) processPacketBurst(rxPkts []*C.struct_rte_mbuf, portID uint16, queueID uint16, txPkts []*C.struct_rte_mbuf) {
	nbTx := uint16(0)

	for i, pkt := range rxPkts {
		if pkt == nil {
			continue
		}

		// Prefetch next packet
		if i+int(dm.config.PrefetchOffset) < len(rxPkts) {
			if rxPkts[i+int(dm.config.PrefetchOffset)] != nil {
				C.rte_prefetch0(C.get_packet_data(rxPkts[i+int(dm.config.PrefetchOffset)]))
			}
		}

		// Process packet
		if dm.processPacket(pkt, portID, queueID) {
			// Forward packet
			txPkts[nbTx] = pkt
			nbTx++
		} else {
			// Drop packet
			C.rte_pktmbuf_free(pkt)
			atomic.AddUint64(&dm.ports[portID].RxDropped, 1)
		}
	}

	// Transmit processed packets
	if nbTx > 0 {
		nbSent := C.dpdk_tx_burst(
			C.ushort(portID),
			C.ushort(queueID),
			(**C.struct_rte_mbuf)(unsafe.Pointer(&txPkts[0])),
			C.ushort(nbTx),
		)

		atomic.AddUint64(&dm.ports[portID].TxPackets, uint64(nbSent))

		// Free unsent packets
		if nbSent < nbTx {
			for i := nbSent; i < nbTx; i++ {
				C.rte_pktmbuf_free(txPkts[i])
				atomic.AddUint64(&dm.ports[portID].TxDropped, 1)
			}
		}
	}
}

// processPacket processes a single packet
func (dm *DPDKManager) processPacket(pkt *C.struct_rte_mbuf, portID uint16, queueID uint16) bool {
	// Get packet data
	data := C.get_packet_data(pkt)
	length := C.get_packet_len(pkt)

	// Convert to Go slice for processing
	packetData := C.GoBytes(data, C.int(length))

	// Basic Ethernet header parsing
	if len(packetData) < 14 {
		return false // Drop malformed packets
	}

	// Extract Ethernet type
	etherType := uint16(packetData[12])<<8 | uint16(packetData[13])

	// Process IPv4 packets
	if etherType == 0x0800 && len(packetData) >= 34 {
		return dm.processIPv4Packet(packetData[14:], pkt)
	}

	// Drop non-IPv4 packets for now
	return false
}

// processIPv4Packet processes IPv4 packets
func (dm *DPDKManager) processIPv4Packet(ipData []byte, pkt *C.struct_rte_mbuf) bool {
	if len(ipData) < 20 {
		return false
	}

	// Extract IP header fields
	protocol := ipData[9]
	srcIP := uint32(ipData[12])<<24 | uint32(ipData[13])<<16 | uint32(ipData[14])<<8 | uint32(ipData[15])
	dstIP := uint32(ipData[16])<<24 | uint32(ipData[17])<<16 | uint32(ipData[18])<<8 | uint32(ipData[19])

	// Get IP header length
	headerLen := (ipData[0] & 0x0F) * 4
	if len(ipData) < int(headerLen) {
		return false
	}

	var srcPort, dstPort uint16
	
	// Extract port numbers for TCP/UDP
	if protocol == 6 || protocol == 17 { // TCP or UDP
		if len(ipData) >= int(headerLen)+4 {
			transportData := ipData[headerLen:]
			srcPort = uint16(transportData[0])<<8 | uint16(transportData[1])
			dstPort = uint16(transportData[2])<<8 | uint16(transportData[3])
		}
	}

	// Apply simple filtering logic
	// For now, accept all packets from known service IPs
	return dm.shouldAcceptPacket(srcIP, dstIP, srcPort, dstPort, protocol)
}

// shouldAcceptPacket determines if a packet should be accepted
func (dm *DPDKManager) shouldAcceptPacket(srcIP, dstIP uint32, srcPort, dstPort uint16, protocol uint8) bool {
	// Simple allow-all policy for now
	// In production, this would check against service rules
	return true
}

// updateWorkerUtilization updates worker utilization statistics
func (dm *DPDKManager) updateWorkerUtilization(coreID int, utilization float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Find core index
	for i, core := range dm.config.WorkerCores {
		if core == coreID {
			if i < len(dm.stats.WorkerUtilization) {
				dm.stats.WorkerUtilization[i] = utilization
			}
			break
		}
	}
}

// statsCollector collects and updates DPDK statistics
func (dm *DPDKManager) statsCollector() {
	defer dm.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastRxPackets, lastTxPackets uint64
	lastUpdate := time.Now()

	for {
		select {
		case <-dm.stopChannel:
			return
		case <-ticker.C:
			dm.mu.RLock()
			
			// Aggregate port statistics
			totalRxPackets := uint64(0)
			totalTxPackets := uint64(0)
			totalRxBytes := uint64(0)
			totalTxBytes := uint64(0)
			totalRxDropped := uint64(0)
			totalTxDropped := uint64(0)

			for _, port := range dm.ports {
				totalRxPackets += atomic.LoadUint64(&port.RxPackets)
				totalTxPackets += atomic.LoadUint64(&port.TxPackets)
				totalRxBytes += atomic.LoadUint64(&port.RxBytes)
				totalTxBytes += atomic.LoadUint64(&port.TxBytes)
				totalRxDropped += atomic.LoadUint64(&port.RxDropped)
				totalTxDropped += atomic.LoadUint64(&port.TxDropped)
			}

			// Calculate rates
			now := time.Now()
			duration := now.Sub(lastUpdate).Seconds()
			if duration > 0 {
				dm.stats.PacketsPerSecond = uint64(float64(totalRxPackets-lastRxPackets) / duration)
				dm.stats.BytesPerSecond = uint64(float64(totalRxBytes-atomic.LoadUint64(&dm.stats.TotalRxBytes)) / duration)
			}

			// Update statistics
			atomic.StoreUint64(&dm.stats.TotalRxPackets, totalRxPackets)
			atomic.StoreUint64(&dm.stats.TotalTxPackets, totalTxPackets)
			atomic.StoreUint64(&dm.stats.TotalRxBytes, totalRxBytes)
			atomic.StoreUint64(&dm.stats.TotalTxBytes, totalTxBytes)
			atomic.StoreUint64(&dm.stats.TotalRxDropped, totalRxDropped)
			atomic.StoreUint64(&dm.stats.TotalTxDropped, totalTxDropped)
			dm.stats.LastUpdate = now

			lastRxPackets = totalRxPackets
			lastTxPackets = totalTxPackets
			lastUpdate = now

			dm.mu.RUnlock()
		}
	}
}

// Stop stops all DPDK workers and cleans up resources
func (dm *DPDKManager) Stop() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.initialized {
		return nil
	}

	fmt.Printf("DPDK: Stopping workers\n")
	close(dm.stopChannel)
	dm.wg.Wait()

	// Close worker channels
	for _, ch := range dm.workerChannels {
		close(ch)
	}

	fmt.Printf("DPDK: Cleanup complete\n")
	return nil
}

// GetStats returns current DPDK statistics
func (dm *DPDKManager) GetStats() *DPDKStats {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	stats := *dm.stats
	return &stats
}

// IsEnabled returns whether DPDK is enabled
func (dm *DPDKManager) IsEnabled() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.enabled && dm.initialized
}

// GetPortStats returns statistics for a specific port
func (dm *DPDKManager) GetPortStats(portID uint16) (*DPDKPort, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	port, exists := dm.ports[portID]
	if !exists {
		return nil, fmt.Errorf("port %d not found", portID)
	}

	// Create a copy to avoid race conditions
	portCopy := *port
	return &portCopy, nil
}