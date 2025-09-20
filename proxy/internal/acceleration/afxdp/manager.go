// +build afxdp

package afxdp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/penguintech/marchproxy/internal/manager"
)

// #cgo CFLAGS: -I/usr/include/bpf -I.
// #cgo LDFLAGS: -lbpf -lxdp
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <errno.h>
// #include <unistd.h>
// #include <sys/socket.h>
// #include <sys/mman.h>
// #include <linux/if.h>
// #include <linux/if_xdp.h>
// #include <linux/if_link.h>
// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <bpf/xsk.h>
//
// struct xsk_socket_info {
//     struct xsk_ring_cons rx;
//     struct xsk_ring_prod tx;
//     struct xsk_umem_info *umem;
//     struct xsk_socket *xsk;
//     uint64_t umem_frame_addr[2048];
//     uint32_t umem_frame_free;
//     uint32_t outstanding_tx;
// };
//
// struct xsk_umem_info {
//     struct xsk_ring_prod fq;
//     struct xsk_ring_cons cq;
//     struct xsk_umem *umem;
//     void *buffer;
//     uint64_t buffer_size;
// };
//
// int create_af_xdp_socket(const char *ifname, int queue_id, struct xsk_socket_info *xsk_info);
// int configure_xsk_umem(struct xsk_umem_info *umem_info, void *buffer, uint64_t buffer_size);
// int rx_and_process(struct xsk_socket_info *xsk_info, int batch_size);
// int tx_packets(struct xsk_socket_info *xsk_info, int batch_size);
// void cleanup_xsk(struct xsk_socket_info *xsk_info);
// uint64_t get_xsk_stats(struct xsk_socket_info *xsk_info, int stat_type);
import "C"

// AFXDPManager handles AF_XDP socket management and zero-copy packet processing
type AFXDPManager struct {
	enabled       bool
	initialized   bool
	sockets       map[string]*AFXDPSocket
	config        *AFXDPConfig
	stats         *AFXDPStats
	workerPool    []*AFXDPWorker
	stopChannel   chan struct{}
	wg            sync.WaitGroup
	mu            sync.RWMutex
}

// AFXDPSocket represents an AF_XDP socket for a specific interface/queue
type AFXDPSocket struct {
	InterfaceName string
	QueueID       int
	SocketInfo    *C.struct_xsk_socket_info
	UmemInfo      *C.struct_xsk_umem_info
	Buffer        unsafe.Pointer
	BufferSize    uint64
	RxPackets     uint64
	TxPackets     uint64
	DroppedPkts   uint64
	InvalidPkts   uint64
	LastActivity  time.Time
}

// AFXDPWorker handles packet processing for AF_XDP sockets
type AFXDPWorker struct {
	ID            int
	Socket        *AFXDPSocket
	ProcessingFn  func([]byte, *AFXDPSocket) bool
	BatchSize     int
	PollTimeout   time.Duration
	PacketsRx     uint64
	PacketsTx     uint64
	ProcessedPkts uint64
	ErrorCount    uint64
}

// AFXDPStats holds AF_XDP performance statistics
type AFXDPStats struct {
	TotalRxPackets    uint64
	TotalTxPackets    uint64
	TotalDropped      uint64
	TotalInvalid      uint64
	ZeroCopyFrames    uint64
	UmemFillRing      uint64
	UmemCompRing      uint64
	SocketUtilization []float64
	FramesPerSecond   uint64
	BytesPerSecond    uint64
	LastUpdate        time.Time
}

// AFXDPConfig holds AF_XDP configuration parameters
type AFXDPConfig struct {
	Interfaces     []string
	QueuesPerIf    int
	UmemFrameSize  uint32
	UmemFrameCount uint32
	BatchSize      int
	PollTimeout    time.Duration
	WorkerThreads  int
	ZeroCopyMode   bool
	BusyPolling    bool
	TxBudget       int
}

// PacketProcessor defines the interface for packet processing functions
type PacketProcessor interface {
	ProcessPacket(data []byte, socket *AFXDPSocket) bool
}

// NewAFXDPManager creates a new AF_XDP manager
func NewAFXDPManager(enabled bool, config *AFXDPConfig) *AFXDPManager {
	if config == nil {
		config = &AFXDPConfig{
			Interfaces:     []string{"eth0"},
			QueuesPerIf:    4,
			UmemFrameSize:  2048,
			UmemFrameCount: 4096,
			BatchSize:      64,
			PollTimeout:    time.Millisecond,
			WorkerThreads:  4,
			ZeroCopyMode:   true,
			BusyPolling:    false,
			TxBudget:       256,
		}
	}

	return &AFXDPManager{
		enabled:     enabled,
		sockets:     make(map[string]*AFXDPSocket),
		config:      config,
		stopChannel: make(chan struct{}),
		stats: &AFXDPStats{
			SocketUtilization: make([]float64, config.WorkerThreads),
			LastUpdate:        time.Now(),
		},
	}
}

// Initialize sets up AF_XDP sockets and memory regions
func (am *AFXDPManager) Initialize() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.enabled {
		return fmt.Errorf("AF_XDP is disabled")
	}

	if am.initialized {
		return fmt.Errorf("AF_XDP already initialized")
	}

	fmt.Printf("AF_XDP: Initializing with %d interfaces, %d queues per interface\n", 
		len(am.config.Interfaces), am.config.QueuesPerIf)

	// Create AF_XDP sockets for each interface and queue
	for _, ifname := range am.config.Interfaces {
		for queueID := 0; queueID < am.config.QueuesPerIf; queueID++ {
			if err := am.createSocket(ifname, queueID); err != nil {
				return fmt.Errorf("failed to create AF_XDP socket for %s queue %d: %w", ifname, queueID, err)
			}
		}
	}

	am.initialized = true
	fmt.Printf("AF_XDP: Initialized successfully with %d sockets\n", len(am.sockets))
	return nil
}

// createSocket creates an AF_XDP socket for a specific interface and queue
func (am *AFXDPManager) createSocket(ifname string, queueID int) error {
	socketKey := fmt.Sprintf("%s:%d", ifname, queueID)

	// Allocate UMEM buffer
	bufferSize := uint64(am.config.UmemFrameSize * am.config.UmemFrameCount)
	buffer := C.malloc(C.size_t(bufferSize))
	if buffer == nil {
		return fmt.Errorf("failed to allocate UMEM buffer")
	}

	// Create UMEM info structure
	umemInfo := (*C.struct_xsk_umem_info)(C.malloc(C.sizeof_struct_xsk_umem_info))
	if umemInfo == nil {
		C.free(buffer)
		return fmt.Errorf("failed to allocate UMEM info structure")
	}

	// Configure UMEM
	ret := C.configure_xsk_umem(umemInfo, buffer, C.ulong(bufferSize))
	if ret != 0 {
		C.free(buffer)
		C.free(unsafe.Pointer(umemInfo))
		return fmt.Errorf("failed to configure UMEM: %d", ret)
	}

	// Create socket info structure
	socketInfo := (*C.struct_xsk_socket_info)(C.malloc(C.sizeof_struct_xsk_socket_info))
	if socketInfo == nil {
		C.free(buffer)
		C.free(unsafe.Pointer(umemInfo))
		return fmt.Errorf("failed to allocate socket info structure")
	}

	socketInfo.umem = umemInfo

	// Create AF_XDP socket
	ifnameC := C.CString(ifname)
	defer C.free(unsafe.Pointer(ifnameC))

	ret = C.create_af_xdp_socket(ifnameC, C.int(queueID), socketInfo)
	if ret != 0 {
		C.free(buffer)
		C.free(unsafe.Pointer(umemInfo))
		C.free(unsafe.Pointer(socketInfo))
		return fmt.Errorf("failed to create AF_XDP socket: %d", ret)
	}

	// Create socket wrapper
	socket := &AFXDPSocket{
		InterfaceName: ifname,
		QueueID:       queueID,
		SocketInfo:    socketInfo,
		UmemInfo:      umemInfo,
		Buffer:        buffer,
		BufferSize:    bufferSize,
		LastActivity:  time.Now(),
	}

	am.sockets[socketKey] = socket
	fmt.Printf("AF_XDP: Created socket for %s queue %d\n", ifname, queueID)
	return nil
}

// StartWorkers starts worker threads for packet processing
func (am *AFXDPManager) StartWorkers(processor PacketProcessor) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return fmt.Errorf("AF_XDP not initialized")
	}

	fmt.Printf("AF_XDP: Starting %d worker threads\n", am.config.WorkerThreads)

	// Create worker pool
	am.workerPool = make([]*AFXDPWorker, 0, am.config.WorkerThreads)
	
	socketList := make([]*AFXDPSocket, 0, len(am.sockets))
	for _, socket := range am.sockets {
		socketList = append(socketList, socket)
	}

	// Distribute sockets among workers
	for i := 0; i < am.config.WorkerThreads; i++ {
		worker := &AFXDPWorker{
			ID:          i,
			BatchSize:   am.config.BatchSize,
			PollTimeout: am.config.PollTimeout,
		}

		// Assign sockets to this worker (round-robin)
		for j := i; j < len(socketList); j += am.config.WorkerThreads {
			worker.Socket = socketList[j] // For simplicity, one socket per worker
			break
		}

		if worker.Socket != nil {
			am.workerPool = append(am.workerPool, worker)
			am.wg.Add(1)
			go am.workerLoop(worker, processor)
		}
	}

	// Start statistics collector
	am.wg.Add(1)
	go am.statsCollector()

	fmt.Printf("AF_XDP: Started %d workers\n", len(am.workerPool))
	return nil
}

// workerLoop runs the main packet processing loop for a worker
func (am *AFXDPManager) workerLoop(worker *AFXDPWorker, processor PacketProcessor) {
	defer am.wg.Done()

	fmt.Printf("AF_XDP: Worker %d started for socket %s:%d\n", 
		worker.ID, worker.Socket.InterfaceName, worker.Socket.QueueID)

	ticker := time.NewTicker(worker.PollTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-am.stopChannel:
			fmt.Printf("AF_XDP: Worker %d stopping\n", worker.ID)
			return
		case <-ticker.C:
			am.processPackets(worker, processor)
		}
	}
}

// processPackets processes a batch of packets from the socket
func (am *AFXDPManager) processPackets(worker *AFXDPWorker, processor PacketProcessor) {
	// Receive packets from AF_XDP socket
	rcvd := C.rx_and_process(worker.Socket.SocketInfo, C.int(worker.BatchSize))
	if rcvd > 0 {
		atomic.AddUint64(&worker.PacketsRx, uint64(rcvd))
		atomic.AddUint64(&worker.Socket.RxPackets, uint64(rcvd))
		worker.Socket.LastActivity = time.Now()

		// In a real implementation, we would extract packet data and process it
		// For now, just update statistics
		atomic.AddUint64(&worker.ProcessedPkts, uint64(rcvd))
	}

	// Transmit any pending packets
	sent := C.tx_packets(worker.Socket.SocketInfo, C.int(worker.BatchSize))
	if sent > 0 {
		atomic.AddUint64(&worker.PacketsTx, uint64(sent))
		atomic.AddUint64(&worker.Socket.TxPackets, uint64(sent))
	}
}

// statsCollector collects and aggregates AF_XDP statistics
func (am *AFXDPManager) statsCollector() {
	defer am.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastRxPackets uint64
	lastUpdate := time.Now()

	for {
		select {
		case <-am.stopChannel:
			return
		case <-ticker.C:
			am.mu.RLock()

			// Aggregate statistics from all sockets
			totalRxPackets := uint64(0)
			totalTxPackets := uint64(0)
			totalDropped := uint64(0)
			totalInvalid := uint64(0)

			for _, socket := range am.sockets {
				totalRxPackets += atomic.LoadUint64(&socket.RxPackets)
				totalTxPackets += atomic.LoadUint64(&socket.TxPackets)
				totalDropped += atomic.LoadUint64(&socket.DroppedPkts)
				totalInvalid += atomic.LoadUint64(&socket.InvalidPkts)
			}

			// Calculate frame rate
			now := time.Now()
			duration := now.Sub(lastUpdate).Seconds()
			if duration > 0 {
				am.stats.FramesPerSecond = uint64(float64(totalRxPackets-lastRxPackets) / duration)
			}

			// Update statistics
			atomic.StoreUint64(&am.stats.TotalRxPackets, totalRxPackets)
			atomic.StoreUint64(&am.stats.TotalTxPackets, totalTxPackets)
			atomic.StoreUint64(&am.stats.TotalDropped, totalDropped)
			atomic.StoreUint64(&am.stats.TotalInvalid, totalInvalid)
			am.stats.LastUpdate = now

			// Update worker utilization
			for i, worker := range am.workerPool {
				if i < len(am.stats.SocketUtilization) {
					packetsProcessed := atomic.LoadUint64(&worker.ProcessedPkts)
					am.stats.SocketUtilization[i] = float64(packetsProcessed) / duration / 1000000.0 // MPPS
				}
			}

			lastRxPackets = totalRxPackets
			lastUpdate = now
			am.mu.RUnlock()
		}
	}
}

// UpdateServices updates service rules for AF_XDP processing
func (am *AFXDPManager) UpdateServices(services []manager.Service) error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if !am.initialized {
		return fmt.Errorf("AF_XDP not initialized")
	}

	fmt.Printf("AF_XDP: Updating service rules for %d services\n", len(services))

	// In a full implementation, this would update filtering rules
	// For now, just log the update
	for _, service := range services {
		fmt.Printf("AF_XDP: Service %d - %s (Auth: %s)\n", 
			service.ID, service.IPFQDN, service.AuthType)
	}

	return nil
}

// Stop stops all workers and cleans up resources
func (am *AFXDPManager) Stop() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.initialized {
		return nil
	}

	fmt.Printf("AF_XDP: Stopping workers and cleaning up\n")

	// Stop all workers
	close(am.stopChannel)
	am.wg.Wait()

	// Cleanup sockets
	for socketKey, socket := range am.sockets {
		C.cleanup_xsk(socket.SocketInfo)
		C.free(socket.Buffer)
		C.free(unsafe.Pointer(socket.UmemInfo))
		C.free(unsafe.Pointer(socket.SocketInfo))
		delete(am.sockets, socketKey)
		fmt.Printf("AF_XDP: Cleaned up socket %s\n", socketKey)
	}

	am.initialized = false
	fmt.Printf("AF_XDP: Cleanup complete\n")
	return nil
}

// GetStats returns current AF_XDP statistics
func (am *AFXDPManager) GetStats() *AFXDPStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := *am.stats
	return &stats
}

// IsEnabled returns whether AF_XDP is enabled and initialized
func (am *AFXDPManager) IsEnabled() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.enabled && am.initialized
}

// GetSocketStats returns statistics for a specific socket
func (am *AFXDPManager) GetSocketStats(interfaceName string, queueID int) (*AFXDPSocket, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	socketKey := fmt.Sprintf("%s:%d", interfaceName, queueID)
	socket, exists := am.sockets[socketKey]
	if !exists {
		return nil, fmt.Errorf("socket not found: %s", socketKey)
	}

	// Create a copy for safe access
	socketCopy := *socket
	return &socketCopy, nil
}

// GetWorkerStats returns statistics for all workers
func (am *AFXDPManager) GetWorkerStats() []*AFXDPWorker {
	am.mu.RLock()
	defer am.mu.RUnlock()

	workers := make([]*AFXDPWorker, len(am.workerPool))
	for i, worker := range am.workerPool {
		workerCopy := *worker
		workers[i] = &workerCopy
	}
	return workers
}

// SetZeroCopyMode enables or disables zero-copy mode
func (am *AFXDPManager) SetZeroCopyMode(enabled bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	am.config.ZeroCopyMode = enabled
	fmt.Printf("AF_XDP: Zero-copy mode %s\n", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// GetActiveInterfaces returns list of interfaces with active AF_XDP sockets
func (am *AFXDPManager) GetActiveInterfaces() []string {
	am.mu.RLock()
	defer am.mu.RUnlock()

	interfaces := make(map[string]bool)
	for _, socket := range am.sockets {
		interfaces[socket.InterfaceName] = true
	}

	result := make([]string, 0, len(interfaces))
	for ifname := range interfaces {
		result = append(result, ifname)
	}
	return result
}