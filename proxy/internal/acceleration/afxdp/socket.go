// +build afxdp

package afxdp

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AFXDPSocket represents an AF_XDP socket for zero-copy packet processing
type AFXDPSocket struct {
	fd           int
	interfaceName string
	queueID      int
	config       *AFXDPConfig

	// UMEM (User Memory) configuration
	umem         *UMEM
	frameSize    uint32
	frameCount   uint32

	// Ring buffers
	rxRing       *RxRing
	txRing       *TxRing
	fillRing     *FillRing
	compRing     *CompRing

	// Statistics
	stats        *AFXDPStats

	// Control
	running      bool
	mu           sync.RWMutex

	// Packet handler
	packetHandler PacketHandler
}

// AFXDPConfig holds AF_XDP socket configuration
type AFXDPConfig struct {
	InterfaceName  string
	QueueID        int
	FrameSize      uint32
	FrameCount     uint32
	Mode           AFXDPMode
	Flags          uint32
	BatchSize      int
	PollTimeout    time.Duration
	ZeroCopy       bool
	WakeupFlag     bool
}

// AFXDPMode represents AF_XDP socket mode
type AFXDPMode int

const (
	ModeZeroCopy AFXDPMode = iota
	ModeCopy
	ModeSkb
)

// UMEM represents User Memory area for packet buffers
type UMEM struct {
	memory       []byte
	size         uint64
	frameSize    uint32
	frameCount   uint32
	headroom     uint32
	freeFrames   chan uint64
	usedFrames   map[uint64]bool
	mu           sync.Mutex
}

// Ring buffer structures
type RxRing struct {
	producer uint32
	consumer uint32
	size     uint32
	mask     uint32
	ring     unsafe.Pointer
}

type TxRing struct {
	producer uint32
	consumer uint32
	size     uint32
	mask     uint32
	ring     unsafe.Pointer
}

type FillRing struct {
	producer uint32
	consumer uint32
	size     uint32
	mask     uint32
	ring     unsafe.Pointer
}

type CompRing struct {
	producer uint32
	consumer uint32
	size     uint32
	mask     uint32
	ring     unsafe.Pointer
}

// AFXDPStats holds AF_XDP socket statistics
type AFXDPStats struct {
	RxPackets      uint64
	TxPackets      uint64
	RxBytes        uint64
	TxBytes        uint64
	RxDropped      uint64
	TxDropped      uint64
	RxInvalid      uint64
	TxInvalid      uint64
	RxRingFull     uint64
	FillRingEmpty  uint64
	TxRingEmpty    uint64
	CompRingFull   uint64
	LastUpdate     time.Time
}

// XDPPacket represents a packet received through AF_XDP
type XDPPacket struct {
	Data      []byte
	Length    uint32
	Addr      uint64
	Timestamp time.Time
	QueueID   int
}

// PacketHandler is called for each received packet
type PacketHandler func(*XDPPacket) bool

// XDP socket option constants
const (
	XDP_STATISTICS       = 7
	XDP_OPTIONS         = 8
	XDP_UMEM_REG        = 4
	XDP_UMEM_FILL_RING  = 5
	XDP_UMEM_COMPLETION_RING = 6
	XDP_RX_RING         = 2
	XDP_TX_RING         = 3

	XDP_COPY            = 1 << 1
	XDP_ZEROCOPY        = 1 << 2
	XDP_USE_NEED_WAKEUP = 1 << 3

	XDP_RING_NEED_WAKEUP = 1 << 0
)

// NewAFXDPSocket creates a new AF_XDP socket
func NewAFXDPSocket(config *AFXDPConfig) (*AFXDPSocket, error) {
	if config == nil {
		return nil, fmt.Errorf("AF_XDP config is required")
	}

	// Set defaults
	if config.FrameSize == 0 {
		config.FrameSize = 2048
	}
	if config.FrameCount == 0 {
		config.FrameCount = 4096
	}
	if config.BatchSize == 0 {
		config.BatchSize = 64
	}
	if config.PollTimeout == 0 {
		config.PollTimeout = time.Millisecond
	}

	socket := &AFXDPSocket{
		interfaceName: config.InterfaceName,
		queueID:      config.QueueID,
		config:       config,
		frameSize:    config.FrameSize,
		frameCount:   config.FrameCount,
		stats:        &AFXDPStats{LastUpdate: time.Now()},
	}

	return socket, nil
}

// Initialize sets up the AF_XDP socket and rings
func (s *AFXDPSocket) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create AF_XDP socket
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("failed to create AF_XDP socket: %w", err)
	}
	s.fd = fd

	// Setup UMEM
	if err := s.setupUMEM(); err != nil {
		unix.Close(s.fd)
		return fmt.Errorf("failed to setup UMEM: %w", err)
	}

	// Setup rings
	if err := s.setupRings(); err != nil {
		unix.Close(s.fd)
		return fmt.Errorf("failed to setup rings: %w", err)
	}

	// Bind socket to interface and queue
	if err := s.bindSocket(); err != nil {
		unix.Close(s.fd)
		return fmt.Errorf("failed to bind socket: %w", err)
	}

	fmt.Printf("AF_XDP: Initialized socket on %s queue %d\n",
		s.interfaceName, s.queueID)
	return nil
}

// setupUMEM allocates and registers user memory
func (s *AFXDPSocket) setupUMEM() error {
	// Calculate total memory size
	totalSize := uint64(s.frameSize) * uint64(s.frameCount)

	// Allocate memory (page-aligned)
	pageSize := uint64(syscall.Getpagesize())
	alignedSize := (totalSize + pageSize - 1) &^ (pageSize - 1)

	memory, err := unix.Mmap(-1, 0, int(alignedSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("failed to mmap UMEM: %w", err)
	}

	// Create UMEM structure
	s.umem = &UMEM{
		memory:     memory,
		size:       alignedSize,
		frameSize:  s.frameSize,
		frameCount: s.frameCount,
		headroom:   0,
		freeFrames: make(chan uint64, s.frameCount),
		usedFrames: make(map[uint64]bool),
	}

	// Initialize free frame queue
	for i := uint32(0); i < s.frameCount; i++ {
		s.umem.freeFrames <- uint64(i) * uint64(s.frameSize)
	}

	// Register UMEM with kernel
	umemReg := struct {
		addr       uint64
		len        uint64
		chunkSize  uint32
		headroom   uint32
		flags      uint32
	}{
		addr:      uint64(uintptr(unsafe.Pointer(&memory[0]))),
		len:       alignedSize,
		chunkSize: s.frameSize,
		headroom:  0,
		flags:     0,
	}

	if err := s.setsockopt(XDP_UMEM_REG, unsafe.Pointer(&umemReg),
		unsafe.Sizeof(umemReg)); err != nil {
		unix.Munmap(memory)
		return fmt.Errorf("failed to register UMEM: %w", err)
	}

	return nil
}

// setupRings creates and configures the ring buffers
func (s *AFXDPSocket) setupRings() error {
	ringSize := uint32(2048) // Power of 2

	// Setup Fill Ring
	if err := s.setupFillRing(ringSize); err != nil {
		return fmt.Errorf("failed to setup fill ring: %w", err)
	}

	// Setup Completion Ring
	if err := s.setupCompRing(ringSize); err != nil {
		return fmt.Errorf("failed to setup completion ring: %w", err)
	}

	// Setup RX Ring
	if err := s.setupRxRing(ringSize); err != nil {
		return fmt.Errorf("failed to setup RX ring: %w", err)
	}

	// Setup TX Ring
	if err := s.setupTxRing(ringSize); err != nil {
		return fmt.Errorf("failed to setup TX ring: %w", err)
	}

	return nil
}

// setupFillRing configures the fill ring
func (s *AFXDPSocket) setupFillRing(size uint32) error {
	fillRingReq := struct {
		size uint32
	}{size: size}

	if err := s.setsockopt(XDP_UMEM_FILL_RING, unsafe.Pointer(&fillRingReq),
		unsafe.Sizeof(fillRingReq)); err != nil {
		return err
	}

	// Map the ring
	ringOffset := struct {
		producer uint64
		consumer uint64
		desc     uint64
		flags    uint64
	}{}

	if err := s.getsockopt(XDP_UMEM_FILL_RING, unsafe.Pointer(&ringOffset),
		unsafe.Sizeof(ringOffset)); err != nil {
		return err
	}

	s.fillRing = &FillRing{
		size: size,
		mask: size - 1,
	}

	return nil
}

// setupCompRing configures the completion ring
func (s *AFXDPSocket) setupCompRing(size uint32) error {
	compRingReq := struct {
		size uint32
	}{size: size}

	if err := s.setsockopt(XDP_UMEM_COMPLETION_RING, unsafe.Pointer(&compRingReq),
		unsafe.Sizeof(compRingReq)); err != nil {
		return err
	}

	s.compRing = &CompRing{
		size: size,
		mask: size - 1,
	}

	return nil
}

// setupRxRing configures the receive ring
func (s *AFXDPSocket) setupRxRing(size uint32) error {
	rxRingReq := struct {
		size uint32
	}{size: size}

	if err := s.setsockopt(XDP_RX_RING, unsafe.Pointer(&rxRingReq),
		unsafe.Sizeof(rxRingReq)); err != nil {
		return err
	}

	s.rxRing = &RxRing{
		size: size,
		mask: size - 1,
	}

	return nil
}

// setupTxRing configures the transmit ring
func (s *AFXDPSocket) setupTxRing(size uint32) error {
	txRingReq := struct {
		size uint32
	}{size: size}

	if err := s.setsockopt(XDP_TX_RING, unsafe.Pointer(&txRingReq),
		unsafe.Sizeof(txRingReq)); err != nil {
		return err
	}

	s.txRing = &TxRing{
		size: size,
		mask: size - 1,
	}

	return nil
}

// bindSocket binds the socket to network interface and queue
func (s *AFXDPSocket) bindSocket() error {
	// Get interface index
	iface, err := net.InterfaceByName(s.interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", s.interfaceName, err)
	}

	// Bind to interface and queue
	bindReq := struct {
		family   uint16
		ifindex  uint32
		queueID  uint32
		flags    uint32
	}{
		family:  unix.AF_XDP,
		ifindex: uint32(iface.Index),
		queueID: uint32(s.queueID),
		flags:   s.config.Flags,
	}

	if s.config.ZeroCopy {
		bindReq.flags |= XDP_ZEROCOPY
	} else {
		bindReq.flags |= XDP_COPY
	}

	if s.config.WakeupFlag {
		bindReq.flags |= XDP_USE_NEED_WAKEUP
	}

	if err := unix.Bind(s.fd, (*unix.RawSockaddr)(unsafe.Pointer(&bindReq)),
		uint32(unsafe.Sizeof(bindReq))); err != nil {
		return fmt.Errorf("failed to bind AF_XDP socket: %w", err)
	}

	return nil
}

// Start begins packet processing
func (s *AFXDPSocket) Start(handler PacketHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("AF_XDP socket already running")
	}

	s.packetHandler = handler
	s.running = true

	// Pre-populate fill ring
	if err := s.populateFillRing(); err != nil {
		return fmt.Errorf("failed to populate fill ring: %w", err)
	}

	// Start processing goroutine
	go s.processPackets()

	fmt.Printf("AF_XDP: Started processing on %s queue %d\n",
		s.interfaceName, s.queueID)
	return nil
}

// populateFillRing fills the fill ring with available frame addresses
func (s *AFXDPSocket) populateFillRing() error {
	// Fill the ring with available frames
	available := len(s.umem.freeFrames)
	for i := 0; i < available && i < int(s.fillRing.size); i++ {
		select {
		case addr := <-s.umem.freeFrames:
			// Add frame address to fill ring
			s.addToFillRing(addr)
		default:
			break
		}
	}

	// Notify kernel about new frames
	s.kickFillRing()
	return nil
}

// processPackets is the main packet processing loop
func (s *AFXDPSocket) processPackets() {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	// Set up polling
	pollFds := []unix.PollFd{
		{Fd: int32(s.fd), Events: unix.POLLIN},
	}

	for s.running {
		// Poll for events
		n, err := unix.Poll(pollFds, int(s.config.PollTimeout.Milliseconds()))
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			fmt.Printf("AF_XDP: Poll error: %v\n", err)
			continue
		}

		if n > 0 && (pollFds[0].Revents&unix.POLLIN) != 0 {
			// Process received packets
			s.processRxPackets()
		}

		// Process completion ring
		s.processCompletionRing()

		// Refill if needed
		s.refillIfNeeded()
	}
}

// processRxPackets processes packets from the RX ring
func (s *AFXDPSocket) processRxPackets() {
	processed := 0
	maxBatch := s.config.BatchSize

	for processed < maxBatch {
		// Check if packet is available
		if !s.rxPacketAvailable() {
			break
		}

		// Get packet from RX ring
		packet := s.getRxPacket()
		if packet == nil {
			break
		}

		// Update statistics
		atomic.AddUint64(&s.stats.RxPackets, 1)
		atomic.AddUint64(&s.stats.RxBytes, uint64(packet.Length))

		// Call packet handler
		if s.packetHandler != nil {
			handled := s.packetHandler(packet)
			if !handled {
				atomic.AddUint64(&s.stats.RxDropped, 1)
			}
		}

		// Mark frame as processed
		s.markFrameProcessed(packet.Addr)
		processed++
	}

	if processed > 0 {
		// Update RX ring consumer pointer
		s.updateRxConsumer(uint32(processed))
	}
}

// rxPacketAvailable checks if a packet is available in RX ring
func (s *AFXDPSocket) rxPacketAvailable() bool {
	return s.rxRing.consumer != s.rxRing.producer
}

// getRxPacket retrieves a packet from the RX ring
func (s *AFXDPSocket) getRxPacket() *XDPPacket {
	// Get descriptor from RX ring
	idx := s.rxRing.consumer & s.rxRing.mask

	// Read descriptor (simplified - actual implementation would read from mmaped ring)
	// This is a placeholder for the actual ring buffer access
	desc := s.readRxDescriptor(idx)
	if desc == nil {
		return nil
	}

	// Create packet from descriptor
	packet := &XDPPacket{
		Data:      s.getFrameData(desc.addr, desc.len),
		Length:    desc.len,
		Addr:      desc.addr,
		Timestamp: time.Now(),
		QueueID:   s.queueID,
	}

	return packet
}

// RxDescriptor represents an RX ring descriptor
type RxDescriptor struct {
	addr uint64
	len  uint32
}

// readRxDescriptor reads a descriptor from the RX ring (placeholder)
func (s *AFXDPSocket) readRxDescriptor(idx uint32) *RxDescriptor {
	// Actual implementation would read from mmaped ring buffer
	// This is simplified for demonstration
	return &RxDescriptor{
		addr: uint64(idx) * uint64(s.frameSize),
		len:  s.frameSize,
	}
}

// getFrameData returns a slice pointing to frame data
func (s *AFXDPSocket) getFrameData(addr uint64, length uint32) []byte {
	if addr >= uint64(len(s.umem.memory)) {
		return nil
	}

	start := int(addr)
	end := start + int(length)
	if end > len(s.umem.memory) {
		end = len(s.umem.memory)
	}

	return s.umem.memory[start:end]
}

// markFrameProcessed marks a frame as processed and available for reuse
func (s *AFXDPSocket) markFrameProcessed(addr uint64) {
	s.umem.mu.Lock()
	defer s.umem.mu.Unlock()

	delete(s.umem.usedFrames, addr)
	select {
	case s.umem.freeFrames <- addr:
	default:
		// Free frames channel full, drop frame
		atomic.AddUint64(&s.stats.RxDropped, 1)
	}
}

// updateRxConsumer updates the RX ring consumer pointer
func (s *AFXDPSocket) updateRxConsumer(count uint32) {
	s.rxRing.consumer += count
	// Actual implementation would update the mmaped ring consumer pointer
}

// processCompletionRing processes completed TX frames
func (s *AFXDPSocket) processCompletionRing() {
	// Process completed TX frames and return them to free pool
	// Simplified implementation
	for s.compRing.consumer != s.compRing.producer {
		idx := s.compRing.consumer & s.compRing.mask

		// Get completed frame address
		addr := s.readCompDescriptor(idx)
		if addr != 0 {
			s.markFrameProcessed(addr)
		}

		s.compRing.consumer++
	}
}

// readCompDescriptor reads a completion descriptor (placeholder)
func (s *AFXDPSocket) readCompDescriptor(idx uint32) uint64 {
	// Actual implementation would read from mmaped completion ring
	return 0
}

// addToFillRing adds a frame address to the fill ring
func (s *AFXDPSocket) addToFillRing(addr uint64) {
	idx := s.fillRing.producer & s.fillRing.mask
	// Actual implementation would write to mmaped fill ring
	s.writeFillDescriptor(idx, addr)
	s.fillRing.producer++
}

// writeFillDescriptor writes to the fill ring (placeholder)
func (s *AFXDPSocket) writeFillDescriptor(idx uint32, addr uint64) {
	// Actual implementation would write to mmaped ring buffer
}

// kickFillRing notifies kernel about new fill ring entries
func (s *AFXDPSocket) kickFillRing() {
	// Send notification to kernel if needed
	if s.config.WakeupFlag {
		unix.Write(s.fd, []byte{0})
	}
}

// refillIfNeeded refills the fill ring if running low
func (s *AFXDPSocket) refillIfNeeded() {
	available := len(s.umem.freeFrames)
	fillLevel := s.fillRing.producer - s.fillRing.consumer

	if available > 0 && fillLevel < s.fillRing.size/2 {
		s.populateFillRing()
	}
}

// SendPacket sends a packet through the TX ring
func (s *AFXDPSocket) SendPacket(data []byte) error {
	if len(data) > int(s.frameSize) {
		return fmt.Errorf("packet too large: %d > %d", len(data), s.frameSize)
	}

	// Get free frame
	select {
	case addr := <-s.umem.freeFrames:
		// Copy data to frame
		frameData := s.getFrameData(addr, uint32(len(data)))
		copy(frameData, data)

		// Add to TX ring
		if err := s.addToTxRing(addr, uint32(len(data))); err != nil {
			// Return frame to free pool
			s.umem.freeFrames <- addr
			return err
		}

		// Update statistics
		atomic.AddUint64(&s.stats.TxPackets, 1)
		atomic.AddUint64(&s.stats.TxBytes, uint64(len(data)))

		return nil
	default:
		atomic.AddUint64(&s.stats.TxDropped, 1)
		return fmt.Errorf("no free frames available")
	}
}

// addToTxRing adds a packet to the TX ring
func (s *AFXDPSocket) addToTxRing(addr uint64, length uint32) error {
	if s.txRing.producer-s.txRing.consumer >= s.txRing.size {
		return fmt.Errorf("TX ring full")
	}

	idx := s.txRing.producer & s.txRing.mask
	s.writeTxDescriptor(idx, addr, length)
	s.txRing.producer++

	// Kick TX ring
	s.kickTxRing()
	return nil
}

// writeTxDescriptor writes to the TX ring (placeholder)
func (s *AFXDPSocket) writeTxDescriptor(idx uint32, addr uint64, length uint32) {
	// Actual implementation would write to mmaped TX ring
}

// kickTxRing notifies kernel about new TX ring entries
func (s *AFXDPSocket) kickTxRing() {
	if s.config.WakeupFlag {
		unix.Write(s.fd, []byte{1})
	}
}

// GetStats returns current AF_XDP statistics
func (s *AFXDPSocket) GetStats() *AFXDPStats {
	stats := *s.stats
	stats.LastUpdate = time.Now()
	return &stats
}

// Stop stops the AF_XDP socket
func (s *AFXDPSocket) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false

	// Close socket
	if s.fd >= 0 {
		unix.Close(s.fd)
		s.fd = -1
	}

	// Cleanup UMEM
	if s.umem != nil && len(s.umem.memory) > 0 {
		unix.Munmap(s.umem.memory)
	}

	fmt.Printf("AF_XDP: Stopped socket on %s queue %d\n",
		s.interfaceName, s.queueID)
	return nil
}

// Helper functions for socket options
func (s *AFXDPSocket) setsockopt(optname int, optval unsafe.Pointer, optlen uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s.fd),
		uintptr(unix.SOL_XDP), uintptr(optname), uintptr(optval), optlen, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (s *AFXDPSocket) getsockopt(optname int, optval unsafe.Pointer, optlen uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s.fd),
		uintptr(unix.SOL_XDP), uintptr(optname), uintptr(optval),
		uintptr(unsafe.Pointer(&optlen)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// IsRunning returns whether the socket is running
func (s *AFXDPSocket) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetFrameSize returns the configured frame size
func (s *AFXDPSocket) GetFrameSize() uint32 {
	return s.frameSize
}

// GetFrameCount returns the configured frame count
func (s *AFXDPSocket) GetFrameCount() uint32 {
	return s.frameCount
}