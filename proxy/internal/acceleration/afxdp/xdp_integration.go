package afxdp

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/penguintech/marchproxy/internal/acceleration/xdp"
	"github.com/penguintech/marchproxy/internal/manager"
	"github.com/penguintech/marchproxy/internal/proxy"
)

// XDPAFXDPBridge manages the integration between XDP and AF_XDP
type XDPAFXDPBridge struct {
	interfaceName     string
	numQueues         int
	afxdpSockets      []*AFXDPSocket
	xdpManager        *xdp.XDPManager
	goProxy           *proxy.GoProxy
	config            *BridgeConfig
	stats             *BridgeStats
	enhancedProcessor *EnhancedAFXDPProcessor
	running           bool
	mu                sync.RWMutex
}

// BridgeConfig holds configuration for XDP-AF_XDP bridge
type BridgeConfig struct {
	InterfaceName       string
	NumQueues           int
	AFXDPFrameSize      uint32
	AFXDPFrameCount     uint32
	AFXDPBatchSize      int
	ZeroCopy            bool
	SlowPathThreshold   float64 // Percentage of packets to route to slow path
	StatsInterval       time.Duration
	EnableEnhancedProcessor bool
	ProcessorConfig     *ProcessorConfig
}

// BridgeStats holds statistics for the bridge
type BridgeStats struct {
	TotalPackets     uint64
	FastPathPackets  uint64
	SlowPathPackets  uint64
	DroppedPackets   uint64
	FastPathBytes    uint64
	SlowPathBytes    uint64
	ProcessingTime   time.Duration
	LastUpdate       time.Time
}

// SlowPathPacket represents a packet that needs Go proxy processing
type SlowPathPacket struct {
	Data        []byte
	Length      uint32
	SourceIP    [4]byte
	DestIP      [4]byte
	SourcePort  uint16
	DestPort    uint16
	Protocol    uint8
	ServiceID   uint32
	Timestamp   time.Time
	QueueID     int
	NeedsAuth   bool
	NeedsTLS    bool
	IsWebSocket bool
}

// NewXDPAFXDPBridge creates a new XDP-AF_XDP bridge
func NewXDPAFXDPBridge(config *BridgeConfig) *XDPAFXDPBridge {
	if config == nil {
		config = &BridgeConfig{
			NumQueues:               4,
			AFXDPFrameSize:          2048,
			AFXDPFrameCount:         4096,
			AFXDPBatchSize:          64,
			ZeroCopy:                true,
			SlowPathThreshold:       20.0,
			StatsInterval:           time.Second * 5,
			EnableEnhancedProcessor: true,
		}
	}

	bridge := &XDPAFXDPBridge{
		interfaceName: config.InterfaceName,
		numQueues:     config.NumQueues,
		config:        config,
		stats:         &BridgeStats{LastUpdate: time.Now()},
	}

	// Initialize enhanced processor if enabled
	if config.EnableEnhancedProcessor {
		bridge.enhancedProcessor = NewEnhancedAFXDPProcessor(config.ProcessorConfig)
	}

	return bridge
}

// Initialize sets up XDP, AF_XDP sockets, and Go proxy integration
func (bridge *XDPAFXDPBridge) Initialize(xdpMgr *xdp.XDPManager, goProxy *proxy.GoProxy) error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()

	bridge.xdpManager = xdpMgr
	bridge.goProxy = goProxy

	// Initialize AF_XDP sockets for each queue
	bridge.afxdpSockets = make([]*AFXDPSocket, bridge.numQueues)

	for i := 0; i < bridge.numQueues; i++ {
		afxdpConfig := &AFXDPConfig{
			InterfaceName: bridge.interfaceName,
			QueueID:      i,
			FrameSize:    bridge.config.AFXDPFrameSize,
			FrameCount:   bridge.config.AFXDPFrameCount,
			BatchSize:    bridge.config.AFXDPBatchSize,
			ZeroCopy:     bridge.config.ZeroCopy,
			WakeupFlag:   true,
			PollTimeout:  time.Millisecond,
		}

		socket, err := NewAFXDPSocket(afxdpConfig)
		if err != nil {
			return fmt.Errorf("failed to create AF_XDP socket for queue %d: %w", i, err)
		}

		if err := socket.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize AF_XDP socket for queue %d: %w", i, err)
		}

		bridge.afxdpSockets[i] = socket
	}

	// Configure XDP to redirect slow-path packets to AF_XDP
	if err := bridge.configureXDPRedirection(); err != nil {
		return fmt.Errorf("failed to configure XDP redirection: %w", err)
	}

	log.Printf("XDP-AF_XDP Bridge: Initialized with %d queues on %s",
		bridge.numQueues, bridge.interfaceName)
	return nil
}

// configureXDPRedirection configures XDP to redirect packets to AF_XDP
func (bridge *XDPAFXDPBridge) configureXDPRedirection() error {
	// Update XDP program to redirect slow-path packets to AF_XDP sockets
	// This involves modifying the XDP BPF map to include AF_XDP queue information

	redirectMap := make(map[uint32]uint32)
	for i := 0; i < bridge.numQueues; i++ {
		redirectMap[uint32(i)] = uint32(i) // Map queue ID to AF_XDP socket
	}

	return bridge.xdpManager.UpdateRedirectMap(redirectMap)
}

// Start begins packet processing
func (bridge *XDPAFXDPBridge) Start() error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()

	if bridge.running {
		return fmt.Errorf("bridge already running")
	}

	// Start AF_XDP sockets
	for i, socket := range bridge.afxdpSockets {
		queueID := i
		handler := func(packet *XDPPacket) bool {
			return bridge.handleSlowPathPacket(packet, queueID)
		}

		if err := socket.Start(handler); err != nil {
			return fmt.Errorf("failed to start AF_XDP socket %d: %w", i, err)
		}
	}

	bridge.running = true

	// Start statistics collection
	go bridge.statsCollector()

	log.Printf("XDP-AF_XDP Bridge: Started processing")
	return nil
}

// handleSlowPathPacket processes packets that XDP couldn't handle
func (bridge *XDPAFXDPBridge) handleSlowPathPacket(packet *XDPPacket, queueID int) bool {
	startTime := time.Now()

	// Use enhanced processor if available
	if bridge.enhancedProcessor != nil {
		decision := bridge.enhancedProcessor.ProcessPacket(packet)

		switch decision.Action {
		case ActionPass:
			// Packet can be passed through without Go proxy
			atomic.AddUint64(&bridge.stats.FastPathPackets, 1)
			return true

		case ActionDrop:
			// Packet should be dropped
			atomic.AddUint64(&bridge.stats.DroppedPackets, 1)
			return false

		case ActionRedirectGo:
			// Packet needs Go proxy processing - continue with original logic
			break

		case ActionRateLimit:
			// Rate limited
			atomic.AddUint64(&bridge.stats.DroppedPackets, 1)
			return false
		}
	}

	// Parse packet to determine processing requirements
	slowPacket, err := bridge.parseSlowPathPacket(packet, queueID)
	if err != nil {
		atomic.AddUint64(&bridge.stats.DroppedPackets, 1)
		return false
	}

	// Update statistics
	atomic.AddUint64(&bridge.stats.SlowPathPackets, 1)
	atomic.AddUint64(&bridge.stats.SlowPathBytes, uint64(packet.Length))

	// Route to appropriate Go proxy handler
	success := bridge.routeToGoProxy(slowPacket)

	// Update processing time (simplified approach)
	processingTime := time.Since(startTime)
	bridge.stats.ProcessingTime = processingTime

	return success
}

// parseSlowPathPacket parses a packet to extract metadata for Go proxy
func (bridge *XDPAFXDPBridge) parseSlowPathPacket(packet *XDPPacket, queueID int) (*SlowPathPacket, error) {
	if len(packet.Data) < 20 { // Minimum IP header size
		return nil, fmt.Errorf("packet too small")
	}

	slowPacket := &SlowPathPacket{
		Data:      make([]byte, len(packet.Data)),
		Length:    packet.Length,
		Timestamp: packet.Timestamp,
		QueueID:   queueID,
	}

	copy(slowPacket.Data, packet.Data)

	// Parse IP header
	ipHeader := packet.Data[0:20]
	version := (ipHeader[0] >> 4) & 0xF
	if version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}

	// Extract IP addresses
	copy(slowPacket.SourceIP[:], ipHeader[12:16])
	copy(slowPacket.DestIP[:], ipHeader[16:20])
	slowPacket.Protocol = ipHeader[9]

	// Parse transport layer if TCP/UDP
	headerLen := int(ipHeader[0]&0xF) * 4
	if len(packet.Data) > headerLen+4 {
		switch slowPacket.Protocol {
		case 6: // TCP
			tcpHeader := packet.Data[headerLen:]
			slowPacket.SourcePort = uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])
			slowPacket.DestPort = uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])

			// Check for TLS/HTTP/WebSocket indicators
			bridge.analyzeApplicationLayer(slowPacket, packet.Data[headerLen:])

		case 17: // UDP
			udpHeader := packet.Data[headerLen:]
			slowPacket.SourcePort = uint16(udpHeader[0])<<8 | uint16(udpHeader[1])
			slowPacket.DestPort = uint16(udpHeader[2])<<8 | uint16(udpHeader[3])
		}
	}

	// Determine service and processing requirements
	bridge.classifyPacket(slowPacket)

	return slowPacket, nil
}

// analyzeApplicationLayer analyzes packet content for TLS/HTTP/WebSocket
func (bridge *XDPAFXDPBridge) analyzeApplicationLayer(packet *SlowPathPacket, payload []byte) {
	if len(payload) < 20 { // Minimum TCP header
		return
	}

	tcpHeaderLen := int(payload[12]>>4) * 4
	if len(payload) <= tcpHeaderLen {
		return
	}

	appData := payload[tcpHeaderLen:]
	if len(appData) < 5 {
		return
	}

	// Check for TLS handshake
	if appData[0] == 0x16 && appData[1] == 0x03 {
		packet.NeedsTLS = true
	}

	// Check for HTTP
	if len(appData) >= 4 {
		httpMethods := []string{"GET ", "POST", "PUT ", "DEL ", "HEAD", "OPTI"}
		appDataStr := string(appData[:min(len(appData), 8)])
		for _, method := range httpMethods {
			if len(appDataStr) >= len(method) && appDataStr[:len(method)] == method {
				// Check for WebSocket upgrade
				if len(appData) > 100 {
					fullData := string(appData[:min(len(appData), 500)])
					if containsIgnoreCase(fullData, "upgrade: websocket") {
						packet.IsWebSocket = true
					}
				}
				break
			}
		}
	}
}

// classifyPacket determines service and processing requirements
func (bridge *XDPAFXDPBridge) classifyPacket(packet *SlowPathPacket) {
	// Look up service based on destination IP/port
	// This would integrate with the manager's service registry
	destIP := fmt.Sprintf("%d.%d.%d.%d",
		packet.DestIP[0], packet.DestIP[1], packet.DestIP[2], packet.DestIP[3])

	// Simplified service lookup (would be replaced with actual service registry)
	service := bridge.lookupService(destIP, packet.DestPort)
	if service != nil {
		packet.ServiceID = uint32(service.ID)
		packet.NeedsAuth = service.AuthType != "none"
	}
}

// lookupService looks up a service by IP and port (placeholder)
func (bridge *XDPAFXDPBridge) lookupService(ip string, port uint16) *manager.Service {
	// This would integrate with the actual service registry
	// For now, return nil (service lookup would be implemented)
	return nil
}

// routeToGoProxy routes the packet to the appropriate Go proxy handler
func (bridge *XDPAFXDPBridge) routeToGoProxy(packet *SlowPathPacket) bool {
	if bridge.goProxy == nil {
		return false
	}

	// Convert to Go proxy packet format
	proxyPacket := &proxy.Packet{
		Data:        packet.Data,
		Length:      int(packet.Length),
		SourceIP:    packet.SourceIP[:],
		DestIP:      packet.DestIP[:],
		SourcePort:  packet.SourcePort,
		DestPort:    packet.DestPort,
		Protocol:    packet.Protocol,
		ServiceID:   packet.ServiceID,
		Timestamp:   packet.Timestamp,
		NeedsAuth:   packet.NeedsAuth,
		NeedsTLS:    packet.NeedsTLS,
		IsWebSocket: packet.IsWebSocket,
	}

	// Route based on packet type
	switch {
	case packet.IsWebSocket:
		return bridge.goProxy.HandleWebSocketPacket(proxyPacket)
	case packet.NeedsTLS:
		return bridge.goProxy.HandleTLSPacket(proxyPacket)
	case packet.Protocol == 6: // TCP
		return bridge.goProxy.HandleTCPPacket(proxyPacket)
	case packet.Protocol == 17: // UDP
		return bridge.goProxy.HandleUDPPacket(proxyPacket)
	case packet.Protocol == 1: // ICMP
		return bridge.goProxy.HandleICMPPacket(proxyPacket)
	default:
		return bridge.goProxy.HandleGenericPacket(proxyPacket)
	}
}

// statsCollector collects and updates statistics
func (bridge *XDPAFXDPBridge) statsCollector() {
	ticker := time.NewTicker(bridge.config.StatsInterval)
	defer ticker.Stop()

	for bridge.running {
		select {
		case <-ticker.C:
			bridge.updateStats()
		}
	}
}

// updateStats updates bridge statistics
func (bridge *XDPAFXDPBridge) updateStats() {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()

	// Collect AF_XDP socket statistics
	totalRx := uint64(0)
	totalTx := uint64(0)
	totalRxBytes := uint64(0)
	totalTxBytes := uint64(0)

	for _, socket := range bridge.afxdpSockets {
		stats := socket.GetStats()
		totalRx += stats.RxPackets
		totalTx += stats.TxPackets
		totalRxBytes += stats.RxBytes
		totalTxBytes += stats.TxBytes
	}

	// Update bridge statistics
	bridge.stats.TotalPackets = totalRx
	bridge.stats.LastUpdate = time.Now()

	// Calculate fast path vs slow path ratio
	if bridge.xdpManager != nil {
		xdpStats := bridge.xdpManager.GetStats()
		bridge.stats.FastPathPackets = xdpStats.PassedPackets
		bridge.stats.FastPathBytes = xdpStats.TotalBytes
	}

	// Log statistics periodically
	if time.Since(bridge.stats.LastUpdate) > time.Minute {
		bridge.logStats()
	}
}

// logStats logs current statistics
func (bridge *XDPAFXDPBridge) logStats() {
	total := bridge.stats.FastPathPackets + bridge.stats.SlowPathPackets
	if total > 0 {
		fastPathPercentage := float64(bridge.stats.FastPathPackets) / float64(total) * 100
		slowPathPercentage := float64(bridge.stats.SlowPathPackets) / float64(total) * 100

		log.Printf("XDP-AF_XDP Bridge Stats: Total=%d, Fast=%.1f%%, Slow=%.1f%%, Dropped=%d",
			total, fastPathPercentage, slowPathPercentage, bridge.stats.DroppedPackets)
	}
}

// GetStats returns current bridge statistics
func (bridge *XDPAFXDPBridge) GetStats() *BridgeStats {
	bridge.mu.RLock()
	defer bridge.mu.RUnlock()

	stats := *bridge.stats
	return &stats
}

// Stop stops the bridge and all AF_XDP sockets
func (bridge *XDPAFXDPBridge) Stop() error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()

	if !bridge.running {
		return nil
	}

	bridge.running = false

	// Stop all AF_XDP sockets
	for i, socket := range bridge.afxdpSockets {
		if err := socket.Stop(); err != nil {
			log.Printf("Error stopping AF_XDP socket %d: %v", i, err)
		}
	}

	log.Printf("XDP-AF_XDP Bridge: Stopped")
	return nil
}

// IsRunning returns whether the bridge is running
func (bridge *XDPAFXDPBridge) IsRunning() bool {
	bridge.mu.RLock()
	defer bridge.mu.RUnlock()
	return bridge.running
}

// Helper functions moved to enhanced_processor.go to avoid duplication

func containsIgnoreCase(s, substr string) bool {
	// Simple case-insensitive search
	sLower := strings.ToLower(s)
	substrLower := strings.ToLower(substr)
	return strings.Contains(sLower, substrLower)
}