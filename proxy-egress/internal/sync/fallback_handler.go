package sync

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"marchproxy-egress/internal/auth"
	"marchproxy-egress/internal/manager"
)

// FallbackHandler processes packets that XDP cannot handle in fast-path
type FallbackHandler struct {
	ruleSyncer    *RuleSynchronizer
	authenticator *auth.Authenticator
	managerClient *manager.Client

	// Active connections requiring slow-path processing
	activeConnections map[string]*SlowPathConnection
	connectionMu      sync.RWMutex

	// Performance tracking
	stats *FallbackStats
}

// SlowPathConnection represents a connection that requires Go proxy processing
type SlowPathConnection struct {
	ID            string
	SourceIP      net.IP
	SourcePort    uint16
	DestIP        net.IP
	DestPort      uint16
	Protocol      uint8
	ServiceID     uint32
	Rule          *SlowPathRule
	CreatedAt     time.Time
	LastActivity  time.Time
	PacketCount   uint64
	ByteCount     uint64
	Authenticated bool
	AuthToken     string
}

// FallbackStats tracks slow-path processing performance
type FallbackStats struct {
	TotalConnections     uint64
	AuthenticatedConns   uint64
	FailedAuthentication uint64
	TLSConnections      uint64
	WebSocketUpgrades   uint64
	ComplexRouting      uint64
	AverageProcessTime  time.Duration
	mu                  sync.RWMutex
}

// NewFallbackHandler creates a new fallback handler
func NewFallbackHandler(ruleSyncer *RuleSynchronizer, authenticator *auth.Authenticator, client *manager.Client) *FallbackHandler {
	return &FallbackHandler{
		ruleSyncer:        ruleSyncer,
		authenticator:     authenticator,
		managerClient:     client,
		activeConnections: make(map[string]*SlowPathConnection),
		stats:            &FallbackStats{},
	}
}

// ProcessPacket handles packets that XDP passed to userspace for complex processing
func (fh *FallbackHandler) ProcessPacket(ctx context.Context, packet *PacketInfo) (*ProcessingResult, error) {
	startTime := time.Now()
	defer func() {
		fh.updateProcessingTime(time.Since(startTime))
	}()

	// Generate connection ID
	connID := fh.generateConnectionID(packet)

	// Get or create connection state
	conn := fh.getOrCreateConnection(connID, packet)
	if conn == nil {
		return &ProcessingResult{Action: "drop", Reason: "failed to create connection"}, nil
	}

	// Update connection activity
	fh.updateConnectionActivity(conn, packet)

	// Find the slow-path rule for this connection
	rule := fh.findSlowPathRule(conn.ServiceID)
	if rule == nil {
		log.Printf("No slow-path rule found for service %d", conn.ServiceID)
		return &ProcessingResult{Action: "drop", Reason: "no rule found"}, nil
	}

	// Process based on rule requirements
	result, err := fh.processBasedOnRule(ctx, conn, rule, packet)
	if err != nil {
		return &ProcessingResult{Action: "drop", Reason: fmt.Sprintf("processing error: %v", err)}, err
	}

	return result, nil
}

// processBasedOnRule applies the appropriate processing based on the slow-path rule
func (fh *FallbackHandler) processBasedOnRule(ctx context.Context, conn *SlowPathConnection, rule *SlowPathRule, packet *PacketInfo) (*ProcessingResult, error) {
	// 1. Authentication processing
	if rule.RequiresAuth && !conn.Authenticated {
		result, err := fh.processAuthentication(conn, rule, packet)
		if err != nil || result.Action == "drop" {
			fh.stats.incrementFailedAuth()
			return result, err
		}
		fh.stats.incrementAuthenticatedConns()
	}

	// 2. TLS processing
	if rule.HasTLS {
		result, err := fh.processTLS(conn, packet)
		if err != nil {
			return &ProcessingResult{Action: "drop", Reason: fmt.Sprintf("TLS error: %v", err)}, err
		}
		if result.Action != "continue" {
			fh.stats.incrementTLSConns()
			return result, nil
		}
	}

	// 3. WebSocket upgrade processing
	if rule.HasWebSocket && fh.isWebSocketUpgrade(packet) {
		result, err := fh.processWebSocketUpgrade(conn, packet)
		if err != nil {
			return &ProcessingResult{Action: "drop", Reason: fmt.Sprintf("WebSocket error: %v", err)}, err
		}
		fh.stats.incrementWebSocketUpgrades()
		return result, nil
	}

	// 4. Complex routing
	if rule.ComplexRouting {
		result, err := fh.processComplexRouting(conn, rule, packet)
		if err != nil {
			return &ProcessingResult{Action: "drop", Reason: fmt.Sprintf("routing error: %v", err)}, err
		}
		fh.stats.incrementComplexRouting()
		return result, nil
	}

	// 5. Default forwarding
	return fh.processDefaultForwarding(conn, rule, packet)
}

// processAuthentication handles JWT and Base64 token authentication
func (fh *FallbackHandler) processAuthentication(conn *SlowPathConnection, rule *SlowPathRule, packet *PacketInfo) (*ProcessingResult, error) {
	// Extract authentication token from packet
	token, err := fh.extractAuthToken(packet, rule.AuthType)
	if err != nil {
		return &ProcessingResult{Action: "drop", Reason: "no auth token"}, err
	}

	// Validate token using authenticator
	err = fh.authenticator.AuthenticateService(int(rule.ServiceID), token)
	if err != nil {
		log.Printf("Authentication failed for service %d: %v", rule.ServiceID, err)
		return &ProcessingResult{Action: "drop", Reason: "authentication failed"}, nil
	}

	// Mark connection as authenticated
	conn.Authenticated = true
	conn.AuthToken = token

	log.Printf("Successfully authenticated connection %s for service %d", conn.ID, rule.ServiceID)
	return &ProcessingResult{Action: "continue", Reason: "authenticated"}, nil
}

// processTLS handles TLS termination and certificate management
func (fh *FallbackHandler) processTLS(conn *SlowPathConnection, packet *PacketInfo) (*ProcessingResult, error) {
	// TLS processing would involve:
	// - Certificate validation
	// - TLS handshake processing
	// - Certificate chain verification
	// - SNI (Server Name Indication) processing

	log.Printf("Processing TLS for connection %s", conn.ID)

	// For now, return a placeholder implementation
	return &ProcessingResult{
		Action: "forward",
		Reason: "TLS processed",
		Destination: &ForwardingDestination{
			IP:   conn.DestIP,
			Port: conn.DestPort,
		},
	}, nil
}

// processWebSocketUpgrade handles WebSocket protocol upgrades
func (fh *FallbackHandler) processWebSocketUpgrade(conn *SlowPathConnection, packet *PacketInfo) (*ProcessingResult, error) {
	log.Printf("Processing WebSocket upgrade for connection %s", conn.ID)

	// WebSocket upgrade processing would involve:
	// - HTTP Upgrade header validation
	// - WebSocket key generation and validation
	// - Protocol negotiation
	// - Connection state transition

	return &ProcessingResult{
		Action: "websocket_upgrade",
		Reason: "WebSocket upgrade processed",
		Destination: &ForwardingDestination{
			IP:   conn.DestIP,
			Port: conn.DestPort,
		},
	}, nil
}

// processComplexRouting handles load balancing and advanced routing
func (fh *FallbackHandler) processComplexRouting(conn *SlowPathConnection, rule *SlowPathRule, packet *PacketInfo) (*ProcessingResult, error) {
	log.Printf("Processing complex routing for connection %s", conn.ID)

	// Complex routing would involve:
	// - Load balancing algorithm selection
	// - Health check of destination services
	// - Weighted routing decisions
	// - Sticky session management

	// Select destination from multiple services
	destination, err := fh.selectDestination(rule.Mapping)
	if err != nil {
		return &ProcessingResult{Action: "drop", Reason: "no healthy destinations"}, err
	}

	return &ProcessingResult{
		Action:      "forward",
		Reason:      "complex routing completed",
		Destination: destination,
	}, nil
}

// processDefaultForwarding handles simple packet forwarding
func (fh *FallbackHandler) processDefaultForwarding(conn *SlowPathConnection, rule *SlowPathRule, packet *PacketInfo) (*ProcessingResult, error) {
	return &ProcessingResult{
		Action: "forward",
		Reason: "default forwarding",
		Destination: &ForwardingDestination{
			IP:   conn.DestIP,
			Port: conn.DestPort,
		},
	}, nil
}

// Helper functions

func (fh *FallbackHandler) generateConnectionID(packet *PacketInfo) string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		packet.SourceIP, packet.SourcePort,
		packet.DestIP, packet.DestPort,
		packet.Protocol)
}

func (fh *FallbackHandler) getOrCreateConnection(connID string, packet *PacketInfo) *SlowPathConnection {
	fh.connectionMu.Lock()
	defer fh.connectionMu.Unlock()

	if conn, exists := fh.activeConnections[connID]; exists {
		return conn
	}

	// Create new connection
	conn := &SlowPathConnection{
		ID:            connID,
		SourceIP:      packet.SourceIP,
		SourcePort:    packet.SourcePort,
		DestIP:        packet.DestIP,
		DestPort:      packet.DestPort,
		Protocol:      packet.Protocol,
		ServiceID:     packet.ServiceID,
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		PacketCount:   1,
		ByteCount:     uint64(packet.Size),
	}

	fh.activeConnections[connID] = conn
	fh.stats.incrementTotalConnections()

	return conn
}

func (fh *FallbackHandler) updateConnectionActivity(conn *SlowPathConnection, packet *PacketInfo) {
	fh.connectionMu.Lock()
	defer fh.connectionMu.Unlock()

	conn.LastActivity = time.Now()
	conn.PacketCount++
	conn.ByteCount += uint64(packet.Size)
}

func (fh *FallbackHandler) findSlowPathRule(serviceID uint32) *SlowPathRule {
	slowPathRules := fh.ruleSyncer.GetSlowPathRules()
	for _, rule := range slowPathRules {
		if rule.ServiceID == serviceID {
			return rule
		}
	}
	return nil
}

func (fh *FallbackHandler) extractAuthToken(packet *PacketInfo, authType string) (string, error) {
	// Extract authentication token from packet headers
	// This would parse HTTP headers or custom packet fields

	// Placeholder implementation
	if packet.Headers != nil {
		if token, exists := packet.Headers["Authorization"]; exists {
			return token, nil
		}
		if token, exists := packet.Headers["X-Auth-Token"]; exists {
			return token, nil
		}
	}

	return "", fmt.Errorf("no authentication token found")
}

func (fh *FallbackHandler) isWebSocketUpgrade(packet *PacketInfo) bool {
	if packet.Headers == nil {
		return false
	}

	upgrade, hasUpgrade := packet.Headers["Upgrade"]
	connection, hasConnection := packet.Headers["Connection"]

	return hasUpgrade && hasConnection &&
		   upgrade == "websocket" &&
		   connection == "Upgrade"
}

func (fh *FallbackHandler) selectDestination(mapping *manager.Mapping) (*ForwardingDestination, error) {
	if len(mapping.DestServices) == 0 {
		return nil, fmt.Errorf("no destination services configured")
	}

	// Simple round-robin selection for now
	// In production, this would implement proper load balancing
	_ = mapping.DestServices[0]

	// Look up service details from manager
	// For now, return a placeholder
	return &ForwardingDestination{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}, nil
}

// Statistics methods

func (fh *FallbackHandler) updateProcessingTime(duration time.Duration) {
	fh.stats.mu.Lock()
	defer fh.stats.mu.Unlock()

	// Simple moving average for processing time
	fh.stats.AverageProcessTime = (fh.stats.AverageProcessTime + duration) / 2
}

func (fs *FallbackStats) incrementTotalConnections() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.TotalConnections++
}

func (fs *FallbackStats) incrementAuthenticatedConns() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.AuthenticatedConns++
}

func (fs *FallbackStats) incrementFailedAuth() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.FailedAuthentication++
}

func (fs *FallbackStats) incrementTLSConns() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.TLSConnections++
}

func (fs *FallbackStats) incrementWebSocketUpgrades() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.WebSocketUpgrades++
}

func (fs *FallbackStats) incrementComplexRouting() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.ComplexRouting++
}

// GetStats returns current fallback processing statistics
func (fh *FallbackHandler) GetStats() map[string]interface{} {
	fh.stats.mu.RLock()
	defer fh.stats.mu.RUnlock()

	fh.connectionMu.RLock()
	activeConns := len(fh.activeConnections)
	fh.connectionMu.RUnlock()

	return map[string]interface{}{
		"total_connections":      fh.stats.TotalConnections,
		"authenticated_conns":    fh.stats.AuthenticatedConns,
		"failed_authentication":  fh.stats.FailedAuthentication,
		"tls_connections":        fh.stats.TLSConnections,
		"websocket_upgrades":     fh.stats.WebSocketUpgrades,
		"complex_routing":        fh.stats.ComplexRouting,
		"average_process_time":   fh.stats.AverageProcessTime,
		"active_connections":     activeConns,
	}
}

// Supporting types

type PacketInfo struct {
	SourceIP    net.IP
	SourcePort  uint16
	DestIP      net.IP
	DestPort    uint16
	Protocol    uint8
	ServiceID   uint32
	Size        int
	Headers     map[string]string
	Payload     []byte
}

type ProcessingResult struct {
	Action      string                 // "forward", "drop", "continue", "websocket_upgrade"
	Reason      string                 // Human-readable reason
	Destination *ForwardingDestination // Where to forward packet
}

type ForwardingDestination struct {
	IP   net.IP
	Port uint16
}