package afxdp

import (
	"crypto/md5"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

// EnhancedAFXDPProcessor handles packets from XDP with maximum processing
// before falling back to Go proxy
type EnhancedAFXDPProcessor struct {
	// Caching for fast lookups
	serviceCache    map[string]*CachedService
	authTokenCache  map[uint32]*AuthToken
	ruleCache      map[string]*ProcessingRule

	// Statistics
	stats          *EnhancedStats

	// Configuration
	config         *ProcessorConfig
}

// CachedService represents a cached service for fast lookups
type CachedService struct {
	ID              uint32
	IPAddress       net.IP
	PortRange       PortRange
	Protocol        uint8
	AuthType        AuthType
	RequiresTLS     bool
	AllowsWebSocket bool
	RateLimitPPS    uint32
	BandwidthLimit  uint64
	LastAccess      time.Time
}

// PortRange represents a port range
type PortRange struct {
	Start uint16
	End   uint16
}

// AuthType represents authentication requirements
type AuthType uint8

const (
	AuthNone AuthType = iota
	AuthSimpleToken
	AuthJWT
	AuthTLS
	AuthComplex
)

// ProcessingRule represents a cached processing rule
type ProcessingRule struct {
	ID          uint32
	Action      ActionType
	Priority    uint8
	CanFastPath bool
	LastUsed    time.Time
}

// ActionType represents the action to take
type ActionType uint8

const (
	ActionPass ActionType = iota
	ActionDrop
	ActionRedirectGo
	ActionRateLimit
)

// AuthToken represents a cached authentication token
type AuthToken struct {
	Hash      uint32
	ServiceID uint32
	ExpiryTime time.Time
	Permissions uint8
}

// EnhancedStats holds detailed processing statistics
type EnhancedStats struct {
	// Processing distribution
	FastPathProcessed    uint64
	SlowPathRedirected   uint64
	AuthProcessed        uint64
	TLSDetected         uint64
	WebSocketDetected   uint64
	RateLimited         uint64

	// Content analysis
	HTTPRequests        uint64
	HTTPSRequests       uint64
	HTTPMethods         map[string]uint64
	ContentTypes        map[string]uint64

	// Performance metrics
	AvgProcessingTime   time.Duration
	CacheHitRate       float64

	LastUpdate         time.Time
}

// ProcessorConfig holds processor configuration
type ProcessorConfig struct {
	MaxCacheSize       int
	CacheTTL          time.Duration
	EnableDeepInspection bool
	MaxPacketSize     int
	AuthTokenTTL      time.Duration
}

// HTTPPacketInfo contains parsed HTTP packet information
type HTTPPacketInfo struct {
	Method        string
	URI           string
	Version       string
	Headers       map[string]string
	ContentType   string
	ContentLength int
	IsWebSocket   bool
	HasAuth       bool
	AuthToken     string
}

// NewEnhancedAFXDPProcessor creates a new enhanced processor
func NewEnhancedAFXDPProcessor(config *ProcessorConfig) *EnhancedAFXDPProcessor {
	if config == nil {
		config = &ProcessorConfig{
			MaxCacheSize:         10000,
			CacheTTL:            time.Minute * 5,
			EnableDeepInspection: true,
			MaxPacketSize:       65536,
			AuthTokenTTL:        time.Hour,
		}
	}

	return &EnhancedAFXDPProcessor{
		serviceCache:   make(map[string]*CachedService),
		authTokenCache: make(map[uint32]*AuthToken),
		ruleCache:     make(map[string]*ProcessingRule),
		config:        config,
		stats: &EnhancedStats{
			HTTPMethods:  make(map[string]uint64),
			ContentTypes: make(map[string]uint64),
			LastUpdate:   time.Now(),
		},
	}
}

// ProcessPacket processes a packet with maximum AF_XDP-level logic
func (p *EnhancedAFXDPProcessor) ProcessPacket(packet *XDPPacket) PacketDecision {
	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		p.stats.AvgProcessingTime = processingTime
	}()

	// Parse packet headers
	packetInfo, err := p.parsePacketHeaders(packet.Data)
	if err != nil {
		return PacketDecision{Action: ActionDrop, Reason: "Invalid packet"}
	}

	// Look up service in cache
	serviceKey := fmt.Sprintf("%s:%d:%d", packetInfo.DestIP.String(),
		packetInfo.DestPort, packetInfo.Protocol)
	service := p.getCachedService(serviceKey, packetInfo)

	if service == nil {
		// No service found - pass through
		return PacketDecision{Action: ActionPass, Reason: "No service match"}
	}

	// Rate limiting check
	if service.RateLimitPPS > 0 {
		if !p.checkRateLimit(packetInfo.SourceIP, service.RateLimitPPS) {
			atomic.AddUint64(&p.stats.RateLimited, 1)
			return PacketDecision{Action: ActionDrop, Reason: "Rate limited"}
		}
	}

	// Protocol-specific processing
	switch packetInfo.Protocol {
	case 6: // TCP
		return p.processTCPPacket(packet, packetInfo, service)
	case 17: // UDP
		return p.processUDPPacket(packet, packetInfo, service)
	case 1: // ICMP
		return p.processICMPPacket(packet, packetInfo, service)
	default:
		return PacketDecision{Action: ActionPass, Reason: "Unknown protocol"}
	}
}

// PacketInfo contains parsed packet information
type PacketInfo struct {
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
	Protocol   uint8
	PayloadLen uint16
	Payload    []byte
}

// PacketDecision represents the processing decision
type PacketDecision struct {
	Action    ActionType
	Reason    string
	ServiceID uint32
	Metadata  map[string]interface{}
}

// parsePacketHeaders parses basic packet headers
func (p *EnhancedAFXDPProcessor) parsePacketHeaders(data []byte) (*PacketInfo, error) {
	if len(data) < 34 { // Minimum Ethernet + IP header
		return nil, fmt.Errorf("packet too small")
	}

	// Parse Ethernet header
	ethType := uint16(data[12])<<8 | uint16(data[13])
	if ethType != 0x0800 { // IPv4
		return nil, fmt.Errorf("non-IPv4 packet")
	}

	// Parse IPv4 header
	ipHeader := data[14:]
	if len(ipHeader) < 20 {
		return nil, fmt.Errorf("invalid IP header")
	}

	version := (ipHeader[0] >> 4) & 0xF
	if version != 4 {
		return nil, fmt.Errorf("invalid IP version")
	}

	headerLen := int(ipHeader[0]&0xF) * 4
	if len(ipHeader) < headerLen {
		return nil, fmt.Errorf("truncated IP header")
	}

	packetInfo := &PacketInfo{
		SourceIP: net.IP(ipHeader[12:16]),
		DestIP:   net.IP(ipHeader[16:20]),
		Protocol: ipHeader[9],
	}

	// Parse transport layer
	transportHeader := ipHeader[headerLen:]
	switch packetInfo.Protocol {
	case 6: // TCP
		if len(transportHeader) < 20 {
			return nil, fmt.Errorf("invalid TCP header")
		}
		packetInfo.SourcePort = uint16(transportHeader[0])<<8 | uint16(transportHeader[1])
		packetInfo.DestPort = uint16(transportHeader[2])<<8 | uint16(transportHeader[3])

		tcpHeaderLen := int(transportHeader[12]>>4) * 4
		if len(transportHeader) > tcpHeaderLen {
			packetInfo.Payload = transportHeader[tcpHeaderLen:]
			packetInfo.PayloadLen = uint16(len(packetInfo.Payload))
		}

	case 17: // UDP
		if len(transportHeader) < 8 {
			return nil, fmt.Errorf("invalid UDP header")
		}
		packetInfo.SourcePort = uint16(transportHeader[0])<<8 | uint16(transportHeader[1])
		packetInfo.DestPort = uint16(transportHeader[2])<<8 | uint16(transportHeader[3])

		if len(transportHeader) > 8 {
			packetInfo.Payload = transportHeader[8:]
			packetInfo.PayloadLen = uint16(len(packetInfo.Payload))
		}

	case 1: // ICMP
		if len(transportHeader) < 8 {
			return nil, fmt.Errorf("invalid ICMP header")
		}
		packetInfo.SourcePort = 0
		packetInfo.DestPort = uint16(transportHeader[0]) // ICMP type
		packetInfo.Payload = transportHeader[8:]
		packetInfo.PayloadLen = uint16(len(packetInfo.Payload))
	}

	return packetInfo, nil
}

// processTCPPacket handles TCP-specific processing
func (p *EnhancedAFXDPProcessor) processTCPPacket(packet *XDPPacket, info *PacketInfo, service *CachedService) PacketDecision {
	// Check for HTTPS (port 443 or TLS handshake)
	if info.DestPort == 443 || p.isTLSHandshake(info.Payload) {
		atomic.AddUint64(&p.stats.HTTPSRequests, 1)
		atomic.AddUint64(&p.stats.TLSDetected, 1)

		if service.RequiresTLS {
			// Must go to Go proxy for TLS termination
			return PacketDecision{
				Action:    ActionRedirectGo,
				Reason:    "TLS termination required",
				ServiceID: service.ID,
				Metadata:  map[string]interface{}{"tls": true},
			}
		}
	}

	// Check for HTTP traffic
	if info.PayloadLen > 0 && p.isHTTPTraffic(info.Payload) {
		atomic.AddUint64(&p.stats.HTTPRequests, 1)

		httpInfo := p.parseHTTPHeaders(info.Payload)
		if httpInfo != nil {
			// Update method statistics
			p.stats.HTTPMethods[httpInfo.Method]++

			// Check for WebSocket upgrade
			if httpInfo.IsWebSocket {
				atomic.AddUint64(&p.stats.WebSocketDetected, 1)

				if service.AllowsWebSocket {
					// Must go to Go proxy for WebSocket handling
					return PacketDecision{
						Action:    ActionRedirectGo,
						Reason:    "WebSocket upgrade required",
						ServiceID: service.ID,
						Metadata:  map[string]interface{}{"websocket": true, "method": httpInfo.Method},
					}
				} else {
					return PacketDecision{Action: ActionDrop, Reason: "WebSocket not allowed"}
				}
			}

			// Authentication check
			if service.AuthType != AuthNone {
				authResult := p.checkAuthentication(httpInfo, service)
				if authResult == AuthResultComplex {
					// Complex auth needs Go proxy
					return PacketDecision{
						Action:    ActionRedirectGo,
						Reason:    "Complex authentication required",
						ServiceID: service.ID,
						Metadata:  map[string]interface{}{"auth": true, "method": httpInfo.Method},
					}
				} else if authResult == AuthResultFailed {
					return PacketDecision{Action: ActionDrop, Reason: "Authentication failed"}
				}
			}

			// Simple HTTP request that can be fast-pathed
			if p.canFastPathHTTP(httpInfo, service) {
				atomic.AddUint64(&p.stats.FastPathProcessed, 1)
				return PacketDecision{
					Action:    ActionPass,
					Reason:    "Fast-path HTTP",
					ServiceID: service.ID,
					Metadata:  map[string]interface{}{"method": httpInfo.Method, "fastpath": true},
				}
			}
		}
	}

	// Default TCP handling
	if service.AuthType == AuthNone || service.AuthType == AuthSimpleToken {
		atomic.AddUint64(&p.stats.FastPathProcessed, 1)
		return PacketDecision{Action: ActionPass, ServiceID: service.ID}
	}

	// Complex processing needed
	atomic.AddUint64(&p.stats.SlowPathRedirected, 1)
	return PacketDecision{
		Action:    ActionRedirectGo,
		Reason:    "Complex TCP processing",
		ServiceID: service.ID,
	}
}

// processUDPPacket handles UDP-specific processing
func (p *EnhancedAFXDPProcessor) processUDPPacket(packet *XDPPacket, info *PacketInfo, service *CachedService) PacketDecision {
	// UDP is generally simpler and can often be fast-pathed
	if service.AuthType == AuthNone {
		atomic.AddUint64(&p.stats.FastPathProcessed, 1)
		return PacketDecision{Action: ActionPass, ServiceID: service.ID}
	}

	// UDP with authentication needs Go proxy
	atomic.AddUint64(&p.stats.SlowPathRedirected, 1)
	return PacketDecision{
		Action:    ActionRedirectGo,
		Reason:    "UDP authentication required",
		ServiceID: service.ID,
	}
}

// processICMPPacket handles ICMP-specific processing
func (p *EnhancedAFXDPProcessor) processICMPPacket(packet *XDPPacket, info *PacketInfo, service *CachedService) PacketDecision {
	// ICMP can usually be fast-pathed
	atomic.AddUint64(&p.stats.FastPathProcessed, 1)
	return PacketDecision{Action: ActionPass, ServiceID: service.ID}
}

// isTLSHandshake checks if payload contains TLS handshake
func (p *EnhancedAFXDPProcessor) isTLSHandshake(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}

	// Check for TLS handshake record type (0x16) and version (0x03xx)
	return payload[0] == 0x16 && payload[1] == 0x03
}

// isHTTPTraffic checks if payload contains HTTP traffic
func (p *EnhancedAFXDPProcessor) isHTTPTraffic(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}

	// Check for HTTP methods
	httpMethods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "TRAC", "CONN"}

	payloadStr := string(payload[:min(len(payload), 8)])
	for _, method := range httpMethods {
		if len(payloadStr) >= len(method) && payloadStr[:len(method)] == method {
			return true
		}
	}

	return false
}

// parseHTTPHeaders parses HTTP headers from payload
func (p *EnhancedAFXDPProcessor) parseHTTPHeaders(payload []byte) *HTTPPacketInfo {
	if len(payload) < 16 {
		return nil
	}

	payloadStr := string(payload[:min(len(payload), 2048)]) // Limit parsing
	lines := strings.Split(payloadStr, "\r\n")
	if len(lines) < 1 {
		return nil
	}

	// Parse request line
	requestParts := strings.SplitN(lines[0], " ", 3)
	if len(requestParts) < 3 {
		return nil
	}

	httpInfo := &HTTPPacketInfo{
		Method:  requestParts[0],
		URI:     requestParts[1],
		Version: requestParts[2],
		Headers: make(map[string]string),
	}

	// Parse headers
	for i := 1; i < len(lines) && lines[i] != ""; i++ {
		headerParts := strings.SplitN(lines[i], ":", 2)
		if len(headerParts) == 2 {
			key := strings.TrimSpace(strings.ToLower(headerParts[0]))
			value := strings.TrimSpace(headerParts[1])
			httpInfo.Headers[key] = value

			// Check for specific headers
			switch key {
			case "content-type":
				httpInfo.ContentType = value
			case "authorization":
				httpInfo.HasAuth = true
				// Extract simple bearer token
				if strings.HasPrefix(value, "Bearer ") {
					httpInfo.AuthToken = strings.TrimPrefix(value, "Bearer ")
				}
			case "upgrade":
				if strings.ToLower(value) == "websocket" {
					httpInfo.IsWebSocket = true
				}
			case "connection":
				if strings.ToLower(value) == "upgrade" {
					// Might be WebSocket upgrade
					if _, exists := httpInfo.Headers["upgrade"]; exists {
						httpInfo.IsWebSocket = true
					}
				}
			}
		}
	}

	return httpInfo
}

// AuthResult represents authentication check result
type AuthResult int

const (
	AuthResultPassed AuthResult = iota
	AuthResultFailed
	AuthResultComplex
)

// checkAuthentication performs authentication check
func (p *EnhancedAFXDPProcessor) checkAuthentication(httpInfo *HTTPPacketInfo, service *CachedService) AuthResult {
	switch service.AuthType {
	case AuthNone:
		return AuthResultPassed

	case AuthSimpleToken:
		if !httpInfo.HasAuth {
			return AuthResultFailed
		}

		// Simple token validation
		if httpInfo.AuthToken != "" {
			tokenHash := p.hashString(httpInfo.AuthToken)
			if token := p.authTokenCache[tokenHash]; token != nil {
				if time.Now().Before(token.ExpiryTime) &&
				   (token.ServiceID == service.ID || token.ServiceID == 0) {
					atomic.AddUint64(&p.stats.AuthProcessed, 1)
					return AuthResultPassed
				}
			}
		}
		return AuthResultFailed

	case AuthJWT:
		// JWT requires complex processing
		return AuthResultComplex

	case AuthTLS:
		// TLS auth requires complex processing
		return AuthResultComplex

	case AuthComplex:
		// Complex auth always requires Go proxy
		return AuthResultComplex

	default:
		return AuthResultFailed
	}
}

// canFastPathHTTP determines if an HTTP request can be fast-pathed
func (p *EnhancedAFXDPProcessor) canFastPathHTTP(httpInfo *HTTPPacketInfo, service *CachedService) bool {
	// Simple GET/HEAD requests without complex features can be fast-pathed
	if httpInfo.Method == "GET" || httpInfo.Method == "HEAD" {
		// No WebSocket upgrade
		if httpInfo.IsWebSocket {
			return false
		}

		// No complex content types
		if httpInfo.ContentType != "" && !strings.HasPrefix(httpInfo.ContentType, "text/") &&
		   !strings.HasPrefix(httpInfo.ContentType, "application/json") {
			return false
		}

		// Simple authentication only
		if service.AuthType != AuthNone && service.AuthType != AuthSimpleToken {
			return false
		}

		return true
	}

	return false
}

// getCachedService looks up or creates a cached service
func (p *EnhancedAFXDPProcessor) getCachedService(key string, info *PacketInfo) *CachedService {
	// Check cache first
	if service, exists := p.serviceCache[key]; exists {
		service.LastAccess = time.Now()
		return service
	}

	// Service lookup would integrate with actual service registry
	// For now, return a mock service for demonstration
	service := &CachedService{
		ID:              1,
		IPAddress:       info.DestIP,
		PortRange:       PortRange{Start: info.DestPort, End: info.DestPort},
		Protocol:        info.Protocol,
		AuthType:        AuthNone,
		RequiresTLS:     false,
		AllowsWebSocket: true,
		RateLimitPPS:    1000,
		BandwidthLimit:  1000000,
		LastAccess:      time.Now(),
	}

	// Cache the service
	p.serviceCache[key] = service
	return service
}

// checkRateLimit implements rate limiting
func (p *EnhancedAFXDPProcessor) checkRateLimit(sourceIP net.IP, limitPPS uint32) bool {
	// Simplified rate limiting - in production would use proper algorithm
	return true
}

// hashString creates a hash of a string
func (p *EnhancedAFXDPProcessor) hashString(s string) uint32 {
	hash := md5.Sum([]byte(s))
	return *(*uint32)(unsafe.Pointer(&hash[0]))
}

// GetStats returns current statistics
func (p *EnhancedAFXDPProcessor) GetStats() *EnhancedStats {
	stats := *p.stats
	stats.LastUpdate = time.Now()
	return &stats
}

// ClearCache clears expired cache entries
func (p *EnhancedAFXDPProcessor) ClearCache() {
	now := time.Now()

	// Clear expired services
	for key, service := range p.serviceCache {
		if now.Sub(service.LastAccess) > p.config.CacheTTL {
			delete(p.serviceCache, key)
		}
	}

	// Clear expired auth tokens
	for hash, token := range p.authTokenCache {
		if now.After(token.ExpiryTime) {
			delete(p.authTokenCache, hash)
		}
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}