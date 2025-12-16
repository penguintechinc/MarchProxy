package sync

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"marchproxy-egress/internal/acceleration/xdp"
	"marchproxy-egress/internal/manager"
)

// RuleSynchronizer handles synchronization between manager rules and XDP fast-path
type RuleSynchronizer struct {
	managerClient *manager.Client
	xdpManager    *xdp.XDPManager

	// Rule state tracking
	lastConfigHash string
	lastSyncTime   time.Time
	syncInterval   time.Duration

	// Rule classification
	fastPathRules map[string]*FastPathRule
	slowPathRules map[string]*SlowPathRule

	mu sync.RWMutex
	stopChan chan struct{}
}

// FastPathRule represents a rule that can be handled by XDP
type FastPathRule struct {
	ServiceID    uint32
	IPAddr       net.IP
	Port         uint16
	Protocol     uint8
	Action       uint8 // 0=drop, 1=pass, 2=redirect_to_userspace
	RequiresAuth bool
}

// SlowPathRule represents a rule that requires Go proxy processing
type SlowPathRule struct {
	ServiceID     uint32
	Service       *manager.Service
	Mapping       *manager.Mapping
	RequiresAuth  bool
	AuthType      string
	HasTLS        bool
	HasWebSocket  bool
	ComplexRouting bool
}

// Rule classification criteria
const (
	// Actions
	ACTION_DROP      = 0
	ACTION_PASS      = 1
	ACTION_USERSPACE = 2

	// Protocols
	PROTOCOL_TCP  = 6
	PROTOCOL_UDP  = 17
	PROTOCOL_ICMP = 1
)

// NewRuleSynchronizer creates a new rule synchronizer
func NewRuleSynchronizer(client *manager.Client, xdpMgr *xdp.XDPManager) *RuleSynchronizer {
	return &RuleSynchronizer{
		managerClient: client,
		xdpManager:    xdpMgr,
		syncInterval:  30 * time.Second, // Sync every 30 seconds
		fastPathRules: make(map[string]*FastPathRule),
		slowPathRules: make(map[string]*SlowPathRule),
		stopChan:      make(chan struct{}),
	}
}

// Start begins the rule synchronization process
func (rs *RuleSynchronizer) Start() error {
	log.Printf("Starting rule synchronizer with %v interval", rs.syncInterval)

	// Initial synchronization
	if err := rs.syncRules(); err != nil {
		return fmt.Errorf("initial rule sync failed: %w", err)
	}

	// Start periodic synchronization
	go rs.syncLoop()

	return nil
}

// Stop stops the rule synchronization
func (rs *RuleSynchronizer) Stop() {
	log.Printf("Stopping rule synchronizer")
	close(rs.stopChan)
}

// syncLoop runs the periodic synchronization
func (rs *RuleSynchronizer) syncLoop() {
	ticker := time.NewTicker(rs.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := rs.syncRules(); err != nil {
				log.Printf("Rule sync error: %v", err)
			}
		case <-rs.stopChan:
			return
		}
	}
}

// syncRules fetches configuration from manager and updates XDP rules
func (rs *RuleSynchronizer) syncRules() error {
	// Fetch configuration from manager
	// TODO: Implement GetConfiguration method in manager.Client
	// config, err := rs.managerClient.GetConfiguration()
	// if err != nil {
	// 	return fmt.Errorf("failed to fetch configuration: %w", err)
	// }

	// Temporary stub - use GetConfig instead
	config, err := rs.managerClient.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to fetch configuration: %w", err)
	}

	// Check if configuration has changed
	if config.Version == rs.lastConfigHash {
		// No changes, skip sync
		return nil
	}

	log.Printf("Configuration changed (version: %s), synchronizing rules...", config.Version)

	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Clear existing rules
	rs.fastPathRules = make(map[string]*FastPathRule)
	rs.slowPathRules = make(map[string]*SlowPathRule)

	// Process each service and mapping combination
	for _, service := range config.Services {
		for _, mapping := range config.Mappings {
			if rs.serviceInMapping(&service, &mapping) {
				rs.classifyAndAddRule(&service, &mapping)
			}
		}
	}

	// Update XDP rules
	if err := rs.updateXDPRules(); err != nil {
		return fmt.Errorf("failed to update XDP rules: %w", err)
	}

	// Update state
	rs.lastConfigHash = config.Version
	rs.lastSyncTime = time.Now()

	log.Printf("Rule sync completed: %d fast-path, %d slow-path rules",
		len(rs.fastPathRules), len(rs.slowPathRules))

	return nil
}

// serviceInMapping checks if a service is referenced in a mapping
func (rs *RuleSynchronizer) serviceInMapping(service *manager.Service, mapping *manager.Mapping) bool {
	// Check if service is in source or destination services
	for _, srcID := range mapping.SourceServices {
		if srcID == service.ID {
			return true
		}
	}
	for _, dstID := range mapping.DestinationServices {
		if dstID == service.ID {
			return true
		}
	}
	return false
}

// classifyAndAddRule determines if a rule can use fast-path (XDP) or needs slow-path (Go)
func (rs *RuleSynchronizer) classifyAndAddRule(service *manager.Service, mapping *manager.Mapping) {
	ruleKey := fmt.Sprintf("%d-%d", service.ID, mapping.ID)

	// Determine if this rule can use XDP fast-path
	canUseFastPath := rs.canUseFastPath(service, mapping)

	if canUseFastPath {
		// Create fast-path rule for XDP
		fastRule := &FastPathRule{
			ServiceID:    uint32(service.ID),
			IPAddr:       net.ParseIP(service.IPAddress),
			Port:         uint16(service.Port),
			Protocol:     rs.getProtocolNumber(mapping.Protocols),
			RequiresAuth: service.AuthType != "none",
		}

		// Determine action based on authentication requirements
		if fastRule.RequiresAuth {
			// Authentication required - pass to userspace
			fastRule.Action = ACTION_USERSPACE
		} else {
			// Simple allow for non-authenticated traffic
			fastRule.Action = ACTION_PASS
		}

		rs.fastPathRules[ruleKey] = fastRule

		log.Printf("Added fast-path rule: service=%d, ip=%s, port=%d, proto=%d",
			fastRule.ServiceID, fastRule.IPAddr, fastRule.Port, fastRule.Protocol)
	} else {
		// Create slow-path rule for Go proxy
		slowRule := &SlowPathRule{
			ServiceID:      uint32(service.ID),
			Service:        service,
			Mapping:        mapping,
			RequiresAuth:   service.AuthType != "none",
			AuthType:       service.AuthType,
			HasTLS:         service.TLSEnabled,
			HasWebSocket:   rs.hasWebSocketSupport(mapping),
			ComplexRouting: rs.hasComplexRouting(mapping),
		}

		rs.slowPathRules[ruleKey] = slowRule

		log.Printf("Added slow-path rule: service=%d, auth=%s, tls=%v, ws=%v",
			slowRule.ServiceID, slowRule.AuthType, slowRule.HasTLS, slowRule.HasWebSocket)
	}
}

// canUseFastPath determines if a service/mapping can be handled by XDP
func (rs *RuleSynchronizer) canUseFastPath(service *manager.Service, mapping *manager.Mapping) bool {
	// Rules that MUST use slow-path (Go proxy):

	// 1. Authentication required (JWT/Base64 validation)
	if service.AuthType == "jwt" || service.AuthType == "base64" {
		return false
	}

	// 2. TLS termination required
	if service.TLSEnabled {
		return false
	}

	// 3. HTTP/HTTPS protocol handling
	if rs.isHTTPProtocol(mapping.Protocols) {
		return false
	}

	// 4. WebSocket upgrade support
	if rs.hasWebSocketSupport(mapping) {
		return false
	}

	// 5. Complex routing logic
	if rs.hasComplexRouting(mapping) {
		return false
	}

	// 6. Custom port ranges or complex port configurations
	if rs.hasComplexPorts(service, mapping) {
		return false
	}

	// Rules that CAN use fast-path (XDP):
	// - Simple TCP/UDP port forwarding
	// - No authentication (or authentication handled in userspace)
	// - Basic allow/drop/redirect decisions
	// - Connection tracking and statistics

	return true
}

// updateXDPRules pushes fast-path rules to XDP program
func (rs *RuleSynchronizer) updateXDPRules() error {
	if !rs.xdpManager.IsEnabled() {
		log.Printf("XDP not enabled, skipping XDP rule updates")
		return nil
	}

	// Clear existing XDP rules
	if err := rs.xdpManager.ClearServiceRules(); err != nil {
		return fmt.Errorf("failed to clear XDP rules: %w", err)
	}

	// Add fast-path rules to XDP
	ruleID := uint32(1)
	for _, rule := range rs.fastPathRules {
		xdpRule := &xdp.ServiceRule{
			ServiceID: rule.ServiceID,
			IPAddr:    rs.ipToUint32(rule.IPAddr),
			Port:      rule.Port,
			Protocol:  rule.Protocol,
			Action:    rule.Action,
		}

		if err := rs.xdpManager.AddServiceRule(ruleID, xdpRule); err != nil {
			log.Printf("Failed to add XDP rule %d: %v", ruleID, err)
			continue
		}

		ruleID++
	}

	log.Printf("Updated XDP with %d fast-path rules", len(rs.fastPathRules))
	return nil
}

// Helper functions

func (rs *RuleSynchronizer) getProtocolNumber(protocols []string) uint8 {
	// Simple protocol mapping - in reality, this would be more sophisticated
	for _, proto := range protocols {
		switch proto {
		case "tcp":
			return PROTOCOL_TCP
		case "udp":
			return PROTOCOL_UDP
		case "icmp":
			return PROTOCOL_ICMP
		}
	}
	return PROTOCOL_TCP // Default to TCP
}

func (rs *RuleSynchronizer) isHTTPProtocol(protocols []string) bool {
	for _, proto := range protocols {
		if proto == "http" || proto == "https" {
			return true
		}
	}
	return false
}

func (rs *RuleSynchronizer) hasWebSocketSupport(mapping *manager.Mapping) bool {
	// Check if mapping includes WebSocket upgrade capabilities
	// This would be determined by mapping configuration
	return mapping.SupportsWebSocket
}

func (rs *RuleSynchronizer) hasComplexRouting(mapping *manager.Mapping) bool {
	// Check for complex routing requirements:
	// - Multiple destination services with load balancing
	// - Header-based routing
	// - Path-based routing
	return len(mapping.DestinationServices) > 1 ||
		   mapping.LoadBalancing != "none" ||
		   len(mapping.RoutingRules) > 0
}

func (rs *RuleSynchronizer) hasComplexPorts(service *manager.Service, mapping *manager.Mapping) bool {
	// Check for complex port configurations:
	// - Port ranges
	// - Multiple discrete ports
	// - Dynamic port allocation
	return len(mapping.Ports) > 1 ||
		   service.PortRange != "" ||
		   mapping.DynamicPorts
}

func (rs *RuleSynchronizer) ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// GetFastPathRules returns current fast-path rules (for monitoring/debugging)
func (rs *RuleSynchronizer) GetFastPathRules() map[string]*FastPathRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	rules := make(map[string]*FastPathRule)
	for k, v := range rs.fastPathRules {
		rules[k] = v
	}
	return rules
}

// GetSlowPathRules returns current slow-path rules (for monitoring/debugging)
func (rs *RuleSynchronizer) GetSlowPathRules() map[string]*SlowPathRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	rules := make(map[string]*SlowPathRule)
	for k, v := range rs.slowPathRules {
		rules[k] = v
	}
	return rules
}

// GetSyncStats returns synchronization statistics
func (rs *RuleSynchronizer) GetSyncStats() map[string]interface{} {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return map[string]interface{}{
		"last_sync_time":    rs.lastSyncTime,
		"last_config_hash":  rs.lastConfigHash,
		"sync_interval":     rs.syncInterval,
		"fast_path_rules":   len(rs.fastPathRules),
		"slow_path_rules":   len(rs.slowPathRules),
		"xdp_enabled":       rs.xdpManager.IsEnabled(),
	}
}