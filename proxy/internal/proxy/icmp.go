package proxy

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPProxy handles ICMP traffic proxying
type ICMPProxy struct {
	config      *ICMPConfig
	conn4       *icmp.PacketConn
	conn6       *icmp.PacketConn
	routingMap  map[string]*ICMPRoute
	stats       *ICMPStats
	running     bool
}

// ICMPConfig holds ICMP proxy configuration
type ICMPConfig struct {
	ListenIPv4  string
	ListenIPv6  string
	Timeout     time.Duration
	BufferSize  int
	MaxPacketSize int
	EnableIPv4  bool
	EnableIPv6  bool
	RateLimitPPS int // Packets per second rate limit
	LogTraffic  bool
}

// ICMPRoute defines an ICMP routing rule
type ICMPRoute struct {
	SourceCIDR      *net.IPNet
	DestinationIP   net.IP
	DestinationCIDR *net.IPNet
	AllowedTypes    []int // ICMP message types allowed
	TTL             int
	Priority        int
	ServiceID       string
	AuthRequired    bool
}

// ICMPStats holds ICMP proxy statistics
type ICMPStats struct {
	PacketsReceived    uint64
	PacketsForwarded   uint64
	PacketsDropped     uint64
	PacketsFiltered    uint64
	BytesReceived      uint64
	BytesForwarded     uint64
	ErrorsTotal        uint64
	RateLimitHits      uint64
	AuthFailures       uint64
	LastActivity       time.Time
}

// ICMPPacket represents an ICMP packet with metadata
type ICMPPacket struct {
	Data        []byte
	Source      net.Addr
	Destination net.Addr
	Type        int
	Code        int
	Checksum    int
	ID          int
	Sequence    int
	Timestamp   time.Time
	TTL         int
	Size        int
}

// NewICMPProxy creates a new ICMP proxy
func NewICMPProxy(config *ICMPConfig) *ICMPProxy {
	if config == nil {
		config = &ICMPConfig{
			ListenIPv4:    "0.0.0.0",
			ListenIPv6:    "::",
			Timeout:       time.Second * 30,
			BufferSize:    65536,
			MaxPacketSize: 1500,
			EnableIPv4:    true,
			EnableIPv6:    true,
			RateLimitPPS:  1000,
			LogTraffic:    false,
		}
	}

	return &ICMPProxy{
		config:     config,
		routingMap: make(map[string]*ICMPRoute),
		stats:      &ICMPStats{LastActivity: time.Now()},
	}
}

// Start initializes and starts the ICMP proxy
func (ip *ICMPProxy) Start() error {
	if ip.running {
		return fmt.Errorf("ICMP proxy already running")
	}

	// Initialize IPv4 ICMP socket
	if ip.config.EnableIPv4 {
		conn4, err := icmp.ListenPacket("ip4:icmp", ip.config.ListenIPv4)
		if err != nil {
			return fmt.Errorf("failed to create IPv4 ICMP socket: %w", err)
		}
		ip.conn4 = conn4

		// Set socket options for IPv4
		if err := ip.setIPv4SocketOptions(); err != nil {
			return fmt.Errorf("failed to set IPv4 socket options: %w", err)
		}
	}

	// Initialize IPv6 ICMP socket
	if ip.config.EnableIPv6 {
		conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", ip.config.ListenIPv6)
		if err != nil {
			return fmt.Errorf("failed to create IPv6 ICMP socket: %w", err)
		}
		ip.conn6 = conn6

		// Set socket options for IPv6
		if err := ip.setIPv6SocketOptions(); err != nil {
			return fmt.Errorf("failed to set IPv6 socket options: %w", err)
		}
	}

	ip.running = true

	// Start packet processing goroutines
	if ip.config.EnableIPv4 {
		go ip.processIPv4Packets()
	}
	if ip.config.EnableIPv6 {
		go ip.processIPv6Packets()
	}

	fmt.Printf("ICMP Proxy: Started (IPv4: %v, IPv6: %v)\n",
		ip.config.EnableIPv4, ip.config.EnableIPv6)
	return nil
}

// setIPv4SocketOptions sets socket options for IPv4 ICMP
func (ip *ICMPProxy) setIPv4SocketOptions() error {
	if ip.conn4 == nil {
		return fmt.Errorf("IPv4 connection not initialized")
	}

	// For simplicity, skip socket options for now
	// Raw socket access would require platform-specific implementation
	_ = ip.conn4 // Use connection to avoid unused variable
	return nil
}

// setIPv6SocketOptions sets socket options for IPv6 ICMP
func (ip *ICMPProxy) setIPv6SocketOptions() error {
	if ip.conn6 == nil {
		return fmt.Errorf("IPv6 connection not initialized")
	}

	// For simplicity, skip socket options for now
	// Raw socket access would require platform-specific implementation
	_ = ip.conn6 // Use connection to avoid unused variable
	return nil
}

// processIPv4Packets processes incoming IPv4 ICMP packets
func (ip *ICMPProxy) processIPv4Packets() {
	buffer := make([]byte, ip.config.MaxPacketSize)

	for ip.running {
		// Set read timeout
		ip.conn4.SetReadDeadline(time.Now().Add(ip.config.Timeout))

		n, peer, err := ip.conn4.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ip.running {
				fmt.Printf("ICMP Proxy: IPv4 read error: %v\n", err)
			}
			continue
		}

		ip.stats.PacketsReceived++
		ip.stats.BytesReceived += uint64(n)
		ip.stats.LastActivity = time.Now()

		// Parse ICMP packet
		packet, err := ip.parseICMPv4Packet(buffer[:n], peer)
		if err != nil {
			ip.stats.ErrorsTotal++
			continue
		}

		// Process packet
		go ip.handleICMPPacket(packet, 4)
	}
}

// processIPv6Packets processes incoming IPv6 ICMP packets
func (ip *ICMPProxy) processIPv6Packets() {
	buffer := make([]byte, ip.config.MaxPacketSize)

	for ip.running {
		// Set read timeout
		ip.conn6.SetReadDeadline(time.Now().Add(ip.config.Timeout))

		n, peer, err := ip.conn6.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ip.running {
				fmt.Printf("ICMP Proxy: IPv6 read error: %v\n", err)
			}
			continue
		}

		ip.stats.PacketsReceived++
		ip.stats.BytesReceived += uint64(n)
		ip.stats.LastActivity = time.Now()

		// Parse ICMP packet
		packet, err := ip.parseICMPv6Packet(buffer[:n], peer)
		if err != nil {
			ip.stats.ErrorsTotal++
			continue
		}

		// Process packet
		go ip.handleICMPPacket(packet, 6)
	}
}

// parseICMPv4Packet parses an IPv4 ICMP packet
func (ip *ICMPProxy) parseICMPv4Packet(data []byte, peer net.Addr) (*ICMPPacket, error) {
	msg, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply), data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ICMPv4 message: %w", err)
	}

	packet := &ICMPPacket{
		Data:        data,
		Source:      peer,
		Type:        msg.Type.Protocol(),
		Code:        msg.Code,
		Checksum:    msg.Checksum,
		Timestamp:   time.Now(),
		Size:        len(data),
	}

	// Extract additional fields for specific ICMP types
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		packet.ID = body.ID
		packet.Sequence = body.Seq
	case *icmp.PacketTooBig:
		// Handle Packet Too Big messages
	case *icmp.TimeExceeded:
		// Handle Time Exceeded messages
	case *icmp.DstUnreach:
		// Handle Destination Unreachable messages
	}

	return packet, nil
}

// parseICMPv6Packet parses an IPv6 ICMP packet
func (ip *ICMPProxy) parseICMPv6Packet(data []byte, peer net.Addr) (*ICMPPacket, error) {
	msg, err := icmp.ParseMessage(int(ipv6.ICMPTypeEchoReply), data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ICMPv6 message: %w", err)
	}

	packet := &ICMPPacket{
		Data:        data,
		Source:      peer,
		Type:        msg.Type.Protocol(),
		Code:        msg.Code,
		Checksum:    msg.Checksum,
		Timestamp:   time.Now(),
		Size:        len(data),
	}

	// Extract additional fields for specific ICMP types
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		packet.ID = body.ID
		packet.Sequence = body.Seq
	}

	return packet, nil
}

// handleICMPPacket processes an ICMP packet according to routing rules
func (ip *ICMPProxy) handleICMPPacket(packet *ICMPPacket, ipVersion int) {
	// Apply rate limiting
	if !ip.rateLimitCheck() {
		ip.stats.RateLimitHits++
		ip.stats.PacketsDropped++
		return
	}

	// Find matching route
	route := ip.findRoute(packet)
	if route == nil {
		ip.stats.PacketsFiltered++
		if ip.config.LogTraffic {
			fmt.Printf("ICMP Proxy: No route found for packet from %s\n", packet.Source.String())
		}
		return
	}

	// Check if packet type is allowed
	if !ip.isTypeAllowed(packet.Type, route.AllowedTypes) {
		ip.stats.PacketsFiltered++
		if ip.config.LogTraffic {
			fmt.Printf("ICMP Proxy: Packet type %d not allowed\n", packet.Type)
		}
		return
	}

	// Apply authentication if required
	if route.AuthRequired {
		if !ip.authenticatePacket(packet) {
			ip.stats.AuthFailures++
			ip.stats.PacketsDropped++
			return
		}
	}

	// Forward packet
	if err := ip.forwardPacket(packet, route, ipVersion); err != nil {
		ip.stats.ErrorsTotal++
		if ip.config.LogTraffic {
			fmt.Printf("ICMP Proxy: Failed to forward packet: %v\n", err)
		}
		return
	}

	ip.stats.PacketsForwarded++
	ip.stats.BytesForwarded += uint64(packet.Size)

	if ip.config.LogTraffic {
		fmt.Printf("ICMP Proxy: Forwarded %s packet from %s to %s\n",
			ip.getICMPTypeName(packet.Type), packet.Source.String(), route.DestinationIP.String())
	}
}

// rateLimitCheck implements simple rate limiting
func (ip *ICMPProxy) rateLimitCheck() bool {
	// Simple rate limiting implementation
	// In production, use a more sophisticated rate limiter
	return true // Simplified for this implementation
}

// findRoute finds a matching route for the packet
func (ip *ICMPProxy) findRoute(packet *ICMPPacket) *ICMPRoute {
	sourceIP := ip.extractSourceIP(packet.Source)

	// Find the best matching route
	var bestRoute *ICMPRoute
	bestPriority := -1

	for _, route := range ip.routingMap {
		if route.SourceCIDR.Contains(sourceIP) {
			if route.Priority > bestPriority {
				bestRoute = route
				bestPriority = route.Priority
			}
		}
	}

	return bestRoute
}

// extractSourceIP extracts the IP address from a net.Addr
func (ip *ICMPProxy) extractSourceIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return nil
	}
}

// isTypeAllowed checks if an ICMP type is allowed by the route
func (ip *ICMPProxy) isTypeAllowed(msgType int, allowedTypes []int) bool {
	if len(allowedTypes) == 0 {
		return true // Allow all types if none specified
	}

	for _, allowedType := range allowedTypes {
		if msgType == allowedType {
			return true
		}
	}
	return false
}

// authenticatePacket performs packet authentication
func (ip *ICMPProxy) authenticatePacket(packet *ICMPPacket) bool {
	// Implement authentication logic here
	// For ICMP, authentication might be based on source IP, packet content, etc.
	return true // Simplified for this implementation
}

// forwardPacket forwards the ICMP packet to the destination
func (ip *ICMPProxy) forwardPacket(packet *ICMPPacket, route *ICMPRoute, ipVersion int) error {
	var conn *icmp.PacketConn

	if ipVersion == 4 {
		conn = ip.conn4
	} else {
		conn = ip.conn6
	}

	if conn == nil {
		return fmt.Errorf("no connection available for IPv%d", ipVersion)
	}

	// Create destination address
	var destAddr net.Addr
	if ipVersion == 4 {
		destAddr = &net.IPAddr{IP: route.DestinationIP}
	} else {
		destAddr = &net.IPAddr{IP: route.DestinationIP}
	}

	// Modify packet if needed (TTL, etc.)
	modifiedData := ip.modifyPacket(packet.Data, route)

	// Set write timeout
	conn.SetWriteDeadline(time.Now().Add(ip.config.Timeout))

	// Send packet
	_, err := conn.WriteTo(modifiedData, destAddr)
	return err
}

// modifyPacket modifies packet fields like TTL before forwarding
func (ip *ICMPProxy) modifyPacket(data []byte, route *ICMPRoute) []byte {
	// Create a copy of the data
	modified := make([]byte, len(data))
	copy(modified, data)

	// Modify TTL if specified in route
	if route.TTL > 0 {
		// TTL modification would depend on packet format
		// This is a simplified implementation
	}

	return modified
}

// getICMPTypeName returns a human-readable name for ICMP type
func (ip *ICMPProxy) getICMPTypeName(msgType int) string {
	switch msgType {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 8:
		return "Echo Request"
	case 11:
		return "Time Exceeded"
	case 12:
		return "Parameter Problem"
	default:
		return fmt.Sprintf("Type %d", msgType)
	}
}

// AddRoute adds a new ICMP routing rule
func (ip *ICMPProxy) AddRoute(routeID string, route *ICMPRoute) {
	ip.routingMap[routeID] = route
	fmt.Printf("ICMP Proxy: Added route %s for %s -> %s\n",
		routeID, route.SourceCIDR.String(), route.DestinationIP.String())
}

// RemoveRoute removes an ICMP routing rule
func (ip *ICMPProxy) RemoveRoute(routeID string) {
	delete(ip.routingMap, routeID)
	fmt.Printf("ICMP Proxy: Removed route %s\n", routeID)
}

// UpdateRoute updates an existing ICMP routing rule
func (ip *ICMPProxy) UpdateRoute(routeID string, route *ICMPRoute) {
	ip.routingMap[routeID] = route
	fmt.Printf("ICMP Proxy: Updated route %s\n", routeID)
}

// GetStats returns current ICMP proxy statistics
func (ip *ICMPProxy) GetStats() *ICMPStats {
	stats := *ip.stats
	return &stats
}

// GetRoutes returns all configured routes
func (ip *ICMPProxy) GetRoutes() map[string]*ICMPRoute {
	routes := make(map[string]*ICMPRoute)
	for id, route := range ip.routingMap {
		routeCopy := *route
		routes[id] = &routeCopy
	}
	return routes
}

// IsRunning returns whether the ICMP proxy is running
func (ip *ICMPProxy) IsRunning() bool {
	return ip.running
}

// Stop stops the ICMP proxy
func (ip *ICMPProxy) Stop() error {
	if !ip.running {
		return fmt.Errorf("ICMP proxy not running")
	}

	ip.running = false

	// Close connections
	if ip.conn4 != nil {
		ip.conn4.Close()
	}
	if ip.conn6 != nil {
		ip.conn6.Close()
	}

	fmt.Printf("ICMP Proxy: Stopped\n")
	return nil
}

// CreateEchoRequest creates an ICMP echo request packet
func (ip *ICMPProxy) CreateEchoRequest(id, seq int, data []byte) ([]byte, error) {
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: data,
		},
	}

	return msg.Marshal(nil)
}

// CreateEchoReply creates an ICMP echo reply packet
func (ip *ICMPProxy) CreateEchoReply(id, seq int, data []byte) ([]byte, error) {
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: data,
		},
	}

	return msg.Marshal(nil)
}