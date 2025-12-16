package websocket

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"marchproxy-egress/internal/manager"
)

// WebSocketProxy handles WebSocket connection proxying
type WebSocketProxy struct {
	config           *WebSocketConfig
	stats            *WebSocketStats
	connections      map[string]*WebSocketConnection
	upgradeHandler   *UpgradeHandler
	messageProcessor *MessageProcessor
	mu               sync.RWMutex
}

// WebSocketConfig holds WebSocket proxy configuration
type WebSocketConfig struct {
	EnableCompression     bool
	CompressionLevel      int
	MaxMessageSize        int64
	PingInterval          time.Duration
	PongTimeout           time.Duration
	HandshakeTimeout      time.Duration
	MaxConnections        int
	BufferSize            int
	EnableSubprotocols    bool
	AllowedOrigins        []string
	AllowedExtensions     []string
	EnablePermessageDeflate bool
	WindowBits            int
}

// WebSocketConnection represents an active WebSocket connection
type WebSocketConnection struct {
	ID              string
	ClientConn      net.Conn
	BackendConn     net.Conn
	Service         *manager.Service
	SubProtocol     string
	Extensions      []string
	CompressionEnabled bool
	State           ConnectionState
	LastPing        time.Time
	LastPong        time.Time
	BytesReceived   uint64
	BytesSent       uint64
	MessagesReceived uint64
	MessagesSent    uint64
	StartTime       time.Time
	mu              sync.RWMutex
}

// ConnectionState represents the state of a WebSocket connection
type ConnectionState int

const (
	StateConnecting ConnectionState = iota
	StateOpen
	StateClosing
	StateClosed
)

// WebSocketStats holds WebSocket proxy statistics
type WebSocketStats struct {
	TotalConnections     uint64
	ActiveConnections    uint64
	UpgradedConnections  uint64
	FailedUpgrades       uint64
	TotalMessagesProxied uint64
	TotalBytesProxied    uint64
	AverageLatency       time.Duration
	CompressionRatio     float64
	ErrorCount           uint64
	LastUpdate           time.Time
}

// UpgradeHandler handles HTTP to WebSocket upgrade requests
type UpgradeHandler struct {
	proxy  *WebSocketProxy
	config *WebSocketConfig
}

// MessageProcessor handles WebSocket message processing and routing
type MessageProcessor struct {
	proxy       *WebSocketProxy
	config      *WebSocketConfig
	frameParser *FrameParser
}

// FrameParser handles WebSocket frame parsing and construction
type FrameParser struct {
	maxFrameSize int64
}

// WebSocketFrame represents a WebSocket frame
type WebSocketFrame struct {
	Fin     bool
	RSV1    bool
	RSV2    bool
	RSV3    bool
	Opcode  uint8
	Masked  bool
	Payload []byte
	MaskKey [4]byte
}

// Frame opcodes
const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

// WebSocket GUID for upgrade
const WebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// NewWebSocketProxy creates a new WebSocket proxy
func NewWebSocketProxy(config *WebSocketConfig) *WebSocketProxy {
	if config == nil {
		config = &WebSocketConfig{
			EnableCompression:       true,
			CompressionLevel:        6,
			MaxMessageSize:          1024 * 1024, // 1MB
			PingInterval:            time.Second * 30,
			PongTimeout:             time.Second * 10,
			HandshakeTimeout:        time.Second * 10,
			MaxConnections:          10000,
			BufferSize:              4096,
			EnableSubprotocols:      true,
			AllowedOrigins:          []string{"*"},
			AllowedExtensions:       []string{"permessage-deflate"},
			EnablePermessageDeflate: true,
			WindowBits:              15,
		}
	}

	proxy := &WebSocketProxy{
		config:      config,
		connections: make(map[string]*WebSocketConnection),
		stats: &WebSocketStats{
			LastUpdate: time.Now(),
		},
	}

	proxy.upgradeHandler = &UpgradeHandler{
		proxy:  proxy,
		config: config,
	}

	proxy.messageProcessor = &MessageProcessor{
		proxy:  proxy,
		config: config,
		frameParser: &FrameParser{
			maxFrameSize: config.MaxMessageSize,
		},
	}

	return proxy
}

// HandleUpgrade handles HTTP to WebSocket upgrade requests
func (ws *WebSocketProxy) HandleUpgrade(w http.ResponseWriter, r *http.Request, service *manager.Service) error {
	// Validate WebSocket upgrade request
	if !ws.validateUpgradeRequest(r) {
		http.Error(w, "Invalid WebSocket upgrade request", http.StatusBadRequest)
		atomic.AddUint64(&ws.stats.FailedUpgrades, 1)
		return fmt.Errorf("invalid upgrade request")
	}

	// Check connection limit
	if len(ws.connections) >= ws.config.MaxConnections {
		http.Error(w, "Too many connections", http.StatusServiceUnavailable)
		atomic.AddUint64(&ws.stats.FailedUpgrades, 1)
		return fmt.Errorf("connection limit reached")
	}

	// Connect to backend WebSocket service
	backendConn, err := ws.connectToBackend(r, service)
	if err != nil {
		http.Error(w, "Failed to connect to backend", http.StatusBadGateway)
		atomic.AddUint64(&ws.stats.FailedUpgrades, 1)
		return fmt.Errorf("backend connection failed: %w", err)
	}

	// Hijack the HTTP connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		backendConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		atomic.AddUint64(&ws.stats.FailedUpgrades, 1)
		return fmt.Errorf("hijacking not supported")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		backendConn.Close()
		return fmt.Errorf("hijacking failed: %w", err)
	}

	// Create WebSocket connection
	wsConn := &WebSocketConnection{
		ID:          ws.generateConnectionID(),
		ClientConn:  clientConn,
		BackendConn: backendConn,
		Service:     service,
		State:       StateConnecting,
		StartTime:   time.Now(),
	}

	// Perform WebSocket handshake
	if err := ws.performHandshake(wsConn, r); err != nil {
		clientConn.Close()
		backendConn.Close()
		atomic.AddUint64(&ws.stats.FailedUpgrades, 1)
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Register connection
	ws.mu.Lock()
	ws.connections[wsConn.ID] = wsConn
	ws.mu.Unlock()

	// Update statistics
	atomic.AddUint64(&ws.stats.UpgradedConnections, 1)
	atomic.AddUint64(&ws.stats.ActiveConnections, 1)

	// Start proxying
	go ws.proxyConnection(wsConn)

	fmt.Printf("WebSocket: Upgraded connection %s for service %d\n", wsConn.ID, service.ID)
	return nil
}

// validateUpgradeRequest validates a WebSocket upgrade request
func (ws *WebSocketProxy) validateUpgradeRequest(r *http.Request) bool {
	// Check required headers
	if r.Method != "GET" {
		return false
	}

	if strings.ToLower(r.Header.Get("Connection")) != "upgrade" {
		return false
	}

	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		return false
	}

	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}

	if r.Header.Get("Sec-WebSocket-Key") == "" {
		return false
	}

	// Check origin if restricted
	if len(ws.config.AllowedOrigins) > 0 && ws.config.AllowedOrigins[0] != "*" {
		origin := r.Header.Get("Origin")
		allowed := false
		for _, allowedOrigin := range ws.config.AllowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

// connectToBackend establishes connection to backend WebSocket service
func (ws *WebSocketProxy) connectToBackend(r *http.Request, service *manager.Service) (net.Conn, error) {
	// Create backend URL
	backendURL, err := url.Parse(fmt.Sprintf("ws://%s%s", service.IPFQDN, r.URL.Path))
	if err != nil {
		return nil, err
	}

	// Connect to backend
	ctx, cancel := context.WithTimeout(context.Background(), ws.config.HandshakeTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", backendURL.Host)
	if err != nil {
		return nil, err
	}

	// Send upgrade request to backend
	if err := ws.sendBackendUpgrade(conn, r, backendURL); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// sendBackendUpgrade sends WebSocket upgrade request to backend
func (ws *WebSocketProxy) sendBackendUpgrade(conn net.Conn, r *http.Request, backendURL *url.URL) error {
	// Generate WebSocket key
	key := ws.generateWebSocketKey()

	// Build upgrade request
	upgradeReq := fmt.Sprintf("GET %s HTTP/1.1\r\n", backendURL.Path)
	upgradeReq += fmt.Sprintf("Host: %s\r\n", backendURL.Host)
	upgradeReq += "Upgrade: websocket\r\n"
	upgradeReq += "Connection: Upgrade\r\n"
	upgradeReq += fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", key)
	upgradeReq += "Sec-WebSocket-Version: 13\r\n"

	// Copy relevant headers from client request
	if subProtocol := r.Header.Get("Sec-WebSocket-Protocol"); subProtocol != "" {
		upgradeReq += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", subProtocol)
	}

	if extensions := r.Header.Get("Sec-WebSocket-Extensions"); extensions != "" {
		upgradeReq += fmt.Sprintf("Sec-WebSocket-Extensions: %s\r\n", extensions)
	}

	upgradeReq += "\r\n"

	// Send request
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		return err
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(ws.config.HandshakeTimeout))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Validate upgrade response
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("backend upgrade failed: %d", resp.StatusCode)
	}

	return nil
}

// performHandshake performs WebSocket handshake with client
func (ws *WebSocketProxy) performHandshake(wsConn *WebSocketConnection, r *http.Request) error {
	// Get WebSocket key
	key := r.Header.Get("Sec-WebSocket-Key")
	
	// Generate accept key
	acceptKey := ws.generateAcceptKey(key)

	// Build response headers
	response := "HTTP/1.1 101 Switching Protocols\r\n"
	response += "Upgrade: websocket\r\n"
	response += "Connection: Upgrade\r\n"
	response += fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", acceptKey)

	// Handle subprotocols
	if ws.config.EnableSubprotocols {
		if subProtocols := r.Header.Get("Sec-WebSocket-Protocol"); subProtocols != "" {
			// Select first supported subprotocol (simplified)
			protocols := strings.Split(subProtocols, ",")
			if len(protocols) > 0 {
				wsConn.SubProtocol = strings.TrimSpace(protocols[0])
				response += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", wsConn.SubProtocol)
			}
		}
	}

	// Handle extensions
	if extensions := r.Header.Get("Sec-WebSocket-Extensions"); extensions != "" {
		if ws.config.EnablePermessageDeflate && strings.Contains(extensions, "permessage-deflate") {
			wsConn.CompressionEnabled = true
			wsConn.Extensions = []string{"permessage-deflate"}
			response += "Sec-WebSocket-Extensions: permessage-deflate\r\n"
		}
	}

	response += "\r\n"

	// Send response
	if _, err := wsConn.ClientConn.Write([]byte(response)); err != nil {
		return err
	}

	wsConn.State = StateOpen
	return nil
}

// proxyConnection handles bidirectional WebSocket message proxying
func (ws *WebSocketProxy) proxyConnection(wsConn *WebSocketConnection) {
	defer func() {
		ws.closeConnection(wsConn)
	}()

	// Start ping/pong handling
	pingTicker := time.NewTicker(ws.config.PingInterval)
	defer pingTicker.Stop()

	// Bidirectional proxying
	errChan := make(chan error, 2)

	// Client to backend
	go func() {
		errChan <- ws.proxyDirection(wsConn.ClientConn, wsConn.BackendConn, wsConn, true)
	}()

	// Backend to client
	go func() {
		errChan <- ws.proxyDirection(wsConn.BackendConn, wsConn.ClientConn, wsConn, false)
	}()

	// Handle ping/pong and errors
	for {
		select {
		case <-pingTicker.C:
			if err := ws.sendPing(wsConn); err != nil {
				fmt.Printf("WebSocket: Ping failed for connection %s: %v\n", wsConn.ID, err)
				return
			}
		case err := <-errChan:
			if err != nil {
				fmt.Printf("WebSocket: Proxy error for connection %s: %v\n", wsConn.ID, err)
			}
			return
		}
	}
}

// proxyDirection proxies messages in one direction
func (ws *WebSocketProxy) proxyDirection(src, dst net.Conn, wsConn *WebSocketConnection, clientToBackend bool) error {
	buffer := make([]byte, ws.config.BufferSize)

	for {
		// Set read timeout
		src.SetReadDeadline(time.Now().Add(time.Minute))

		// Read frame
		frame, err := ws.messageProcessor.frameParser.ReadFrame(src, buffer)
		if err != nil {
			if err == io.EOF {
				return nil // Clean close
			}
			return err
		}

		// Process frame based on opcode
		switch frame.Opcode {
		case OpcodePing:
			// Respond with pong
			pongFrame := &WebSocketFrame{
				Fin:     true,
				Opcode:  OpcodePong,
				Payload: frame.Payload,
			}
			if err := ws.messageProcessor.frameParser.WriteFrame(src, pongFrame); err != nil {
				return err
			}
			continue

		case OpcodePong:
			if clientToBackend {
				wsConn.LastPong = time.Now()
			}
			// Forward pong to other side
			if err := ws.messageProcessor.frameParser.WriteFrame(dst, frame); err != nil {
				return err
			}

		case OpcodeClose:
			// Forward close frame and terminate
			ws.messageProcessor.frameParser.WriteFrame(dst, frame)
			return nil

		case OpcodeText, OpcodeBinary, OpcodeContinuation:
			// Process and forward data frames
			if err := ws.processDataFrame(frame, dst, wsConn, clientToBackend); err != nil {
				return err
			}

		default:
			// Unknown opcode, forward as-is
			if err := ws.messageProcessor.frameParser.WriteFrame(dst, frame); err != nil {
				return err
			}
		}
	}
}

// processDataFrame processes data frames with optional compression
func (ws *WebSocketProxy) processDataFrame(frame *WebSocketFrame, dst net.Conn, wsConn *WebSocketConnection, clientToBackend bool) error {
	// Update statistics
	if clientToBackend {
		atomic.AddUint64(&wsConn.MessagesReceived, 1)
		atomic.AddUint64(&wsConn.BytesReceived, uint64(len(frame.Payload)))
	} else {
		atomic.AddUint64(&wsConn.MessagesSent, 1)
		atomic.AddUint64(&wsConn.BytesSent, uint64(len(frame.Payload)))
	}

	// Handle compression/decompression if enabled
	if wsConn.CompressionEnabled && frame.RSV1 {
		// Decompress frame payload
		decompressed, err := ws.decompressPayload(frame.Payload)
		if err != nil {
			return fmt.Errorf("decompression failed: %w", err)
		}
		frame.Payload = decompressed
		frame.RSV1 = false // Clear compression bit after decompression
	}

	// Forward frame
	if err := ws.messageProcessor.frameParser.WriteFrame(dst, frame); err != nil {
		return err
	}

	atomic.AddUint64(&ws.stats.TotalMessagesProxied, 1)
	atomic.AddUint64(&ws.stats.TotalBytesProxied, uint64(len(frame.Payload)))

	return nil
}

// ReadFrame reads a WebSocket frame from connection
func (fp *FrameParser) ReadFrame(conn net.Conn, buffer []byte) (*WebSocketFrame, error) {
	// Read first 2 bytes for basic frame info
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	frame := &WebSocketFrame{}
	
	// Parse first byte
	frame.Fin = (header[0] & 0x80) != 0
	frame.RSV1 = (header[0] & 0x40) != 0
	frame.RSV2 = (header[0] & 0x20) != 0
	frame.RSV3 = (header[0] & 0x10) != 0
	frame.Opcode = header[0] & 0x0F

	// Parse second byte
	frame.Masked = (header[1] & 0x80) != 0
	payloadLen := int64(header[1] & 0x7F)

	// Handle extended payload length
	if payloadLen == 126 {
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = int64(lenBytes[0])<<8 | int64(lenBytes[1])
	} else if payloadLen == 127 {
		lenBytes := make([]byte, 8)
		if _, err := io.ReadFull(conn, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = int64(lenBytes[0])<<56 | int64(lenBytes[1])<<48 |
			int64(lenBytes[2])<<40 | int64(lenBytes[3])<<32 |
			int64(lenBytes[4])<<24 | int64(lenBytes[5])<<16 |
			int64(lenBytes[6])<<8 | int64(lenBytes[7])
	}

	// Check frame size limit
	if payloadLen > fp.maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes", payloadLen)
	}

	// Read masking key if present
	if frame.Masked {
		if _, err := io.ReadFull(conn, frame.MaskKey[:]); err != nil {
			return nil, err
		}
	}

	// Read payload
	if payloadLen > 0 {
		frame.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, frame.Payload); err != nil {
			return nil, err
		}

		// Unmask payload if needed
		if frame.Masked {
			for i := int64(0); i < payloadLen; i++ {
				frame.Payload[i] ^= frame.MaskKey[i%4]
			}
		}
	}

	return frame, nil
}

// WriteFrame writes a WebSocket frame to connection
func (fp *FrameParser) WriteFrame(conn net.Conn, frame *WebSocketFrame) error {
	var header []byte

	// First byte: FIN, RSV, opcode
	firstByte := frame.Opcode
	if frame.Fin {
		firstByte |= 0x80
	}
	if frame.RSV1 {
		firstByte |= 0x40
	}
	if frame.RSV2 {
		firstByte |= 0x20
	}
	if frame.RSV3 {
		firstByte |= 0x10
	}
	header = append(header, firstByte)

	// Second byte and payload length
	payloadLen := len(frame.Payload)
	if payloadLen < 126 {
		secondByte := uint8(payloadLen)
		if frame.Masked {
			secondByte |= 0x80
		}
		header = append(header, secondByte)
	} else if payloadLen < 65536 {
		secondByte := uint8(126)
		if frame.Masked {
			secondByte |= 0x80
		}
		header = append(header, secondByte)
		header = append(header, uint8(payloadLen>>8), uint8(payloadLen))
	} else {
		secondByte := uint8(127)
		if frame.Masked {
			secondByte |= 0x80
		}
		header = append(header, secondByte)
		for i := 7; i >= 0; i-- {
			header = append(header, uint8(payloadLen>>(i*8)))
		}
	}

	// Add masking key if needed
	if frame.Masked {
		header = append(header, frame.MaskKey[:]...)
	}

	// Write header
	if _, err := conn.Write(header); err != nil {
		return err
	}

	// Write payload (mask if needed)
	if len(frame.Payload) > 0 {
		if frame.Masked {
			masked := make([]byte, len(frame.Payload))
			for i, b := range frame.Payload {
				masked[i] = b ^ frame.MaskKey[i%4]
			}
			_, err := conn.Write(masked)
			return err
		} else {
			_, err := conn.Write(frame.Payload)
			return err
		}
	}

	return nil
}

// Helper functions

func (ws *WebSocketProxy) generateConnectionID() string {
	return fmt.Sprintf("ws-%d", time.Now().UnixNano())
}

func (ws *WebSocketProxy) generateWebSocketKey() string {
	key := make([]byte, 16)
	// In practice, use crypto/rand
	for i := range key {
		key[i] = byte(time.Now().UnixNano() % 256)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func (ws *WebSocketProxy) generateAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(WebSocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (ws *WebSocketProxy) sendPing(wsConn *WebSocketConnection) error {
	pingFrame := &WebSocketFrame{
		Fin:    true,
		Opcode: OpcodePing,
		Payload: []byte("ping"),
	}
	
	wsConn.LastPing = time.Now()
	return ws.messageProcessor.frameParser.WriteFrame(wsConn.ClientConn, pingFrame)
}

func (ws *WebSocketProxy) decompressPayload(payload []byte) ([]byte, error) {
	// Simplified decompression - would use actual deflate decompression
	return payload, nil
}

func (ws *WebSocketProxy) closeConnection(wsConn *WebSocketConnection) {
	ws.mu.Lock()
	delete(ws.connections, wsConn.ID)
	ws.mu.Unlock()

	if wsConn.ClientConn != nil {
		wsConn.ClientConn.Close()
	}
	if wsConn.BackendConn != nil {
		wsConn.BackendConn.Close()
	}

	wsConn.State = StateClosed
	atomic.AddUint64(&ws.stats.ActiveConnections, ^uint64(0)) // Decrement

	fmt.Printf("WebSocket: Closed connection %s\n", wsConn.ID)
}

// GetStats returns WebSocket proxy statistics
func (ws *WebSocketProxy) GetStats() *WebSocketStats {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	stats := *ws.stats
	stats.ActiveConnections = uint64(len(ws.connections))
	stats.LastUpdate = time.Now()
	return &stats
}

// GetConnections returns active WebSocket connections
func (ws *WebSocketProxy) GetConnections() map[string]*WebSocketConnection {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	connections := make(map[string]*WebSocketConnection)
	for id, conn := range ws.connections {
		// Return pointers to existing connections instead of copying
		// (copying would cause mutex copy error due to sync.RWMutex)
		connections[id] = conn
	}
	return connections
}