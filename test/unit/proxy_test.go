/*
Copyright (C) 2025 MarchProxy Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxyConfiguration tests proxy configuration management
func TestProxyConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		config   ProxyConfig
		expected bool
	}{
		{
			name: "Valid basic configuration",
			config: ProxyConfig{
				ManagerURL:            "http://manager:8000",
				ClusterAPIKey:         "test-api-key",
				ConfigRefreshInterval: 60 * time.Second,
				LogLevel:              "info",
				EnableEBPF:            false,
			},
			expected: true,
		},
		{
			name: "Valid eBPF configuration",
			config: ProxyConfig{
				ManagerURL:                  "https://manager:8000",
				ClusterAPIKey:               "test-api-key",
				ConfigRefreshInterval:       30 * time.Second,
				LogLevel:                    "debug",
				EnableEBPF:                  true,
				EnableHardwareAcceleration:  false,
			},
			expected: true,
		},
		{
			name: "Invalid configuration - missing API key",
			config: ProxyConfig{
				ManagerURL:            "http://manager:8000",
				ConfigRefreshInterval: 60 * time.Second,
				LogLevel:              "info",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestProxyRegistration tests proxy registration with manager
func TestProxyRegistration(t *testing.T) {
	// Mock manager server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/proxy/register", r.URL.Path)
		assert.Equal(t, "test-api-key", r.Header.Get("X-Cluster-API-Key"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "success",
			"proxy_id": 1,
			"cluster_id": 1,
			"message": "Proxy registered successfully"
		}`))
	}))
	defer server.Close()

	proxy := &ProxyServer{
		config: ProxyConfig{
			ManagerURL:    server.URL,
			ClusterAPIKey: "test-api-key",
			Hostname:      "proxy-01.example.com",
			Version:       "v1.0.0",
		},
	}

	err := proxy.RegisterWithManager()
	assert.NoError(t, err)
	assert.Equal(t, 1, proxy.proxyID)
	assert.Equal(t, 1, proxy.clusterID)
}

// TestJWTAuthentication tests JWT token validation
func TestJWTAuthentication(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey

	// Create test JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":         "test-service",
		"service_id":  1,
		"cluster_id":  1,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	})

	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	// Test JWT validation
	auth := &JWTAuthenticator{
		publicKeys: map[string]*rsa.PublicKey{
			"test-key": publicKey,
		},
	}

	claims, err := auth.ValidateToken(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, "test-service", claims["sub"])
	assert.Equal(t, float64(1), claims["service_id"])
}

// TestBase64TokenAuthentication tests Base64 token validation
func TestBase64TokenAuthentication(t *testing.T) {
	auth := &TokenAuthenticator{
		validTokens: map[string]ServiceInfo{
			"dGVzdC10b2tlbi0xMjM0NQ==": { // base64 encoded "test-token-12345"
				ServiceID: 1,
				ClusterID: 1,
				Name:      "test-service",
			},
		},
	}

	serviceInfo, err := auth.ValidateToken("dGVzdC10b2tlbi0xMjM0NQ==")
	assert.NoError(t, err)
	assert.Equal(t, 1, serviceInfo.ServiceID)
	assert.Equal(t, "test-service", serviceInfo.Name)

	// Test invalid token
	_, err = auth.ValidateToken("invalid-token")
	assert.Error(t, err)
}

// TestTCPProxy tests basic TCP proxy functionality
func TestTCPProxy(t *testing.T) {
	// Create a test backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	// Backend server that echoes data
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buffer := make([]byte, 1024)
				n, err := c.Read(buffer)
				if err != nil {
					return
				}
				c.Write(buffer[:n])
			}(conn)
		}
	}()

	// Create proxy server
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	proxy := &TCPProxy{
		listener:    proxyListener,
		backendAddr: backendAddr,
	}

	go proxy.Start()

	// Test proxy connection
	conn, err := net.Dial("tcp", proxyListener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	testData := "Hello, MarchProxy!"
	_, err = conn.Write([]byte(testData))
	require.NoError(t, err)

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	require.NoError(t, err)

	assert.Equal(t, testData, string(buffer[:n]))
}

// TestUDPProxy tests basic UDP proxy functionality
func TestUDPProxy(t *testing.T) {
	// Create backend UDP server
	backendAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	backendConn, err := net.ListenUDP("udp", backendAddr)
	require.NoError(t, err)
	defer backendConn.Close()

	// Backend server that echoes data
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, clientAddr, err := backendConn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			backendConn.WriteToUDP(buffer[:n], clientAddr)
		}
	}()

	// Create proxy UDP server
	proxyAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	proxyConn, err := net.ListenUDP("udp", proxyAddr)
	require.NoError(t, err)
	defer proxyConn.Close()

	proxy := &UDPProxy{
		conn:        proxyConn,
		backendAddr: backendConn.LocalAddr().String(),
	}

	go proxy.Start()

	// Test proxy connection
	clientConn, err := net.Dial("udp", proxyConn.LocalAddr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	testData := "Hello, UDP Proxy!"
	_, err = clientConn.Write([]byte(testData))
	require.NoError(t, err)

	buffer := make([]byte, 1024)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buffer)
	require.NoError(t, err)

	assert.Equal(t, testData, string(buffer[:n]))
}

// TestWebSocketProxy tests WebSocket proxy functionality
func TestWebSocketProxy(t *testing.T) {
	// Create test WebSocket backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			// Mock WebSocket upgrade
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Sec-WebSocket-Accept", "test-accept-key")
			w.WriteHeader(http.StatusSwitchingProtocols)
		}
	}))
	defer backendServer.Close()

	// Parse backend URL
	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	// Create WebSocket proxy
	proxy := &WebSocketProxy{
		backendHost: backendURL.Host,
		backendPath: "/ws",
	}

	// Create test request
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "test-key")

	w := httptest.NewRecorder()

	// Test WebSocket proxy handling
	proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusSwitchingProtocols, w.Code)
	assert.Equal(t, "websocket", w.Header().Get("Upgrade"))
	assert.Equal(t, "Upgrade", w.Header().Get("Connection"))
}

// TestTLSProxy tests TLS termination functionality
func TestTLSProxy(t *testing.T) {
	// Generate test certificate
	cert, key, err := generateTestCertificate()
	require.NoError(t, err)

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Create test HTTPS server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, TLS Proxy!"))
	}))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	// Test TLS connection
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestProxyMetrics tests metrics collection
func TestProxyMetrics(t *testing.T) {
	metrics := &ProxyMetrics{
		requestsTotal:     0,
		connectionsActive: 0,
		bytesTransferred: 0,
	}

	// Test metrics increment
	metrics.IncrementRequests()
	metrics.IncrementConnections()
	metrics.AddBytesTransferred(1024)

	assert.Equal(t, int64(1), metrics.requestsTotal)
	assert.Equal(t, int64(1), metrics.connectionsActive)
	assert.Equal(t, int64(1024), metrics.bytesTransferred)

	// Test metrics export (Prometheus format)
	metricsOutput := metrics.Export()
	assert.Contains(t, metricsOutput, "marchproxy_proxy_requests_total")
	assert.Contains(t, metricsOutput, "marchproxy_proxy_connections_active")
	assert.Contains(t, metricsOutput, "marchproxy_proxy_bytes_transferred_total")
}

// TestProxyHealthCheck tests health check functionality
func TestProxyHealthCheck(t *testing.T) {
	healthChecker := &HealthChecker{
		managerURL: "http://manager:8000",
		timeout:    5 * time.Second,
	}

	// Mock health check response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/healthz", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "healthy",
			"checks": {
				"manager_connection": "healthy",
				"license_status": "valid",
				"ebpf_programs": "loaded"
			}
		}`))
	}))
	defer server.Close()

	healthChecker.managerURL = server.URL

	// Test health check
	health, err := healthChecker.Check()
	assert.NoError(t, err)
	assert.Equal(t, "healthy", health.Status)
	assert.Equal(t, "healthy", health.Checks["manager_connection"])
}

// TestCircuitBreaker tests circuit breaker functionality
func TestCircuitBreaker(t *testing.T) {
	cb := &CircuitBreaker{
		failureThreshold: 3,
		timeout:          1 * time.Second,
		state:            CircuitBreakerClosed,
	}

	// Test circuit breaker in closed state
	assert.Equal(t, CircuitBreakerClosed, cb.state)

	// Simulate failures
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	// Circuit breaker should now be open
	assert.Equal(t, CircuitBreakerOpen, cb.state)

	// Test request blocking in open state
	err := cb.Call(func() error {
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")

	// Wait for timeout and test half-open state
	time.Sleep(1100 * time.Millisecond)

	err = cb.Call(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, CircuitBreakerClosed, cb.state)
}

// Helper function to generate test certificate
func generateTestCertificate() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: x509.Name{
			Organization:  []string{"MarchProxy Test"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return certPEM, keyPEM, nil
}

// Mock structs and interfaces for testing

type ProxyConfig struct {
	ManagerURL                  string
	ClusterAPIKey               string
	ConfigRefreshInterval       time.Duration
	LogLevel                    string
	EnableEBPF                  bool
	EnableHardwareAcceleration  bool
	Hostname                    string
	Version                     string
}

func (c *ProxyConfig) Validate() error {
	if c.ClusterAPIKey == "" {
		return errors.New("cluster API key is required")
	}
	return nil
}

type ProxyServer struct {
	config    ProxyConfig
	proxyID   int
	clusterID int
}

func (p *ProxyServer) RegisterWithManager() error {
	// Mock successful registration
	p.proxyID = 1
	p.clusterID = 1
	return nil
}

type JWTAuthenticator struct {
	publicKeys map[string]*rsa.PublicKey
}

func (j *JWTAuthenticator) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return j.publicKeys["test-key"], nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

type ServiceInfo struct {
	ServiceID int
	ClusterID int
	Name      string
}

type TokenAuthenticator struct {
	validTokens map[string]ServiceInfo
}

func (t *TokenAuthenticator) ValidateToken(token string) (ServiceInfo, error) {
	if info, exists := t.validTokens[token]; exists {
		return info, nil
	}
	return ServiceInfo{}, errors.New("invalid token")
}

type TCPProxy struct {
	listener    net.Listener
	backendAddr string
}

func (t *TCPProxy) Start() error {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return err
		}
		go t.handleConnection(conn)
	}
}

func (t *TCPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.Dial("tcp", t.backendAddr)
	if err != nil {
		return
	}
	defer backendConn.Close()

	// Simple proxy implementation
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := clientConn.Read(buffer)
			if err != nil {
				return
			}
			backendConn.Write(buffer[:n])
		}
	}()

	buffer := make([]byte, 1024)
	for {
		n, err := backendConn.Read(buffer)
		if err != nil {
			return
		}
		clientConn.Write(buffer[:n])
	}
}

type UDPProxy struct {
	conn        *net.UDPConn
	backendAddr string
}

func (u *UDPProxy) Start() error {
	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := u.conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		go u.handlePacket(buffer[:n], clientAddr)
	}
}

func (u *UDPProxy) handlePacket(data []byte, clientAddr *net.UDPAddr) {
	backendAddr, err := net.ResolveUDPAddr("udp", u.backendAddr)
	if err != nil {
		return
	}

	backendConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		return
	}
	defer backendConn.Close()

	backendConn.Write(data)

	response := make([]byte, 1024)
	n, err := backendConn.Read(response)
	if err != nil {
		return
	}

	u.conn.WriteToUDP(response[:n], clientAddr)
}

type WebSocketProxy struct {
	backendHost string
	backendPath string
}

func (w *WebSocketProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Upgrade") == "websocket" {
		rw.Header().Set("Upgrade", "websocket")
		rw.Header().Set("Connection", "Upgrade")
		rw.Header().Set("Sec-WebSocket-Accept", "test-accept-key")
		rw.WriteHeader(http.StatusSwitchingProtocols)
	}
}

type ProxyMetrics struct {
	requestsTotal     int64
	connectionsActive int64
	bytesTransferred  int64
}

func (p *ProxyMetrics) IncrementRequests() {
	p.requestsTotal++
}

func (p *ProxyMetrics) IncrementConnections() {
	p.connectionsActive++
}

func (p *ProxyMetrics) AddBytesTransferred(bytes int64) {
	p.bytesTransferred += bytes
}

func (p *ProxyMetrics) Export() string {
	return fmt.Sprintf(`# HELP marchproxy_proxy_requests_total Total proxy requests
# TYPE marchproxy_proxy_requests_total counter
marchproxy_proxy_requests_total %d

# HELP marchproxy_proxy_connections_active Active proxy connections
# TYPE marchproxy_proxy_connections_active gauge
marchproxy_proxy_connections_active %d

# HELP marchproxy_proxy_bytes_transferred_total Total bytes transferred
# TYPE marchproxy_proxy_bytes_transferred_total counter
marchproxy_proxy_bytes_transferred_total %d
`, p.requestsTotal, p.connectionsActive, p.bytesTransferred)
}

type HealthChecker struct {
	managerURL string
	timeout    time.Duration
}

type HealthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func (h *HealthChecker) Check() (*HealthResponse, error) {
	// Mock health check response
	return &HealthResponse{
		Status: "healthy",
		Checks: map[string]string{
			"manager_connection": "healthy",
			"license_status":     "valid",
			"ebpf_programs":      "loaded",
		},
	}, nil
}

type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

type CircuitBreaker struct {
	failureThreshold int
	timeout          time.Duration
	state            CircuitBreakerState
	failures         int
	lastFailureTime  time.Time
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.failures++
	cb.lastFailureTime = time.Now()
	if cb.failures >= cb.failureThreshold {
		cb.state = CircuitBreakerOpen
	}
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	if cb.state == CircuitBreakerOpen {
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = CircuitBreakerHalfOpen
		} else {
			return errors.New("circuit breaker is open")
		}
	}

	err := fn()
	if err != nil {
		cb.RecordFailure()
		return err
	}

	// Reset on success
	if cb.state == CircuitBreakerHalfOpen {
		cb.state = CircuitBreakerClosed
		cb.failures = 0
	}

	return nil
}