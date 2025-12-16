// Package proxy implements the core proxy server functionality
package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"marchproxy-egress/internal/config"
	"marchproxy-egress/internal/logging"
	"marchproxy-egress/internal/monitoring"
)

// Server represents the main proxy server
type Server struct {
	config    *config.Config
	logger    *logging.Logger
	monitor   *monitoring.Monitor
	listener  net.Listener
	mu        sync.RWMutex
	shutdown  chan struct{}
	wg        sync.WaitGroup
}

// NewServer creates a new proxy server instance
func NewServer(cfg *config.Config, logger *logging.Logger, monitor *monitoring.Monitor) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	
	server := &Server{
		config:   cfg,
		logger:   logger.WithField("component", "proxy_server"),
		monitor:  monitor,
		shutdown: make(chan struct{}),
	}
	
	return server, nil
}

// Start begins accepting connections and handling traffic
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting proxy server",
		"listen_address", s.config.GetListenAddress(),
		"ebpf_enabled", s.config.EnableEBPF,
		"worker_threads", s.config.WorkerThreads,
	)
	
	// Create TCP listener
	listener, err := net.Listen("tcp", s.config.GetListenAddress())
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	
	s.logger.Info("Proxy server listening", "address", listener.Addr().String())
	
	// Initialize eBPF if enabled
	if s.config.EnableEBPF {
		if err := s.initializeEBPF(); err != nil {
			s.logger.Error("Failed to initialize eBPF", "error", err)
			// Continue without eBPF acceleration
		} else {
			s.logger.Info("eBPF acceleration enabled")
		}
	}
	
	// Set monitor health checker if available
	if s.monitor != nil {
		s.monitor.SetHealthChecker(s)
	}
	
	// Start accepting connections
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptConnections(ctx)
	}()
	
	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		s.logger.Info("Proxy server stopping due to context cancellation")
		return ctx.Err()
	case <-s.shutdown:
		s.logger.Info("Proxy server stopped")
		return nil
	}
}

// Shutdown gracefully stops the proxy server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down proxy server")
	
	s.mu.Lock()
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Unlock()
	
	// Signal shutdown
	close(s.shutdown)
	
	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		s.logger.Info("Proxy server shutdown completed")
		return nil
	case <-ctx.Done():
		s.logger.Warn("Proxy server shutdown timed out")
		return ctx.Err()
	}
}

// IsHealthy implements the HealthChecker interface
func (s *Server) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listener != nil
}

// GetStatus implements the HealthChecker interface
func (s *Server) GetStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	status := map[string]interface{}{
		"listener_active": s.listener != nil,
		"ebpf_enabled":    s.config.EnableEBPF,
		"worker_threads":  s.config.WorkerThreads,
	}
	
	if s.listener != nil {
		status["listen_address"] = s.listener.Addr().String()
	}
	
	return status
}

// acceptConnections accepts incoming connections and handles them
func (s *Server) acceptConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		default:
			s.mu.RLock()
			listener := s.listener
			s.mu.RUnlock()
			
			if listener == nil {
				return
			}
			
			// Set accept timeout to allow for graceful shutdown
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}
			
			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout is expected, try again
				}
				s.logger.Error("Failed to accept connection", "error", err)
				continue
			}
			
			s.logger.Debug("Accepted connection", 
				"remote_addr", conn.RemoteAddr().String(),
				"local_addr", conn.LocalAddr().String(),
			)
			
			// Record connection in metrics
			if s.monitor != nil {
				s.monitor.RecordConnection("tcp", 
					conn.RemoteAddr().String(), 
					conn.LocalAddr().String())
			}
			
			// Handle connection in a separate goroutine
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleConnection(ctx, c)
			}(conn)
		}
	}
}

// handleConnection processes a single client connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	startTime := time.Now()
	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()

	s.logger.Debug("Handling connection", "remote_addr", remoteAddr)

	// TODO: Implement actual proxy logic here
	// This would include:
	// - Protocol detection (HTTP, HTTPS, TCP, etc.)
	// - Authentication (JWT, Base64 tokens)
	// - Load balancing and backend selection
	// - Traffic forwarding and filtering
	// - eBPF acceleration hooks

	// For now, just implement a simple echo server as a placeholder
	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		default:
			// Set read timeout
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))

			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				s.logger.Debug("Connection read error", "error", err, "remote_addr", remoteAddr)
				break
			}

			if n == 0 {
				break
			}

			// Record bytes transferred
			if s.monitor != nil {
				s.monitor.RecordBytesTransferred("inbound", "tcp", int64(n))
			}

			// Echo back (placeholder for actual proxy logic)
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, err := conn.Write(buffer[:n])
			if err != nil {
				s.logger.Debug("Connection write error", "error", err, "remote_addr", remoteAddr)
				break
			}

			// Record bytes transferred
			if s.monitor != nil {
				s.monitor.RecordBytesTransferred("outbound", "tcp", int64(written))
			}
		}

		break // Exit loop after handling one read/write cycle or error
	}

	// Calculate duration after loop exits
	duration := time.Since(startTime)
	s.logger.Debug("Connection closed",
		"remote_addr", remoteAddr,
		"duration", duration.String(),
	)

	// Record connection closure in metrics
	if s.monitor != nil {
		s.monitor.RecordConnectionClosed("tcp", remoteAddr, localAddr, duration)
	}
}

// initializeEBPF sets up eBPF programs for packet filtering and acceleration
func (s *Server) initializeEBPF() error {
	s.logger.Info("Initializing eBPF programs")
	
	// TODO: Implement actual eBPF initialization
	// This would include:
	// - Loading eBPF bytecode
	// - Attaching to network interfaces
	// - Setting up maps for configuration sharing
	// - Implementing packet filtering rules
	
	s.logger.Info("eBPF initialization completed (mock implementation)")
	return nil
}