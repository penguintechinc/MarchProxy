package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/penguintech/marchproxy/proxy-rtmp/internal/config"
	"github.com/penguintech/marchproxy/proxy-rtmp/internal/rtmp"
	"github.com/penguintech/marchproxy/proxy-rtmp/internal/transcode"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Server implements the ModuleService gRPC server
type Server struct {
	config        *config.Config
	rtmpServer    *rtmp.Server
	ffmpegManager *transcode.Manager
	grpcServer    *grpc.Server
	listener      net.Listener
}

// NewServer creates a new gRPC server
func NewServer(cfg *config.Config, rtmpSrv *rtmp.Server, ffmpegMgr *transcode.Manager) *Server {
	return &Server{
		config:        cfg,
		rtmpServer:    rtmpSrv,
		ffmpegManager: ffmpegMgr,
	}
}

// Start starts the gRPC server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.GRPCPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener

	// Create gRPC server
	s.grpcServer = grpc.NewServer()

	// Register health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register ModuleService (placeholder - needs proto definitions)
	// pb.RegisterModuleServiceServer(s.grpcServer, s)

	logrus.WithField("address", addr).Info("gRPC server started")

	// Serve in background
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			logrus.WithError(err).Error("gRPC server error")
		}
	}()

	return nil
}

// Stop stops the gRPC server
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	logrus.Info("gRPC server stopped")
}

// ModuleService implementation (placeholders for proto-generated methods)

// GetStatus returns module status
func (s *Server) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	rtmpStats := s.rtmpServer.GetStats()
	ffmpegStats := s.ffmpegManager.GetStats()

	sessions := s.rtmpServer.GetAllSessions()
	processes := s.ffmpegManager.GetAllProcesses()

	status := map[string]interface{}{
		"module":           "rtmp",
		"version":          "1.0.0",
		"status":           "running",
		"uptime":           time.Since(time.Now()).String(), // TODO: track actual start time
		"rtmp_stats":       rtmpStats,
		"ffmpeg_stats":     ffmpegStats,
		"active_sessions":  len(sessions),
		"active_processes": len(processes),
	}

	return status, nil
}

// GetRoutes returns configured routes
func (s *Server) GetRoutes(ctx context.Context) ([]map[string]interface{}, error) {
	sessions := s.rtmpServer.GetAllSessions()
	routes := make([]map[string]interface{}, len(sessions))

	for i, session := range sessions {
		routes[i] = map[string]interface{}{
			"stream_key": session.StreamKey,
			"client":     session.ClientAddr,
			"status":     session.Status,
			"info":       session.GetInfo(),
		}
	}

	return routes, nil
}

// GetMetrics returns module metrics
func (s *Server) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	rtmpStats := s.rtmpServer.GetStats()
	ffmpegStats := s.ffmpegManager.GetStats()

	sessions := s.rtmpServer.GetAllSessions()
	var totalBytesIn, totalBytesOut int64
	for _, session := range sessions {
		info := session.GetInfo()
		if bytesIn, ok := info["bytes_in"].(int64); ok {
			totalBytesIn += bytesIn
		}
		if bytesOut, ok := info["bytes_out"].(int64); ok {
			totalBytesOut += bytesOut
		}
	}

	metrics := map[string]interface{}{
		"rtmp":            rtmpStats,
		"ffmpeg":          ffmpegStats,
		"total_bytes_in":  totalBytesIn,
		"total_bytes_out": totalBytesOut,
		"sessions_count":  len(sessions),
		"timestamp":       time.Now().Unix(),
	}

	return metrics, nil
}

// HealthCheck performs health check
func (s *Server) HealthCheck(ctx context.Context) (bool, error) {
	// Check if RTMP server is running
	rtmpStats := s.rtmpServer.GetStats()
	if running, ok := rtmpStats["running"].(bool); !ok || !running {
		return false, fmt.Errorf("RTMP server not running")
	}

	// Check FFmpeg manager
	ffmpegStats := s.ffmpegManager.GetStats()
	if encoder, ok := ffmpegStats["encoder"].(string); !ok || encoder == "" {
		return false, fmt.Errorf("FFmpeg manager not initialized")
	}

	return true, nil
}

// GetStats returns detailed statistics
func (s *Server) GetStats(ctx context.Context) (map[string]interface{}, error) {
	rtmpStats := s.rtmpServer.GetStats()
	ffmpegStats := s.ffmpegManager.GetStats()

	sessions := s.rtmpServer.GetAllSessions()
	sessionDetails := make([]map[string]interface{}, len(sessions))
	for i, session := range sessions {
		sessionDetails[i] = session.GetInfo()
	}

	processes := s.ffmpegManager.GetAllProcesses()
	processDetails := make([]map[string]interface{}, len(processes))
	for i, proc := range processes {
		processDetails[i] = map[string]interface{}{
			"stream_key": proc.StreamKey,
			"status":     proc.Status,
			"encoder":    proc.Encoder.Name,
			"codec":      proc.Encoder.Codec,
			"bitrate":    proc.Bitrate.Name,
		}
	}

	stats := map[string]interface{}{
		"rtmp":      rtmpStats,
		"ffmpeg":    ffmpegStats,
		"sessions":  sessionDetails,
		"processes": processDetails,
		"config": map[string]interface{}{
			"port":             s.config.Port,
			"grpc_port":        s.config.GRPCPort,
			"encoder":          s.config.Encoder,
			"enable_hls":       s.config.EnableHLS,
			"enable_dash":      s.config.EnableDASH,
			"segment_duration": s.config.SegmentDuration,
		},
	}

	return stats, nil
}
