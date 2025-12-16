package transcode

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/penguintech/marchproxy/proxy-rtmp/internal/config"
	"github.com/sirupsen/logrus"
)

// ProcessStatus represents FFmpeg process status
type ProcessStatus string

const (
	StatusIdle     ProcessStatus = "idle"
	StatusStarting ProcessStatus = "starting"
	StatusRunning  ProcessStatus = "running"
	StatusStopping ProcessStatus = "stopping"
	StatusStopped  ProcessStatus = "stopped"
	StatusError    ProcessStatus = "error"
)

// Process represents a running FFmpeg process
type Process struct {
	ID          string
	StreamKey   string
	InputURL    string
	OutputPaths map[string]string // format -> path (hls, dash)
	Encoder     *EncoderConfig
	Bitrate     BitrateConfig
	Cmd         *exec.Cmd
	Status      ProcessStatus
	StartTime   time.Time
	StopTime    time.Time
	Error       error
	mutex       sync.RWMutex
}

// Manager manages FFmpeg processes
type Manager struct {
	config    *config.Config
	encoder   *EncoderConfig
	processes map[string]*Process
	mutex     sync.RWMutex
}

// NewManager creates a new FFmpeg manager
func NewManager(encoder *EncoderConfig, cfg *config.Config) *Manager {
	return &Manager{
		config:    cfg,
		encoder:   encoder,
		processes: make(map[string]*Process),
	}
}

// StartTranscode starts a new transcoding process
func (m *Manager) StartTranscode(ctx context.Context, streamKey string, inputURL string, bitrate BitrateConfig) (*Process, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if already transcoding
	if _, exists := m.processes[streamKey]; exists {
		return nil, fmt.Errorf("transcoding already running for stream: %s", streamKey)
	}

	// Create output paths
	outputPaths := make(map[string]string)
	if m.config.EnableHLS {
		outputPaths["hls"] = fmt.Sprintf("%s/%s/index.m3u8", m.config.OutputDir, streamKey)
	}
	if m.config.EnableDASH {
		outputPaths["dash"] = fmt.Sprintf("%s/%s/manifest.mpd", m.config.OutputDir, streamKey)
	}

	// Create process
	proc := &Process{
		ID:          streamKey,
		StreamKey:   streamKey,
		InputURL:    inputURL,
		OutputPaths: outputPaths,
		Encoder:     m.encoder,
		Bitrate:     bitrate,
		Status:      StatusStarting,
		StartTime:   time.Now(),
	}

	// Build FFmpeg command
	args := m.buildFFmpegArgs(inputURL, outputPaths, bitrate)
	proc.Cmd = exec.CommandContext(ctx, m.config.FFmpegPath, args...)

	logrus.WithFields(logrus.Fields{
		"stream_key": streamKey,
		"encoder":    m.encoder.Name,
		"bitrate":    bitrate.Name,
		"args":       args,
	}).Info("Starting FFmpeg process")

	// Start process
	if err := proc.Cmd.Start(); err != nil {
		proc.Status = StatusError
		proc.Error = err
		return nil, fmt.Errorf("failed to start FFmpeg: %w", err)
	}

	proc.Status = StatusRunning
	m.processes[streamKey] = proc

	// Monitor process
	go m.monitorProcess(ctx, proc)

	return proc, nil
}

// buildFFmpegArgs builds FFmpeg command arguments
func (m *Manager) buildFFmpegArgs(input string, outputs map[string]string, bitrate BitrateConfig) []string {
	var args []string

	// Input
	args = append(args, "-i", input)

	// Video encoding based on encoder type
	switch m.encoder.HWAccel {
	case "cuda": // NVIDIA
		args = append(args,
			"-hwaccel", "cuda",
			"-hwaccel_output_format", "cuda",
			"-c:v", m.encoder.Encoder,
			"-preset", m.encoder.Preset,
			"-vf", fmt.Sprintf("scale_cuda=%d:%d", bitrate.Width, bitrate.Height),
		)
	case "amf": // AMD
		args = append(args,
			"-hwaccel", "auto",
			"-c:v", m.encoder.Encoder,
			"-quality", m.encoder.Preset,
			"-vf", fmt.Sprintf("scale=%d:%d", bitrate.Width, bitrate.Height),
		)
	default: // CPU
		args = append(args,
			"-c:v", m.encoder.Encoder,
			"-preset", m.encoder.Preset,
			"-vf", fmt.Sprintf("scale=%d:%d", bitrate.Width, bitrate.Height),
		)
	}

	// Common video params
	args = append(args,
		"-b:v", fmt.Sprintf("%dk", bitrate.Bitrate),
		"-maxrate", fmt.Sprintf("%dk", bitrate.Bitrate),
		"-bufsize", fmt.Sprintf("%dk", bitrate.Bitrate*bitrate.BufferSize),
		"-r", fmt.Sprintf("%d", bitrate.Framerate),
		"-g", "60", // GOP size
	)

	// Add encoder-specific params
	for key, value := range m.encoder.Params {
		args = append(args, "-"+key, value)
	}

	// Audio encoding
	args = append(args,
		"-c:a", "aac",
		"-b:a", fmt.Sprintf("%dk", bitrate.AudioRate),
		"-ar", "48000",
		"-ac", "2",
	)

	// HLS output
	if hlsPath, ok := outputs["hls"]; ok {
		args = append(args,
			"-f", "hls",
			"-hls_time", fmt.Sprintf("%d", m.config.SegmentDuration),
			"-hls_list_size", "10",
			"-hls_flags", "delete_segments+independent_segments",
			"-hls_segment_type", "mpegts",
			"-hls_segment_filename", fmt.Sprintf("%s/%%03d.ts", m.config.OutputDir),
			hlsPath,
		)
	}

	// DASH output (separate command needed, simplified here)
	if dashPath, ok := outputs["dash"]; ok {
		args = append(args,
			"-f", "dash",
			"-seg_duration", fmt.Sprintf("%d", m.config.SegmentDuration),
			"-window_size", "10",
			"-extra_window_size", "5",
			"-remove_at_exit", "1",
			dashPath,
		)
	}

	return args
}

// monitorProcess monitors FFmpeg process lifecycle
func (m *Manager) monitorProcess(ctx context.Context, proc *Process) {
	defer func() {
		m.mutex.Lock()
		delete(m.processes, proc.StreamKey)
		m.mutex.Unlock()
	}()

	// Wait for process to complete or context cancellation
	errChan := make(chan error, 1)
	go func() {
		errChan <- proc.Cmd.Wait()
	}()

	select {
	case err := <-errChan:
		proc.mutex.Lock()
		proc.StopTime = time.Now()
		if err != nil {
			proc.Status = StatusError
			proc.Error = err
			logrus.WithError(err).WithField("stream_key", proc.StreamKey).Error("FFmpeg process failed")
		} else {
			proc.Status = StatusStopped
			logrus.WithField("stream_key", proc.StreamKey).Info("FFmpeg process stopped normally")
		}
		proc.mutex.Unlock()

	case <-ctx.Done():
		proc.mutex.Lock()
		proc.Status = StatusStopping
		proc.mutex.Unlock()

		// Kill process
		if proc.Cmd.Process != nil {
			proc.Cmd.Process.Kill()
		}

		proc.mutex.Lock()
		proc.Status = StatusStopped
		proc.StopTime = time.Now()
		proc.mutex.Unlock()

		logrus.WithField("stream_key", proc.StreamKey).Info("FFmpeg process stopped by context")
	}
}

// StopTranscode stops a transcoding process
func (m *Manager) StopTranscode(streamKey string) error {
	m.mutex.Lock()
	proc, exists := m.processes[streamKey]
	if !exists {
		m.mutex.Unlock()
		return fmt.Errorf("no transcoding process for stream: %s", streamKey)
	}
	m.mutex.Unlock()

	proc.mutex.Lock()
	defer proc.mutex.Unlock()

	if proc.Cmd.Process != nil {
		proc.Status = StatusStopping
		if err := proc.Cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process: %w", err)
		}
	}

	return nil
}

// GetProcess returns process information
func (m *Manager) GetProcess(streamKey string) (*Process, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	proc, exists := m.processes[streamKey]
	return proc, exists
}

// GetAllProcesses returns all active processes
func (m *Manager) GetAllProcesses() []*Process {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	processes := make([]*Process, 0, len(m.processes))
	for _, proc := range m.processes {
		processes = append(processes, proc)
	}
	return processes
}

// GetStats returns manager statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_processes": len(m.processes),
		"encoder":         m.encoder.Name,
		"codec":           m.encoder.Codec,
		"hw_accel":        m.encoder.HWAccel,
	}

	statusCounts := make(map[ProcessStatus]int)
	for _, proc := range m.processes {
		proc.mutex.RLock()
		statusCounts[proc.Status]++
		proc.mutex.RUnlock()
	}
	stats["status_counts"] = statusCounts

	return stats
}
