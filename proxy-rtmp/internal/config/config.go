package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config holds the RTMP proxy configuration
type Config struct {
	// Server settings
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	GRPCPort int    `mapstructure:"grpc-port"`

	// Logging
	LogLevel string `mapstructure:"log-level"`

	// Encoder settings
	Encoder string `mapstructure:"encoder"` // auto, x264, x265, nvenc_h264, nvenc_h265, amf_h264, amf_h265
	Preset  string `mapstructure:"preset"`  // ultrafast, fast, medium, slow

	// Output settings
	OutputDir       string `mapstructure:"output-dir"`
	EnableHLS       bool   `mapstructure:"enable-hls"`
	EnableDASH      bool   `mapstructure:"enable-dash"`
	SegmentDuration int    `mapstructure:"segment-duration"` // seconds

	// FFmpeg settings
	FFmpegPath    string            `mapstructure:"ffmpeg-path"`
	FFprobePath   string            `mapstructure:"ffprobe-path"`
	EncoderParams map[string]string `mapstructure:"encoder-params"`

	// Rate limiting (per route)
	MaxBitrate    int `mapstructure:"max-bitrate"`    // Mbps
	MaxStreams    int `mapstructure:"max-streams"`    // concurrent streams
	MaxResolution int `mapstructure:"max-resolution"` // height in pixels

	// Health check
	HealthCheckInterval int `mapstructure:"health-check-interval"` // seconds
}

// Load loads configuration from file and environment
func Load(cfgFile string) (*Config, error) {
	// Set defaults
	viper.SetDefault("host", "0.0.0.0")
	viper.SetDefault("port", 1935)
	viper.SetDefault("grpc-port", 50053)
	viper.SetDefault("log-level", "info")
	viper.SetDefault("encoder", "auto")
	viper.SetDefault("preset", "medium")
	viper.SetDefault("output-dir", "/var/lib/marchproxy/streams")
	viper.SetDefault("enable-hls", true)
	viper.SetDefault("enable-dash", true)
	viper.SetDefault("segment-duration", 6)
	viper.SetDefault("ffmpeg-path", "ffmpeg")
	viper.SetDefault("ffprobe-path", "ffprobe")
	viper.SetDefault("max-bitrate", 10)      // 10 Mbps default
	viper.SetDefault("max-streams", 100)     // 100 concurrent streams
	viper.SetDefault("max-resolution", 1080) // 1080p max
	viper.SetDefault("health-check-interval", 30)

	// Load config file if specified
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("rtmp")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/marchproxy/")
		viper.AddConfigPath(".")
	}

	// Environment variables
	viper.SetEnvPrefix("RTMP")
	viper.AutomaticEnv()

	// Read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
	}

	// Unmarshal config
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate and create output directory
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	if c.GRPCPort < 1 || c.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.GRPCPort)
	}

	if c.SegmentDuration < 1 || c.SegmentDuration > 60 {
		return fmt.Errorf("segment duration must be between 1 and 60 seconds")
	}

	validEncoders := map[string]bool{
		"auto": true, "x264": true, "x265": true,
		"nvenc_h264": true, "nvenc_h265": true,
		"amf_h264": true, "amf_h265": true,
	}
	if !validEncoders[c.Encoder] {
		return fmt.Errorf("invalid encoder: %s", c.Encoder)
	}

	validPresets := map[string]bool{
		"ultrafast": true, "superfast": true, "veryfast": true,
		"faster": true, "fast": true, "medium": true,
		"slow": true, "slower": true, "veryslow": true,
	}
	if !validPresets[c.Preset] {
		return fmt.Errorf("invalid preset: %s", c.Preset)
	}

	return nil
}
