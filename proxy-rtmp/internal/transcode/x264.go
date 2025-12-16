package transcode

// X264 CPU encoder configuration

// EncoderConfig holds encoder configuration
type EncoderConfig struct {
	Name     string            // Encoder name
	Codec    string            // Codec (h264, h265)
	Encoder  string            // FFmpeg encoder name
	HWAccel  string            // Hardware acceleration (empty for CPU)
	Preset   string            // Encoding preset
	Params   map[string]string // Additional encoder parameters
	Bitrates []BitrateConfig   // Adaptive bitrate ladder
}

// BitrateConfig holds bitrate ladder configuration
type BitrateConfig struct {
	Name       string // Profile name (e.g., "1080p", "720p")
	Width      int    // Video width
	Height     int    // Video height
	Bitrate    int    // Video bitrate in kbps
	AudioRate  int    // Audio bitrate in kbps
	Framerate  int    // Target framerate
	BufferSize int    // Buffer size multiplier
}

// NewX264Config creates x264 CPU encoder configuration
func NewX264Config(preset string) *EncoderConfig {
	return &EncoderConfig{
		Name:    "x264",
		Codec:   "h264",
		Encoder: "libx264",
		HWAccel: "",
		Preset:  preset,
		Params: map[string]string{
			"tune":         "zerolatency",
			"profile":      "high",
			"level":        "4.1",
			"g":            "60", // GOP size (2 seconds at 30fps)
			"sc_threshold": "0",
			"flags":        "+cgop", // Closed GOP
		},
		Bitrates: DefaultBitrateLadder(),
	}
}

// DefaultBitrateLadder returns default adaptive bitrate ladder
func DefaultBitrateLadder() []BitrateConfig {
	return []BitrateConfig{
		{
			Name:       "1080p",
			Width:      1920,
			Height:     1080,
			Bitrate:    5000, // 5 Mbps
			AudioRate:  192,  // 192 kbps
			Framerate:  30,
			BufferSize: 2,
		},
		{
			Name:       "720p",
			Width:      1280,
			Height:     720,
			Bitrate:    3000, // 3 Mbps
			AudioRate:  128,  // 128 kbps
			Framerate:  30,
			BufferSize: 2,
		},
		{
			Name:       "480p",
			Width:      854,
			Height:     480,
			Bitrate:    1500, // 1.5 Mbps
			AudioRate:  128,  // 128 kbps
			Framerate:  30,
			BufferSize: 2,
		},
		{
			Name:       "360p",
			Width:      640,
			Height:     360,
			Bitrate:    800, // 800 kbps
			AudioRate:  96,  // 96 kbps
			Framerate:  30,
			BufferSize: 2,
		},
	}
}

// GetFFmpegArgs returns FFmpeg arguments for x264 encoding
func (e *EncoderConfig) GetFFmpegArgs(input string, output string, bitrate BitrateConfig) []string {
	args := []string{
		"-i", input,
		"-c:v", e.Encoder,
		"-preset", e.Preset,
		"-b:v", formatBitrate(bitrate.Bitrate),
		"-maxrate", formatBitrate(bitrate.Bitrate),
		"-bufsize", formatBitrate(bitrate.Bitrate * bitrate.BufferSize),
		"-vf", formatScale(bitrate.Width, bitrate.Height),
		"-r", formatFramerate(bitrate.Framerate),
		"-c:a", "aac",
		"-b:a", formatBitrate(bitrate.AudioRate),
		"-ar", "48000",
		"-ac", "2",
	}

	// Add encoder-specific params
	for key, value := range e.Params {
		args = append(args, "-"+key, value)
	}

	// Output format
	args = append(args, "-f", "flv", output)

	return args
}

// Helper functions
func formatBitrate(kbps int) string {
	return string(rune(kbps)) + "k"
}

func formatScale(width, height int) string {
	return string(rune(width)) + ":" + string(rune(height))
}

func formatFramerate(fps int) string {
	return string(rune(fps))
}
