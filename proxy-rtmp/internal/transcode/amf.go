package transcode

import "fmt"

// AMD AMF hardware encoder configuration

// NewAMFH264Config creates AMD AMF H.264 encoder configuration
func NewAMFH264Config(preset string) *EncoderConfig {
	return &EncoderConfig{
		Name:    "amf_h264",
		Codec:   "h264",
		Encoder: "h264_amf",
		HWAccel: "amf",
		Preset:  mapPresetToAMF(preset),
		Params: map[string]string{
			"profile":        "high",
			"level":          "4.1",
			"rc":             "vbr_latency", // VBR with low latency
			"qp_i":           "23",
			"qp_p":           "23",
			"qp_b":           "23",
			"quality":        "quality", // quality, balanced, speed
			"preanalysis":    "1",
			"vbaq":           "1", // Variance-based adaptive quantization
			"enforce_hrd":    "1",
			"filler_data":    "0",
			"frame_skipping": "0",
		},
		Bitrates: DefaultBitrateLadder(),
	}
}

// NewAMFH265Config creates AMD AMF H.265 encoder configuration
func NewAMFH265Config(preset string) *EncoderConfig {
	return &EncoderConfig{
		Name:    "amf_h265",
		Codec:   "h265",
		Encoder: "hevc_amf",
		HWAccel: "amf",
		Preset:  mapPresetToAMF(preset),
		Params: map[string]string{
			"profile":        "main",
			"level":          "4.1",
			"rc":             "vbr_latency",
			"qp_i":           "23",
			"qp_p":           "23",
			"quality":        "quality",
			"preanalysis":    "1",
			"vbaq":           "1",
			"enforce_hrd":    "1",
			"filler_data":    "0",
			"frame_skipping": "0",
		},
		Bitrates: DefaultBitrateLadder(),
	}
}

// mapPresetToAMF maps CPU preset names to AMF quality presets
func mapPresetToAMF(preset string) string {
	// AMF uses: speed, balanced, quality
	mapping := map[string]string{
		"ultrafast": "speed",
		"superfast": "speed",
		"veryfast":  "speed",
		"faster":    "balanced",
		"fast":      "balanced",
		"medium":    "balanced",
		"slow":      "quality",
		"slower":    "quality",
		"veryslow":  "quality",
	}

	if amfPreset, ok := mapping[preset]; ok {
		return amfPreset
	}
	return "balanced" // Default to balanced
}

// GetFFmpegArgsAMF returns FFmpeg arguments for AMF encoding
func (e *EncoderConfig) GetFFmpegArgsAMF(input string, output string, bitrate BitrateConfig) []string {
	args := []string{
		"-hwaccel", "auto",
		"-i", input,
		"-c:v", e.Encoder,
		"-quality", e.Preset,
		"-b:v", fmt.Sprintf("%dk", bitrate.Bitrate),
		"-maxrate", fmt.Sprintf("%dk", bitrate.Bitrate),
		"-bufsize", fmt.Sprintf("%dk", bitrate.Bitrate*bitrate.BufferSize),
		"-vf", fmt.Sprintf("scale=%d:%d", bitrate.Width, bitrate.Height),
		"-r", fmt.Sprintf("%d", bitrate.Framerate),
		"-c:a", "aac",
		"-b:a", fmt.Sprintf("%dk", bitrate.AudioRate),
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
