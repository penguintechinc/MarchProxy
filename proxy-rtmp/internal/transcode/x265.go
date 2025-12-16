package transcode

import "fmt"

// NewX265Config creates x265 CPU encoder configuration
func NewX265Config(preset string) *EncoderConfig {
	return &EncoderConfig{
		Name:    "x265",
		Codec:   "h265",
		Encoder: "libx265",
		HWAccel: "",
		Preset:  preset,
		Params: map[string]string{
			"tune":         "zerolatency",
			"profile":      "main",
			"level":        "4.1",
			"g":            "60",
			"sc_threshold": "0",
			"x265-params":  "keyint=60:min-keyint=60:scenecut=0",
		},
		Bitrates: DefaultBitrateLadder(),
	}
}

// GetFFmpegArgsX265 returns FFmpeg arguments for x265 encoding
func (e *EncoderConfig) GetFFmpegArgsX265(input string, output string, bitrate BitrateConfig) []string {
	args := []string{
		"-i", input,
		"-c:v", e.Encoder,
		"-preset", e.Preset,
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
