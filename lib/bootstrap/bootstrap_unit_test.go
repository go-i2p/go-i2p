package bootstrap

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
)

// TestBootstrapTypeConfiguration verifies that different bootstrap types
// can be configured properly.
func TestBootstrapTypeConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		bootstrapType  string
		reseedFilePath string
		wantErr        bool
		description    string
	}{
		{
			name:          "auto type should work",
			bootstrapType: "auto",
			wantErr:       false,
			description:   "Auto should create composite bootstrap",
		},
		{
			name:          "empty type defaults to auto",
			bootstrapType: "",
			wantErr:       false,
			description:   "Empty string should default to composite bootstrap",
		},
		{
			name:           "file type with path should work",
			bootstrapType:  "file",
			reseedFilePath: "/tmp/test.su3",
			wantErr:        false,
			description:    "File type with valid path should work",
		},
		{
			name:          "reseed type should work",
			bootstrapType: "reseed",
			wantErr:       false,
			description:   "Reseed type should create reseed bootstrap",
		},
		{
			name:          "local type should work",
			bootstrapType: "local",
			wantErr:       false,
			description:   "Local type should create local netDb bootstrap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.BootstrapConfig{
				LowPeerThreshold: testLowPeerThreshold,
				BootstrapType:    tt.bootstrapType,
				ReseedFilePath:   tt.reseedFilePath,
				ReseedServers: []*config.ReseedConfig{
					{
						Url:            testReseedServerURL,
						SU3Fingerprint: testReseedFingerprint,
					},
				},
			}

			// Verify that the appropriate bootstrap instance can be created
			var bootstrapper Bootstrap
			switch cfg.BootstrapType {
			case "file":
				if cfg.ReseedFilePath != "" {
					bootstrapper = NewFileBootstrap(cfg.ReseedFilePath)
				}
			case "reseed":
				bootstrapper = NewReseedBootstrap(cfg)
			case "local":
				bootstrapper = NewLocalNetDbBootstrap(cfg)
			case "auto", "":
				bootstrapper = NewCompositeBootstrap(cfg)
			default:
				// Unknown type should fall back to composite
				bootstrapper = NewCompositeBootstrap(cfg)
			}

			if bootstrapper == nil {
				t.Errorf("%s: failed to create bootstrapper for type %q", tt.description, cfg.BootstrapType)
			}
		})
	}
}
