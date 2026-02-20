package bootstrap
package bootstrap

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
)

// TestCompositeBootstrapBehavior verifies that composite bootstrap
// maintains its sequential fallback behavior when type is "auto".
func TestCompositeBootstrapBehavior(t *testing.T) {
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		BootstrapType:    "auto",
		ReseedFilePath:   "",
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            testReseedServerURL,
				SU3Fingerprint: testReseedFingerprint,
			},
		},
	}

	cb := NewCompositeBootstrap(cfg)
	if cb == nil {
		t.Fatal("NewCompositeBootstrap should not return nil")
	}

	// Verify it has all three bootstrap methods available
	if cb.reseedBootstrap == nil {
		t.Error("CompositeBootstrap should have reseedBootstrap initialized")
	}
	if cb.localNetDbBootstrap == nil {
		t.Error("CompositeBootstrap should have localNetDbBootstrap initialized")
	}
	// fileBootstrap should be nil since no ReseedFilePath is set
	if cb.fileBootstrap != nil {
		t.Error("CompositeBootstrap should not have fileBootstrap when ReseedFilePath is empty")
	}
}
