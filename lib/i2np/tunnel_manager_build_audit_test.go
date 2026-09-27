package i2np

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

func TestTunnelManagerBuildAuditFixes(t *testing.T) {
	tm := NewTunnelManager(nil)

	t.Run("validateBuildResponse rejects success without payload", func(t *testing.T) {
		err := tm.validateBuildResponse(tunnel.BuildResponse{HopIndex: 1, Success: true, Reply: nil})
		if err == nil {
			t.Fatal("expected empty success payload to fail validation")
		}
	})

	t.Run("routeBuildReply rejects empty payload and unknown message ID", func(t *testing.T) {
		tm.pendingBuilds[42] = &buildRequest{tunnelID: 7}
		if err := tm.routeBuildReply(nil, 42); err == nil {
			t.Fatal("expected empty reply payload to fail routing validation")
		}
		if err := tm.routeBuildReply([]byte{0x01}, 999); err == nil {
			t.Fatal("expected missing pending build to fail routing validation")
		}
	})

	t.Run("registerLayerKeysForHop rejects zero values", func(t *testing.T) {
		if err := tm.registerLayerKeysForHop(0, [32]byte{}, [32]byte{}); err == nil {
			t.Fatal("expected zero layer keys to fail validation")
		}
		if err := tm.registerLayerKeysForHop(0, [32]byte{1}, [32]byte{2}); err != nil {
			t.Fatalf("expected non-zero layer keys to be accepted: %v", err)
		}
	})
}
