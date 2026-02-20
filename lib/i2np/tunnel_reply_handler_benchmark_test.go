package i2np

import (
	"testing"
	"time"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

func BenchmarkTunnelBuildReply_ProcessReply_Success(b *testing.B) {
	reply := createSuccessfulTunnelBuildReply()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reply.ProcessReply()
	}
}

func BenchmarkTunnelBuildReply_ProcessReply_Mixed(b *testing.B) {
	reply := createMixedTunnelBuildReply()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reply.ProcessReply()
	}
}

func BenchmarkVariableTunnelBuildReply_ProcessReply_Success(b *testing.B) {
	reply := createSuccessfulVariableTunnelBuildReply(5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reply.ProcessReply()
	}
}

func BenchmarkReplyProcessor_RegisterPendingBuild(b *testing.B) {
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnelID := tunnel.TunnelID(i)
		_ = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	}
}

func BenchmarkReplyProcessor_ProcessBuildReply(b *testing.B) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	// Pre-register builds
	for i := 0; i < b.N; i++ {
		tunnelID := tunnel.TunnelID(i)
		_ = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnelID := tunnel.TunnelID(i)
		reply := createSuccessfulVariableTunnelBuildReply(3)
		_ = rp.ProcessBuildReply(reply, tunnelID)
	}
}

func BenchmarkReplyProcessor_CleanupExpiredBuilds(b *testing.B) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 1 * time.Millisecond
	rp := NewReplyProcessor(config, nil)

	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Register some builds
		for j := 0; j < 10; j++ {
			tunnelID := tunnel.TunnelID(i*10 + j)
			_ = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
		}

		time.Sleep(2 * time.Millisecond)
		rp.CleanupExpiredBuilds()
	}
}
