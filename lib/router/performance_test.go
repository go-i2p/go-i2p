package router

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	tunnelpkg "github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/require"
)

// BenchmarkMessageThroughput measures message processing throughput.
// This benchmark tests the entire message routing pipeline from I2CP to garlic encryption.
//
// Target: >1000 msg/sec for small messages (1KB)
func BenchmarkMessageThroughput(b *testing.B) {
	env := setupPerformanceEnvironment(b)
	defer env.Cleanup()

	payload := make([]byte, 512) // 512 bytes payload
	rand.Read(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := env.messageRouter.RouteOutboundMessage(
			env.senderSession,
			0, // messageID
			env.receiverDestHash,
			env.receiverPubKey,
			payload,
			0,   // no expiration
			nil, // no status callback
		)
		if err != nil {
			b.Fatalf("Failed to route message: %v", err)
		}
	}
	b.StopTimer()

	messagesPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(messagesPerSec, "msg/sec")
}

// BenchmarkMessageThroughputParallel measures concurrent message processing throughput.
// Tests the system's ability to handle multiple concurrent message sends.
func BenchmarkMessageThroughputParallel(b *testing.B) {
	env := setupPerformanceEnvironment(b)
	defer env.Cleanup()

	payload := make([]byte, 512)
	rand.Read(payload)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := env.messageRouter.RouteOutboundMessage(
				env.senderSession,
				0, // messageID
				env.receiverDestHash,
				env.receiverPubKey,
				payload,
				0,   // no expiration
				nil, // no status callback
			)
			if err != nil {
				b.Fatalf("Failed to route message: %v", err)
			}
		}
	})
	b.StopTimer()

	messagesPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(messagesPerSec, "msg/sec")
}

// BenchmarkTunnelPoolOperations measures tunnel pool operation performance.
// Tests add/remove/select tunnel operations which are critical for routing.
func BenchmarkTunnelPoolOperations(b *testing.B) {
	selector := &mockPeerSelector{}
	pool := tunnelpkg.NewTunnelPool(selector)

	// Pre-populate with tunnels
	tunnels := make([]*tunnelpkg.TunnelState, 20)
	for i := 0; i < 20; i++ {
		tunnels[i] = &tunnelpkg.TunnelState{
			ID:        tunnelpkg.TunnelID(uint32(i + 1)),
			State:     tunnelpkg.TunnelReady,
			CreatedAt: time.Now(),
		}
		pool.AddTunnel(tunnels[i])
	}

	b.Run("SelectTunnel", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pool.SelectTunnel()
		}
	})

	b.Run("AddTunnel", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tunnel := &tunnelpkg.TunnelState{
				ID:        tunnelpkg.TunnelID(uint32(1000 + i)),
				State:     tunnelpkg.TunnelReady,
				CreatedAt: time.Now(),
			}
			pool.AddTunnel(tunnel)
		}
	})

	b.Run("GetActiveTunnels", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = pool.GetActiveTunnels()
		}
	})
}

// BenchmarkEncryptionDecryption measures tunnel encryption/decryption performance.
// Tests the cryptographic performance of tunnel layer encryption.
func BenchmarkEncryptionDecryption(b *testing.B) {
	// Create test tunnel encryptor with AES (default)
	var layerKey, ivKey tunnel.TunnelKey
	rand.Read(layerKey[:])
	rand.Read(ivKey[:])

	encryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	require.NoError(b, err)

	// Test data - tunnel message payload size for AES
	data := make([]byte, 1008)
	rand.Read(data)

	b.Run("Encryption", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := encryptor.Encrypt(data)
			if err != nil {
				b.Fatalf("Encryption failed: %v", err)
			}
		}
		b.SetBytes(int64(len(data)))
	})

	b.Run("Decryption", func(b *testing.B) {
		// Pre-encrypt data
		encrypted, _ := encryptor.Encrypt(data)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := encryptor.Decrypt(encrypted)
			if err != nil {
				b.Fatalf("Decryption failed: %v", err)
			}
		}
		b.SetBytes(int64(len(encrypted)))
	})
}

// BenchmarkGarlicEncryption measures garlic message encryption performance.
// Tests ECIES-X25519-AEAD-Ratchet encryption throughput.
func BenchmarkGarlicEncryption(b *testing.B) {
	var privKey [32]byte
	rand.Read(privKey[:])

	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(b, err)

	// Create destination with public key
	var destHash common.Hash
	rand.Read(destHash[:])

	var destPubKey [32]byte
	rand.Read(destPubKey[:])

	payload := make([]byte, 512)
	rand.Read(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := garlicMgr.EncryptGarlicMessage(destHash, destPubKey, payload)
		if err != nil {
			b.Fatalf("Garlic encryption failed: %v", err)
		}
	}
	b.SetBytes(int64(len(payload)))
}

// BenchmarkNetDBOperations measures NetDB operation performance.
// Tests basic NetDB operations like storage and retrieval.
func BenchmarkNetDBOperations(b *testing.B) {
	db := netdb.NewStdNetDB("")
	defer db.Stop()

	// Test LeaseSet storage
	b.Run("StoreLeaseSet", func(b *testing.B) {
		leaseSetBytes := make([]byte, 100)
		rand.Read(leaseSetBytes)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var destHash common.Hash
			rand.Read(destHash[:])
			if err := db.StoreLeaseSet(destHash, leaseSetBytes, 1); err != nil {
				b.Logf("Error storing lease set: %v", err)
			}
		}
	})
}

// performanceEnvironment is a lightweight environment for performance testing
type performanceEnvironment struct {
	senderSession    *i2cp.Session
	receiverDestHash common.Hash
	receiverPubKey   [32]byte
	messageRouter    *i2cp.MessageRouter
	cleanupFuncs     []func()
}

// setupPerformanceEnvironment creates a minimal environment for benchmarking
func setupPerformanceEnvironment(tb testing.TB) *performanceEnvironment {
	env := &performanceEnvironment{
		cleanupFuncs: make([]func(), 0),
	}

	// Create sender session
	sessionConfig := i2cp.DefaultSessionConfig()
	sessionConfig.Nickname = "perf-sender"

	var err error
	env.senderSession, err = i2cp.NewSession(1, nil, sessionConfig)
	require.NoError(tb, err)
	env.cleanupFuncs = append(env.cleanupFuncs, func() { env.senderSession.Stop() })

	// Add tunnel pool to sender
	selector := &mockPeerSelector{}
	outboundPool := tunnelpkg.NewTunnelPoolWithConfig(selector, tunnelpkg.DefaultPoolConfig())

	// Add some ready tunnels with hops
	for i := 0; i < 4; i++ {
		// Create hops for the tunnel
		hops := make([]common.Hash, 3)
		for j := 0; j < 3; j++ {
			rand.Read(hops[j][:])
		}

		tunnel := &tunnelpkg.TunnelState{
			ID:        tunnelpkg.TunnelID(uint32(i + 1)),
			Hops:      hops,
			State:     tunnelpkg.TunnelReady,
			CreatedAt: time.Now(),
		}
		outboundPool.AddTunnel(tunnel)
	}
	env.senderSession.SetOutboundPool(outboundPool)

	// Setup receiver identity
	rand.Read(env.receiverDestHash[:])
	rand.Read(env.receiverPubKey[:])

	// Create garlic manager
	var privKey [32]byte
	rand.Read(privKey[:])
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(tb, err)

	// Create message router with no-op transport
	noopTransport := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		return nil
	}

	env.messageRouter = i2cp.NewMessageRouter(garlicMgr, noopTransport)

	return env
}

// Cleanup releases all resources
func (env *performanceEnvironment) Cleanup() {
	for i := len(env.cleanupFuncs) - 1; i >= 0; i-- {
		env.cleanupFuncs[i]()
	}
}
