package ntcp2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeystorePB2 implements KeystoreProvider for address consistency tests
type testKeystorePB2 struct {
	keyData []byte
}

func (k *testKeystorePB2) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return &testPrivateKeyPB2{keyData: k.keyData}
}

// testPrivateKeyPB2 implements types.PrivateEncryptionKey for testing
type testPrivateKeyPB2 struct {
	keyData []byte
}

func (k *testPrivateKeyPB2) Bytes() []byte {
	return k.keyData
}

func (k *testPrivateKeyPB2) Zero() {
	for i := range k.keyData {
		k.keyData[i] = 0
	}
}

func (k *testPrivateKeyPB2) NewDecrypter() (types.Decrypter, error) {
	return nil, nil
}

func (k *testPrivateKeyPB2) Public() (types.PublicEncryptionKey, error) {
	return nil, nil
}

// newTestIdentityAndKeystorePB2 creates a signed RouterInfo and keystore
func newTestIdentityAndKeystorePB2(t *testing.T) (router_info.RouterInfo, KeystoreProvider) {
	t.Helper()
	identity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	keystore := &testKeystorePB2{
		keyData: make([]byte, 32),
	}
	return *identity, keystore
}

// createTransportPB2 creates an NTCP2Transport for testing with a loopback listener
func createTransportPB2(t *testing.T) *NTCP2Transport {
	t.Helper()
	config, err := NewConfig("127.0.0.1:0") // Dynamic port
	require.NoError(t, err)

	identity, keystore := newTestIdentityAndKeystorePB2(t)

	transport, err := NewNTCP2Transport(identity, config, keystore)
	require.NoError(t, err)
	require.NotNil(t, transport)

	return transport
}

// TestPB2_AddrReturnsTCPAddr validates that Addr() returns a plain TCP address (not wrapped).
// The fix ensures Addr() and config.ListenerAddress are in the same format.
func TestPB2_AddrReturnsTCPAddr(t *testing.T) {
	// Create a transport using the helper
	transport := createTransportPB2(t)
	require.NotNil(t, transport)
	defer transport.Close()

	// Get the address
	addr := transport.Addr()
	require.NotNil(t, addr)

	// Verify it's a plain TCP address, not a wrapped ntcp2.Addr
	// This is the PB-2 fix: unwrap the address in Addr() method
	_, ok := addr.(*net.TCPAddr)
	require.True(t, ok, "Addr() should return *net.TCPAddr, got %T", addr)

	// Verify it's a valid net.Addr (string format should be "IP:port")
	addrStr := addr.String()
	require.NotEmpty(t, addrStr)
	require.Contains(t, addrStr, ":", "address should be in format IP:port")

	// Verify it does NOT have the NTCP2 wrapper format (ntcp2://routerHash/...)
	require.NotContains(t, addrStr, "ntcp2://", "Addr() should not return wrapped format")
}

// TestPB2_AddrConsistentWithConfig validates that Addr() format matches config.ListenerAddress.
// This is the core invariant for PB-2.
func TestPB2_AddrConsistentWithConfig(t *testing.T) {
	transport := createTransportPB2(t)
	require.NotNil(t, transport)
	defer transport.Close()

	addr := transport.Addr()
	require.NotNil(t, addr)

	cfg := transport.config.Load()
	require.NotNil(t, cfg)

	// PB-2 invariant: Addr().String() should equal config.ListenerAddress
	addrStr := addr.String()
	configAddr := cfg.ListenerAddress

	assert.Equal(t, configAddr, addrStr,
		"Addr().String() must match config.ListenerAddress for consistency")
}

// TestPB2_ConcurrentAddrReads validates concurrent access to Addr() is safe.
// This ensures the fix doesn't introduce race conditions.
func TestPB2_ConcurrentAddrReads(t *testing.T) {
	transport := createTransportPB2(t)
	require.NotNil(t, transport)
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var readCount atomic.Int32
	var errorCount atomic.Int32

	// Spawn 10 concurrent reader goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				addr := transport.Addr()
				if addr != nil {
					readCount.Add(1)
					// Verify each read returns a TCPAddr
					if _, ok := addr.(*net.TCPAddr); !ok {
						errorCount.Add(1)
					}
				}
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int32(0), errorCount.Load(),
		"All concurrent reads should return *net.TCPAddr")
	assert.Greater(t, readCount.Load(), int32(0),
		"Should have performed many concurrent reads")
}

// TestPB2_AddrNeverNil validates that Addr() is never nil after initialization.
func TestPB2_AddrNeverNil(t *testing.T) {
	transport := createTransportPB2(t)
	require.NotNil(t, transport)
	defer transport.Close()

	for i := 0; i < 100; i++ {
		addr := transport.Addr()
		assert.NotNil(t, addr, "Addr() should never return nil after initialization")
	}
}

// TestPB2_AddrStableAfterInit validates that Addr() returns the same address
// throughout the transport's lifetime (until Close()).
func TestPB2_AddrStableAfterInit(t *testing.T) {
	transport := createTransportPB2(t)
	require.NotNil(t, transport)
	defer transport.Close()

	// Get initial address
	initialAddr := transport.Addr()
	require.NotNil(t, initialAddr)
	initialStr := initialAddr.String()

	// Sleep to ensure any background operations are stable
	time.Sleep(100 * time.Millisecond)

	// Get address again multiple times
	for i := 0; i < 10; i++ {
		addr := transport.Addr()
		require.NotNil(t, addr)
		assert.Equal(t, initialStr, addr.String(),
			"Addr() should remain stable throughout transport lifetime")
	}
}
