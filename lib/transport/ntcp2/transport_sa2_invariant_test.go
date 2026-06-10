package ntcp2

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/require"
)

// TestSA2_InvariantInitial verifies that the session counting invariant
// holds at transport startup (SA-2 fix: ValidateSessionCountingInvariant).
func TestSA2_InvariantInitial(t *testing.T) {
	t.Parallel()

	transport, cleanup := createTransportSA2(t)
	defer cleanup()

	// The invariant is: sessionCount == number of entries in sessions map
	count := transport.GetSessionCount()
	mismatch := transport.ValidateSessionCountingInvariant()

	require.Equal(t, 0, count, "Should start with zero sessions")
	require.Equal(t, 0, mismatch, "SA-2 invariant should hold at startup")
}

// TestSA2_InvariantAfterClose verifies that the invariant holds after
// closing the transport.
func TestSA2_InvariantAfterClose(t *testing.T) {
	t.Parallel()

	transport, cleanup := createTransportSA2(t)

	// Close the transport
	transport.Close()
	time.Sleep(100 * time.Millisecond)

	// Check invariant after close
	mismatch := transport.ValidateSessionCountingInvariant()
	require.Equal(t, 0, mismatch, "SA-2 invariant should hold after close")

	cleanup()
}

// TestSA2_InvariantStability verifies that the invariant remains stable
// across multiple checks (detects if it drifts due to goroutine leaks).
func TestSA2_InvariantStability(t *testing.T) {
	t.Parallel()

	transport, cleanup := createTransportSA2(t)
	defer cleanup()

	// Check invariant multiple times over a period
	for i := 0; i < 10; i++ {
		mismatch := transport.ValidateSessionCountingInvariant()
		require.Equal(t, 0, mismatch, "Invariant should remain stable (check %d)", i)
		time.Sleep(10 * time.Millisecond)
	}
}

// Helper functions for SA-2 tests

type testKeystoreSA2 struct {
	keyData []byte
}

func (k *testKeystoreSA2) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return &testPrivateKeySA2{keyData: k.keyData}
}

type testPrivateKeySA2 struct {
	keyData []byte
}

func (k *testPrivateKeySA2) Bytes() []byte {
	return k.keyData
}

func (k *testPrivateKeySA2) Zero() {
	for i := range k.keyData {
		k.keyData[i] = 0
	}
}

func (k *testPrivateKeySA2) NewDecrypter() (types.Decrypter, error) {
	return nil, nil
}

func (k *testPrivateKeySA2) Public() (types.PublicEncryptionKey, error) {
	return nil, nil
}

func createTransportSA2(t *testing.T) (*NTCP2Transport, func()) {
	t.Helper()

	// Create test identity with signed RouterInfo
	identity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)

	// Create test keystore
	keystore := &testKeystoreSA2{
		keyData: make([]byte, 32),
	}

	// Create config with dynamic port
	cfg, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err, "Failed to create config")
	cfg.MaxSessions = 100

	// Create transport (this automatically starts listening)
	tr, err := NewNTCP2Transport(*identity, cfg, keystore)
	require.NoError(t, err, "Failed to create NTCP2Transport")
	require.NotNil(t, tr, "Transport should not be nil")

	cleanup := func() {
		tr.Close()
	}

	return tr, cleanup
}

func connectToPeerSA2(t *testing.T, transport *NTCP2Transport) net.Conn {
	t.Helper()

	// Get the transport's address
	addr := transport.Addr()
	require.NotNil(t, addr, "Transport address should not be nil")

	// Dial the transport (simulate inbound connection)
	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err, "Failed to connect to transport")

	return conn
}
