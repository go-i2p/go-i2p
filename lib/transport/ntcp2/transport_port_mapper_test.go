package ntcp2

import (
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeystore implements KeystoreProvider for port mapper tests
type testKeystore struct {
	keyData []byte
}

func (k *testKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return &testPrivateKey{keyData: k.keyData}
}

// testPrivateKey implements types.PrivateEncryptionKey for testing
type testPrivateKey struct {
	keyData []byte
}

func (k *testPrivateKey) Bytes() []byte {
	return k.keyData
}

func (k *testPrivateKey) Zero() {
	for i := range k.keyData {
		k.keyData[i] = 0
	}
}

func (k *testPrivateKey) NewDecrypter() (types.Decrypter, error) {
	return nil, nil
}

func (k *testPrivateKey) Public() (types.PublicEncryptionKey, error) {
	return nil, nil
}

// newTestIdentityAndKeystore creates a signed RouterInfo and keystore for testing
func newTestIdentityAndKeystore(t *testing.T) (router_info.RouterInfo, KeystoreProvider) {
	t.Helper()

	// Create a signed RouterInfo with NTCP2 address
	identity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)

	// Create a test keystore with dummy X25519 key (32 bytes)
	keystore := &testKeystore{
		keyData: make([]byte, 32),
	}

	return *identity, keystore
}

// TestPortMapperLifecycle verifies that NTCP2Transport correctly initializes
// and cleans up the port mapper when binding to a non-loopback address.
// This test validates Phase 4 integration: TCP port mapping lifecycle.
func TestPortMapperLifecycle(t *testing.T) {
	// Create a config that will bind to a wildcard address (non-loopback)
	// This will trigger port mapper initialization
	config, err := NewConfig("0.0.0.0:0") // OS-assigned port on all interfaces
	require.NoError(t, err)

	// Create test router identity and keystore
	identity, keystore := newTestIdentityAndKeystore(t)

	// Create transport (this will call setupNetworkListener, which should initialize port mapper)
	transport, err := NewNTCP2Transport(identity, config, keystore)
	require.NoError(t, err)
	require.NotNil(t, transport)

	// Verify port mapper was initialized for non-loopback binding
	// Note: portMapperManager is initialized in setupNetworkListener if the bound
	// address is not a loopback address. Since we bound to 0.0.0.0, it should be initialized.
	assert.NotNil(t, transport.portMapperManager, "Port mapper should be initialized for non-loopback address")

	// Give port mapper a moment to start its retry goroutine
	time.Sleep(50 * time.Millisecond)

	// Close transport (should clean up port mapper)
	err = transport.Close()
	assert.NoError(t, err)

	// Verify Close is idempotent
	err = transport.Close()
	assert.NoError(t, err)
}

// TestPortMapperNotInitializedForLoopback verifies that the port mapper is NOT
// initialized when binding to a loopback address (optimization - no NAT traversal needed).
func TestPortMapperNotInitializedForLoopback(t *testing.T) {
	// Create a config that will bind to loopback (127.0.0.1)
	config, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)

	// Create test router identity and keystore
	identity, keystore := newTestIdentityAndKeystore(t)

	// Create transport
	transport, err := NewNTCP2Transport(identity, config, keystore)
	require.NoError(t, err)
	require.NotNil(t, transport)
	defer transport.Close()

	// Verify port mapper was NOT initialized for loopback address
	assert.Nil(t, transport.portMapperManager, "Port mapper should not be initialized for loopback address")
}

// TestPortMapperCloseBeforeMapping verifies that closing the transport immediately
// after creation (before port mapping succeeds) does not cause deadlock or panic.
func TestPortMapperCloseBeforeMapping(t *testing.T) {
	config, err := NewConfig("0.0.0.0:0")
	require.NoError(t, err)

	identity, keystore := newTestIdentityAndKeystore(t)

	transport, err := NewNTCP2Transport(identity, config, keystore)
	require.NoError(t, err)
	require.NotNil(t, transport)

	// Close immediately (port mapper retry goroutine may still be starting)
	err = transport.Close()
	assert.NoError(t, err)

	// Verify Close completed within reasonable time (no deadlock)
	// If we reach here, Close() didn't hang
}
