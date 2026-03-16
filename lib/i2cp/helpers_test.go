package i2cp

import (
	"bytes"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertDestinationMethodsWork tests that Bytes, Validate, Base64, and
// Base32Address all succeed on the given destination.
func assertDestinationMethodsWork(t *testing.T, dest *destination.Destination, label string) {
	t.Helper()
	require.NotNil(t, dest)

	b, err := dest.Bytes()
	assert.NoError(t, err, "%s: Bytes()", label)
	assert.NotEmpty(t, b)

	err = dest.Validate()
	assert.NoError(t, err, "%s: Validate()", label)

	b64, err := dest.Base64()
	assert.NoError(t, err, "%s: Base64()", label)
	assert.NotEmpty(t, b64)

	b32, err := dest.Base32Address()
	assert.NoError(t, err, "%s: Base32Address()", label)
	assert.NotEmpty(t, b32)
}

// buildGetDateOptionsData constructs a length-prefixed options byte slice
// for parseGetDateOptions tests.
func buildGetDateOptionsData(content string) []byte {
	d := make([]byte, 2+len(content))
	d[0] = byte(len(content) >> 8)
	d[1] = byte(len(content))
	copy(d[2:], content)
	return d
}

// newBaseTestSession creates a Session with standard test defaults
// (id=1, active, default config).
func newBaseTestSession() *Session {
	return &Session{
		id:        1,
		config:    DefaultSessionConfig(),
		active:    true,
		createdAt: time.Now(),
	}
}

// addTestTunnelsToPool adds count tunnel states to pool with the given base
// tunnel ID and gateway prefix string.
func addTestTunnelsToPool(pool *tunnel.Pool, baseID int, gatewayPrefix string, count int) {
	for i := 0; i < count; i++ {
		tunnelID := tunnel.TunnelID(baseID + i)
		var gateway common.Hash
		copy(gateway[:], []byte(gatewayPrefix))
		gateway[31] = byte(i)

		state := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []common.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		pool.AddTunnel(state)
	}
}

// setupEncryptedLeaseSetConfig creates a DestinationKeyStore and a
// SessionConfig with UseEncryptedLeaseSet enabled and a standard blinding secret.
func setupEncryptedLeaseSetConfig(t *testing.T) (*keys.DestinationKeyStore, *SessionConfig) {
	t.Helper()
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")
	return keyStore, config
}

// assertDefaultSessionConfig asserts that the given config matches all
// DefaultSessionConfig values for tunnel length and count.
func assertDefaultSessionConfig(t *testing.T, config *SessionConfig) {
	t.Helper()
	def := DefaultSessionConfig()
	assert.Equal(t, def.InboundTunnelLength, config.InboundTunnelLength, "InboundTunnelLength")
	assert.Equal(t, def.OutboundTunnelLength, config.OutboundTunnelLength, "OutboundTunnelLength")
	assert.Equal(t, def.InboundTunnelCount, config.InboundTunnelCount, "InboundTunnelCount")
	assert.Equal(t, def.OutboundTunnelCount, config.OutboundTunnelCount, "OutboundTunnelCount")
}

// createTestDestAndPubKey creates a test destination hash and a 32-byte
// public key for message routing tests.
func createTestDestAndPubKey() (common.Hash, [32]byte) {
	destHash := createTestHash()
	var destPubKey [32]byte
	copy(destPubKey[:], "dest-public-key-32-bytes-pads")
	return destHash, destPubKey
}

// callHandleCreateLeaseSet invokes handleCreateLeaseSet on the fixture,
// returning the response message and error.
func callHandleCreateLeaseSet(t *testing.T, f *leaseSetTestFixture) (*Message, error) {
	t.Helper()
	sessionPtr := f.session
	return f.server.handleCreateLeaseSet(f.msg, &sessionPtr)
}

// assertSessionDestinationMatch compares the session destination bytes with
// expectedDestBytes. If shouldMatch is true, asserts equality; otherwise
// asserts inequality.
func assertSessionDestinationMatch(t *testing.T, session *Session, expectedDestBytes []byte, shouldMatch bool, label string) {
	t.Helper()
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	if shouldMatch {
		assert.True(t, bytes.Equal(expectedDestBytes, sessionDestBytes), label)
	} else {
		assert.False(t, bytes.Equal(expectedDestBytes, sessionDestBytes), label)
	}
}

// assertSessionKeysPresent asserts that the session has non-nil keys and a
// non-nil signing private key.
func assertSessionKeysPresent(t *testing.T, session *Session) {
	t.Helper()
	assert.NotNil(t, session.keys, "session keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
}

// doLeaseSetAndMessage creates a LeaseSet, queues msgContent, and receives it,
// asserting success at each step. label prefixes the assertion messages.
func doLeaseSetAndMessage(t *testing.T, session *Session, msgContent string, label string) {
	t.Helper()
	ls, err := session.CreateLeaseSet()
	assert.NoError(t, err, label+" LeaseSet creation should succeed")
	assert.NotNil(t, ls)

	err = session.QueueIncomingMessage([]byte(msgContent))
	assert.NoError(t, err, label+" message queue should succeed")

	msg, err := session.ReceiveMessage()
	assert.NoError(t, err, label+" message receive should succeed")
	assert.NotNil(t, msg)
}
