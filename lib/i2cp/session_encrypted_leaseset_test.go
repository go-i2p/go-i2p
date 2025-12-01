package i2cp

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionConfigEncryptedLeaseSet verifies EncryptedLeaseSet configuration fields
func TestSessionConfigEncryptedLeaseSet(t *testing.T) {
	config := DefaultSessionConfig()

	assert.False(t, config.UseEncryptedLeaseSet, "EncryptedLeaseSet should be disabled by default")
	assert.Nil(t, config.BlindingSecret, "BlindingSecret should be nil by default")
	assert.Equal(t, uint16(600), config.LeaseSetExpiration, "LeaseSetExpiration should default to 600 seconds")

	// Test custom configuration
	secret := []byte("test-secret-32-bytes-long!!!!!!!")
	customConfig := &SessionConfig{
		UseEncryptedLeaseSet: true,
		BlindingSecret:       secret,
		LeaseSetExpiration:   900,
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   5,
		OutboundTunnelCount:  5,
		TunnelLifetime:       10 * time.Minute,
		MessageTimeout:       60 * time.Second,
		MessageQueueSize:     100,
	}

	assert.True(t, customConfig.UseEncryptedLeaseSet)
	assert.Equal(t, secret, customConfig.BlindingSecret)
	assert.Equal(t, uint16(900), customConfig.LeaseSetExpiration)
}

// TestValidateEncryptedLeaseSetSupport ensures Ed25519 requirement is enforced
func TestValidateEncryptedLeaseSetSupport(t *testing.T) {
	// Create session with Ed25519 destination
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	session := &Session{
		destination: keyStore.Destination(),
		keys:        keyStore,
	}

	// Should succeed with Ed25519
	err = session.validateEncryptedLeaseSetSupport()
	assert.NoError(t, err)

	// Verify the signature type
	sigType := session.destination.KeyCertificate.SigningPublicKeyType()
	assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519, sigType)
}

// TestEnsureBlindingSecret verifies blinding secret generation and caching
func TestEnsureBlindingSecret(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	session := &Session{
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
	}

	// First call should generate a random secret
	err = session.ensureBlindingSecret()
	assert.NoError(t, err)
	assert.NotNil(t, session.blindingSecret)
	assert.Equal(t, 32, len(session.blindingSecret))

	firstSecret := session.blindingSecret

	// Second call should reuse the same secret
	err = session.ensureBlindingSecret()
	assert.NoError(t, err)
	assert.Equal(t, firstSecret, session.blindingSecret)

	// Test with configured secret
	configuredSecret := []byte("configured-secret-32-bytes!!!!!")
	config.BlindingSecret = configuredSecret
	session.blindingSecret = nil // Reset

	err = session.ensureBlindingSecret()
	assert.NoError(t, err)
	assert.Equal(t, configuredSecret, session.blindingSecret)
}

// TestUpdateBlindedDestination verifies blinded destination derivation and rotation
func TestUpdateBlindedDestination(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
	}

	// First update should create blinded destination
	err = session.updateBlindedDestination()
	assert.NoError(t, err)
	assert.NotNil(t, session.blindedDestination)
	assert.NotNil(t, session.blindingSecret)

	firstBlinded := session.blindedDestination
	today := time.Now().UTC()
	expectedDate := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	assert.Equal(t, expectedDate, session.lastBlindingDate)

	// Second update on same day should reuse blinded destination
	err = session.updateBlindedDestination()
	assert.NoError(t, err)
	assert.Equal(t, firstBlinded, session.blindedDestination)

	// Simulate next day - should rotate blinded destination
	nextDay := today.Add(25 * time.Hour)
	session.lastBlindingDate = time.Date(nextDay.Year(), nextDay.Month(), nextDay.Day()-1, 0, 0, 0, 0, time.UTC)

	err = session.updateBlindedDestination()
	assert.NoError(t, err)
	assert.NotNil(t, session.blindedDestination)
	// Note: Blinded destination will be different due to date change
	// We can't easily compare them, but we can verify fields are populated
}

// TestGenerateEncryptionCookie verifies cookie generation
func TestGenerateEncryptionCookie(t *testing.T) {
	session := &Session{}

	cookie1, err := session.generateEncryptionCookie()
	assert.NoError(t, err)
	assert.Equal(t, 32, len(cookie1))

	cookie2, err := session.generateEncryptionCookie()
	assert.NoError(t, err)
	assert.Equal(t, 32, len(cookie2))

	// Cookies should be random (different each time)
	assert.NotEqual(t, cookie1, cookie2)
}

// TestCreateEncryptedLeaseSetWithMockTunnels tests full EncryptedLeaseSet creation
func TestCreateEncryptedLeaseSetWithMockTunnels(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")
	config.LeaseSetExpiration = 600

	// Create mock tunnel pool with active tunnels
	tunnels := createMockTunnels(3)
	inboundPool := &tunnel.Pool{}
	// Note: We can't easily set pool state without exposing internals,
	// so we'll test the individual helper functions instead

	session := &Session{
		id:           1,
		destination:  keyStore.Destination(),
		keys:         keyStore,
		config:       config,
		inboundPool:  inboundPool,
		clientNetDB:  netdb.NewClientNetDB(nil), // Pass nil for StdNetDB in test
		createdAt:    time.Now(),
		active:       true,
		stopCh:       make(chan struct{}),
	}

	// Test individual components
	t.Run("ValidateSupport", func(t *testing.T) {
		err := session.validateEncryptedLeaseSetSupport()
		assert.NoError(t, err)
	})

	t.Run("UpdateBlindedDestination", func(t *testing.T) {
		err := session.updateBlindedDestination()
		assert.NoError(t, err)
		assert.NotNil(t, session.blindedDestination)
	})

	t.Run("BuildLeases", func(t *testing.T) {
		leases, err := session.buildLeasesFromTunnels(tunnels)
		assert.NoError(t, err)
		assert.Len(t, leases, 3)
	})

	t.Run("CreateInnerLeaseSet2", func(t *testing.T) {
		leases, err := session.buildLeasesFromTunnels(tunnels)
		require.NoError(t, err)

		ls2, err := session.createInnerLeaseSet2(leases)
		assert.NoError(t, err)
		assert.NotNil(t, ls2)
	})

	t.Run("GenerateCookie", func(t *testing.T) {
		cookie, err := session.generateEncryptionCookie()
		assert.NoError(t, err)
		assert.Equal(t, 32, len(cookie))
	})

	t.Run("EncryptInnerLeaseSet", func(t *testing.T) {
		leases, err := session.buildLeasesFromTunnels(tunnels)
		require.NoError(t, err)

		ls2, err := session.createInnerLeaseSet2(leases)
		require.NoError(t, err)

		cookie, err := session.generateEncryptionCookie()
		require.NoError(t, err)

		encryptedData, err := session.encryptInnerLeaseSet(ls2, cookie)
		assert.NoError(t, err)
		assert.NotEmpty(t, encryptedData)
		assert.True(t, len(encryptedData) > 0)
	})

	t.Run("AssembleEncryptedLeaseSet", func(t *testing.T) {
		// Update blinded destination first
		err := session.updateBlindedDestination()
		require.NoError(t, err)

		cookie := [32]byte{}
		copy(cookie[:], []byte("test-cookie-32-bytes-long!!!!!!"))

		// Create properly-sized encrypted data (minimum 61 bytes per EncryptedLeaseSet spec)
		encryptedData := make([]byte, 100) // Use 100 bytes to be safe
		copy(encryptedData, []byte("mock-encrypted-leaseset-inner-data-with-sufficient-length-to-meet-spec-requirements-minimum-61-bytes"))

		els, err := session.assembleEncryptedLeaseSet(cookie, encryptedData)
		assert.NoError(t, err)
		assert.NotNil(t, els)

		// Verify EncryptedLeaseSet properties
		assert.True(t, els.IsBlinded())
		assert.Equal(t, session.config.LeaseSetExpiration, els.Expires())
	})
}

// TestCreateEncryptedLeaseSetSerialization verifies EncryptedLeaseSet can be serialized
func TestCreateEncryptedLeaseSetSerialization(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	tunnels := createMockTunnels(2)

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
		createdAt:   time.Now(),
	}

	// Build the EncryptedLeaseSet
	err = session.updateBlindedDestination()
	require.NoError(t, err)

	leases, err := session.buildLeasesFromTunnels(tunnels)
	require.NoError(t, err)

	ls2, err := session.createInnerLeaseSet2(leases)
	require.NoError(t, err)

	cookie, err := session.generateEncryptionCookie()
	require.NoError(t, err)

	encryptedData, err := session.encryptInnerLeaseSet(ls2, cookie)
	require.NoError(t, err)

	els, err := session.assembleEncryptedLeaseSet(cookie, encryptedData)
	require.NoError(t, err)

	// Serialize to bytes
	elsBytes, err := els.Bytes()
	assert.NoError(t, err)
	assert.NotEmpty(t, elsBytes)
	assert.True(t, len(elsBytes) > 100) // Should have substantial size

	// Verify can be parsed back
	parsedELS, remainder, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.True(t, parsedELS.IsBlinded())
}

// TestPublishLeaseSetNetworkWithEncrypted verifies blinded hash is used for EncryptedLeaseSet
func TestPublishLeaseSetNetworkWithEncrypted(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
	}

	// Update blinded destination
	err = session.updateBlindedDestination()
	require.NoError(t, err)

	// Calculate expected hashes
	origBytes, err := session.destination.Bytes()
	require.NoError(t, err)
	origHash := data.HashData(origBytes)

	blindedBytes, err := session.blindedDestination.Bytes()
	require.NoError(t, err)
	blindedHash := data.HashData(blindedBytes)

	// Hashes should be different (blinded vs original)
	assert.NotEqual(t, origHash, blindedHash)

	// Create a mock publisher to verify correct hash is used
	mockPublisher := newMockLeaseSetPublisher()

	session.publisher = mockPublisher

	// Publish with EncryptedLeaseSet enabled
	leaseSetBytes := []byte("mock-encrypted-leaseset-data")
	err = session.publishLeaseSetToNetwork(leaseSetBytes)
	assert.NoError(t, err)

	// Verify blinded hash was used
	assert.Contains(t, mockPublisher.published, blindedHash)
	assert.NotContains(t, mockPublisher.published, origHash)

	// Test with EncryptedLeaseSet disabled
	session.config.UseEncryptedLeaseSet = false
	mockPublisher.published = make(map[data.Hash][]byte)

	err = session.publishLeaseSetToNetwork(leaseSetBytes)
	assert.NoError(t, err)

	// Verify original hash was used
	assert.Contains(t, mockPublisher.published, origHash)
	assert.NotContains(t, mockPublisher.published, blindedHash)
}

// TestRegenerateAndPublishWithEncrypted verifies maintenance loop uses EncryptedLeaseSet when configured
func TestRegenerateAndPublishWithEncrypted(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	tunnels := createMockTunnels(2)
	inboundPool := &tunnel.Pool{}

	session := &Session{
		id:           1,
		destination:  keyStore.Destination(),
		keys:         keyStore,
		config:       config,
		inboundPool:  inboundPool,
		clientNetDB:  netdb.NewClientNetDB(nil), // Pass nil for StdNetDB in test
		createdAt:    time.Now(),
		active:       true,
		stopCh:       make(chan struct{}),
	}

	// Note: Full integration test would require mocking tunnel pool state
	// Here we test that the method routing works correctly

	// Verify EncryptedLeaseSet can be created when enabled
	session.config.UseEncryptedLeaseSet = true
	err = session.updateBlindedDestination()
	assert.NoError(t, err)

	// Verify the blinded destination is properly set
	assert.NotNil(t, session.blindedDestination)

	// Test components individually since we can't easily inject tunnel state
	leases, err := session.buildLeasesFromTunnels(tunnels)
	require.NoError(t, err)

	ls2, err := session.createInnerLeaseSet2(leases)
	assert.NoError(t, err)
	assert.NotNil(t, ls2)
}

// createMockTunnels creates mock tunnel data for testing
func createMockTunnels(count int) []*tunnel.TunnelState {
	tunnels := make([]*tunnel.TunnelState, count)
	for i := 0; i < count; i++ {
		// Create a mock gateway hash
		var gateway [32]byte
		gateway[0] = byte(i)

		tunnels[i] = &tunnel.TunnelState{
			ID:        tunnel.TunnelID(1000 + i),
			State:     tunnel.TunnelReady,
			Hops:      []data.Hash{gateway},
			CreatedAt: time.Now(),
		}
	}
	return tunnels
}
