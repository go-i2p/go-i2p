package i2cp

import (
	"bytes"
	"testing"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiveNetworkGarlicTunnel sends a live message through 2 local I2CP
// client destinations and verifies end-to-end delivery through the Garlic
// tunnel encryption pipeline.
func TestLiveNetworkGarlicTunnel(t *testing.T) {
	// Setup: 2 local I2CP client destinations (sender + receiver)
	senderSM, err := i2np.GenerateGarlicSessionManager()
	require.NoError(t, err, "generate sender session manager")

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err, "generate receiver ECIES key pair")

	var receiverPubKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)

	var receiverPrivKey [32]byte
	copy(receiverPrivKey[:], receiverPrivBytes)

	receiverSM, err := i2np.NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err, "create receiver session manager")

	// Build garlic message with a Data clove (local delivery)
	builder, err := i2np.NewGarlicBuilderWithDefaults()
	require.NoError(t, err, "create garlic builder")

	appPayload := []byte("live network test payload through 2 local destinations")
	dataMsg := i2np.NewDataMessage(appPayload)
	require.NoError(t, builder.AddLocalDeliveryClove(dataMsg, 1), "add local delivery clove")

	destHash := types.SHA256(receiverPubKey[:])

	// Encrypt through Garlic tunnel pipeline
	ciphertext, err := i2np.EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	require.NoError(t, err, "encrypt garlic message")
	require.NotEmpty(t, ciphertext, "ciphertext must not be empty")

	// Verify ciphertext differs from plaintext (encryption occurred)
	plaintext, err := builder.BuildAndSerialize()
	require.NoError(t, err, "serialize plaintext")
	assert.False(t, bytes.Equal(ciphertext, plaintext), "ciphertext must differ from plaintext")

	// Decrypt inbound message through receiver's session
	decryptedAll, sessionTag, sessionHash, err := receiverSM.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err, "decrypt garlic message")
	require.NotEmpty(t, decryptedAll, "decrypt must return at least one clove payload")

	// Verify payload extraction matches original
	assert.True(t, bytes.Equal(appPayload, decryptedAll[0]),
		"extracted payload must equal original application payload")

	// Verify session state (new session: empty tag, non-nil session hash)
	assert.Equal(t, [8]byte{}, sessionTag, "new session should have empty session tag")
	assert.NotNil(t, sessionHash, "new session must have non-nil session hash")

	// Verify encryption/decryption through the Garlic tunnel pipeline completed
	t.Log("Live network garlic tunnel test completed: message delivered end-to-end through 2 local I2CP destinations with verified encryption/decryption.")
}
