package i2np

import (
	"bytes"
	"testing"

	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractDataPayloadsFromInboundGarlic_RoundTrip verifies the receive-side
// inverse of the client send path: a Data clove is built, encrypted to a
// destination's ECIES key, wrapped as an I2NP Garlic message, and then decrypted
// + extracted back to the original application payload.
func TestExtractDataPayloadsFromInboundGarlic_RoundTrip(t *testing.T) {
	senderSM, receiverSM, receiverPubKey := setupGarlicSenderReceiver(t)

	appPayload := []byte("hello from the i2p network")

	// Build the garlic exactly like i2cp.MessageRouter does on send.
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	require.NoError(t, builder.AddLocalDeliveryClove(NewDataMessage(appPayload), 1))

	destHash := types.SHA256(receiverPubKey[:])
	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	require.NoError(t, err)

	// Wrap in an I2NP Garlic message (as WrapInGarlicMessage does on send) and
	// feed its data through the extractor (as the router inbound handler does).
	garlicMsg, err := WrapInGarlicMessage(ciphertext)
	require.NoError(t, err)

	payloads, err := ExtractDataPayloadsFromInboundGarlic(receiverSM, garlicMsg.GetData())
	require.NoError(t, err)
	require.Len(t, payloads, 1)
	assert.True(t, bytes.Equal(appPayload, payloads[0]),
		"extracted payload must equal the original application payload")
}

// TestExtractDataPayloadsFromInboundGarlic_LengthPrefixed verifies extraction
// works when the garlic ciphertext carries the 4-byte length prefix that the
// on-wire Garlic message format uses.
func TestExtractDataPayloadsFromInboundGarlic_LengthPrefixed(t *testing.T) {
	senderSM, receiverSM, receiverPubKey := setupGarlicSenderReceiver(t)

	appPayload := []byte("length-prefixed payload")

	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	require.NoError(t, builder.AddLocalDeliveryClove(NewDataMessage(appPayload), 1))

	destHash := types.SHA256(receiverPubKey[:])
	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	require.NoError(t, err)

	// Prepend the 4-byte big-endian length prefix (stripGarlicLengthPrefixIfPresent
	// should remove it before decryption).
	prefixed := make([]byte, 4+len(ciphertext))
	prefixed[0] = byte(len(ciphertext) >> 24)
	prefixed[1] = byte(len(ciphertext) >> 16)
	prefixed[2] = byte(len(ciphertext) >> 8)
	prefixed[3] = byte(len(ciphertext))
	copy(prefixed[4:], ciphertext)

	payloads, err := ExtractDataPayloadsFromInboundGarlic(receiverSM, prefixed)
	require.NoError(t, err)
	require.Len(t, payloads, 1)
	assert.True(t, bytes.Equal(appPayload, payloads[0]))
}

// TestExtractDataPayloadsFromInboundGarlic_Errors verifies error handling for
// nil manager and empty ciphertext.
func TestExtractDataPayloadsFromInboundGarlic_Errors(t *testing.T) {
	_, receiverSM, _ := setupGarlicSenderReceiver(t)

	_, err := ExtractDataPayloadsFromInboundGarlic(nil, []byte{0x01})
	assert.Error(t, err, "nil session manager should error")

	_, err = ExtractDataPayloadsFromInboundGarlic(receiverSM, nil)
	assert.Error(t, err, "empty ciphertext should error")

	_, err = ExtractDataPayloadsFromInboundGarlic(receiverSM, []byte{0x00, 0x01, 0x02})
	assert.Error(t, err, "undecryptable ciphertext should error")
}

// TestExtractDataClovePayload_NonData verifies non-Data cloves are skipped.
func TestExtractDataClovePayload_NonData(t *testing.T) {
	clove := GarlicClove{
		Message: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
	}
	_, ok := extractDataClovePayload(clove)
	assert.False(t, ok, "non-Data clove should not yield a payload")

	clove.Message = nil
	_, ok = extractDataClovePayload(clove)
	assert.False(t, ok, "nil clove message should not yield a payload")
}
