package i2np

import (
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureGarlicKeyRegistrar struct {
	called        bool
	registrations []garlicRegistration
}

type garlicRegistration struct {
	tag [8]byte
	key [32]byte
}

func (c *captureGarlicKeyRegistrar) RegisterOneTimeGarlicKey(tag [8]byte, key [32]byte) {
	c.called = true
	c.registrations = append(c.registrations, garlicRegistration{tag: tag, key: key})
}

func (c *captureGarlicKeyRegistrar) contains(tag [8]byte, key [32]byte) bool {
	for _, reg := range c.registrations {
		if reg.tag == tag && reg.key == key {
			return true
		}
	}
	return false
}

// createTestHop creates a RouterInfo and keystore pair for encryption tests.
func createTestHop(t *testing.T) (*router_info.RouterInfo, *keys.RouterInfoKeystore) {
	t.Helper()
	ks, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-hop")
	require.NoError(t, err, "Failed to create keystore")
	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err, "Failed to construct RouterInfo")
	return ri, ks
}

// createTestTunnelRecord creates a test tunnel.BuildRequestRecord with random crypto keys.
func createTestTunnelRecord(t *testing.T) tunnel.BuildRequestRecord {
	t.Helper()
	layerKey, ivKey, replyKey, replyIV, padding, ourIdent, nextIdent := generateRandomBuildKeys()

	return tunnel.BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(12345),
		OurIdent:      ourIdent,
		NextTunnel:    tunnel.TunnelID(67890),
		NextIdent:     nextIdent,
		LayerKey:      layerKey,
		IVKey:         ivKey,
		ReplyKey:      replyKey,
		ReplyIV:       replyIV,
		Flag:          0,
		RequestTime:   time.Now().Truncate(time.Minute), // I2P timestamps are minute-resolution
		SendMessageID: 42,
		Padding:       padding,
	}
}

// TestCreateShortTunnelBuildMessage_EncryptsRecords verifies that the STBM
// message creation path encrypts each build record with the corresponding
// hop's public key.
func TestCreateShortTunnelBuildMessage_EncryptsRecords(t *testing.T) {
	// Create test hops with real X25519 keys
	hop1RI, hop1KS := createTestHop(t)
	hop2RI, hop2KS := createTestHop(t)

	// Create cleartext records
	rec1 := createTestTunnelRecord(t)
	rec2 := createTestTunnelRecord(t)
	rec2.ReceiveTunnel = tunnel.TunnelID(54321)
	rec2.SendMessageID = 99

	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(12345),
		Hops:          []router_info.RouterInfo{*hop1RI, *hop2RI},
		Records:       []tunnel.BuildRequestRecord{rec1, rec2},
		UseShortBuild: true,
		IsInbound:     false,
	}

	tm := &TunnelManager{}
	msg, err := tm.createShortTunnelBuildMessage(result, 1001)
	require.NoError(t, err, "createShortTunnelBuildMessage should not fail")
	require.NotNil(t, msg)

	// The message data should be: 1 byte count + 2*218 bytes encrypted STBM records
	baseMsg := msg.(*BaseI2NPMessage)
	data := baseMsg.GetData()
	require.Equal(t, 1+2*ShortBuildRecordSize, len(data),
		"STBM data should be 1 + 2*%d bytes", ShortBuildRecordSize)

	// First byte is the record count
	assert.Equal(t, byte(2), data[0], "record count should be 2")

	// Extract encrypted records (218 bytes each per STBM spec)
	encRec1Data := data[1 : 1+ShortBuildRecordSize]
	encRec2Data := data[1+ShortBuildRecordSize : 1+2*ShortBuildRecordSize]

	// Verify records are NOT cleartext: the cleartext portion (offsets 48..202
	// in ShortBytes) must differ from the encrypted ciphertext at the same offsets.
	i2npRec1 := convertToI2NPRecord(rec1)
	cleartextShort := i2npRec1.ShortBytes()
	assert.NotEqual(t,
		cleartextShort[48:48+ShortBuildRecordCleartextLen],
		encRec1Data[48:48+ShortBuildRecordCleartextLen],
		"encrypted record should not contain cleartext data")

	// Decrypt record 1 with hop1's private key and verify
	var enc1 [ShortBuildRecordSize]byte
	copy(enc1[:], encRec1Data)
	decrypted1, err := DecryptShortBuildRequestRecord(enc1, hop1KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err, "decryption of record 1 should succeed with hop1's key")
	assert.Equal(t, rec1.ReceiveTunnel, decrypted1.ReceiveTunnel,
		"decrypted ReceiveTunnel should match original")
	// SendMessageID is overridden by createShortTunnelBuildMessage to the
	// TM's messageID so that the OBEP can correlate the reply correctly.
	assert.Equal(t, 1001, decrypted1.SendMessageID,
		"decrypted SendMessageID should equal the build message ID")

	// Decrypt record 2 with hop2's private key and verify.
	// Per I2P short-tunnel-build protocol, the sender applies chained ChaCha20
	// layer obfuscation: record j has been XOR'd with ChaCha20 streams keyed
	// from each preceding hop's reply key. To decrypt record 2 we must first
	// peel hop1's layer the same way the receiving network would: hop1
	// AEAD-decrypts record 1, derives its replyKey from the resulting Noise
	// chaining key, then XORs the same ChaCha20 stream over record 2.
	var enc2 [ShortBuildRecordSize]byte
	copy(enc2[:], encRec2Data)

	hop1Priv := hop1KS.GetEncryptionPrivateKey().Bytes()
	ck1, err := DecryptSTBMRecordReturningChainingKey(enc1, hop1Priv)
	require.NoError(t, err, "deriving hop1 chaining key should succeed")
	rk1, _, err := DeriveSTBMReplyKey(ck1)
	require.NoError(t, err, "deriving hop1 reply key should succeed")
	require.NoError(t, chacha20XORRecord(&enc2, rk1, 1), "peeling hop1 layer off record 2 should succeed")

	decrypted2, err := DecryptShortBuildRequestRecord(enc2, hop2KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err, "decryption of record 2 should succeed with hop2's key after layer peel")
	assert.Equal(t, rec2.ReceiveTunnel, decrypted2.ReceiveTunnel,
		"decrypted ReceiveTunnel should match original")
	assert.Equal(t, 1001, decrypted2.SendMessageID,
		"decrypted SendMessageID should equal the build message ID")

	// Cross-check: hop2's key should NOT decrypt record 1 successfully
	_, err = DecryptShortBuildRequestRecord(enc1, hop2KS.GetEncryptionPrivateKey().Bytes())
	assert.Error(t, err, "record 1 should NOT decrypt with hop2's key")
}

// TestCreateShortTunnelBuildMessage_RegistersOBEPGarlicKey verifies
// that the one-time garlic key/tag registered for STBM reply decryption is
// derived from the last hop's post-reply chaining key using the i2pd-compliant
// 3-step HKDF chain: SMTunnelLayerKey → TunnelLayerIVKey → RGarlicKeyAndTag.
func TestCreateShortTunnelBuildMessage_RegistersOBEPGarlicKey(t *testing.T) {
	hop1RI, _ := createTestHop(t)
	hop2RI, _ := createTestHop(t)

	rec1 := createTestTunnelRecord(t)
	rec2 := createTestTunnelRecord(t)

	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(12345),
		Hops:          []router_info.RouterInfo{*hop1RI, *hop2RI},
		Records:       []tunnel.BuildRequestRecord{rec1, rec2},
		UseShortBuild: true,
		IsInbound:     false,
	}

	registrar := &captureGarlicKeyRegistrar{}
	tm := &TunnelManager{garlicKeyRegistrar: registrar}

	msg, err := tm.createShortTunnelBuildMessage(result, 1001)
	require.NoError(t, err, "createShortTunnelBuildMessage should not fail")
	require.NotNil(t, msg)
	require.True(t, registrar.called, "expected one-time garlic key to be registered")

	// Verify exactly one key was registered (not multiple guesses).
	// The H1 fix removed the compatibility fallback registration from noiseHash.
	assert.Len(t, registrar.registrations, 1, "should register exactly one garlic key (OBEP path only, no compat)")
}

// TestCreateShortTunnelBuildMessage_ShortBuildRouting verifies that the STBM
// creation path produces a SHORT_TUNNEL_BUILD (type 25) message.
func TestCreateShortTunnelBuildMessage_ShortBuildRouting(t *testing.T) {
	hopRI, _ := createTestHop(t)
	rec := createTestTunnelRecord(t)

	result := makeSingleHopBuildResult(*hopRI, rec, tunnel.TunnelID(33333), true)

	tm := &TunnelManager{}
	msg, err := tm.createShortTunnelBuildMessage(result, 3003)
	require.NoError(t, err)
	assert.Equal(t, I2NPMessageTypeShortTunnelBuild, msg.Type(),
		"should create SHORT_TUNNEL_BUILD message")
}

// TestCreateShortTunnelBuildMessage_MismatchedHops verifies error handling when
// record count exceeds hop count.
func TestCreateShortTunnelBuildMessage_MismatchedHops(t *testing.T) {
	hopRI, _ := createTestHop(t)
	rec1 := createTestTunnelRecord(t)
	rec2 := createTestTunnelRecord(t)

	// 2 records but only 1 hop — should fail
	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(55555),
		Hops:          []router_info.RouterInfo{*hopRI},
		Records:       []tunnel.BuildRequestRecord{rec1, rec2},
		UseShortBuild: true,
		IsInbound:     false,
	}

	tm := &TunnelManager{}
	_, err := tm.createShortTunnelBuildMessage(result, 5005)
	assert.Error(t, err, "should fail when records outnumber hops")
	assert.Contains(t, err.Error(), "no corresponding hop")
}

// TestCreateShortTunnelBuildMessage_NonDeterministic verifies that encrypting
// the same cleartext records twice produces different ciphertext (due to
// ephemeral ECIES keys and random nonces).
func TestCreateShortTunnelBuildMessage_NonDeterministic(t *testing.T) {
	hopRI, _ := createTestHop(t)
	rec := createTestTunnelRecord(t)

	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(77777),
		Hops:          []router_info.RouterInfo{*hopRI},
		Records:       []tunnel.BuildRequestRecord{rec},
		UseShortBuild: true,
		IsInbound:     false,
	}

	tm := &TunnelManager{}
	msg1, err := tm.createShortTunnelBuildMessage(result, 7007)
	require.NoError(t, err)
	msg2, err := tm.createShortTunnelBuildMessage(result, 7008)
	require.NoError(t, err)

	data1 := msg1.(*BaseI2NPMessage).GetData()
	data2 := msg2.(*BaseI2NPMessage).GetData()

	// The encrypted records should differ (each STBM uses a fresh ephemeral X25519 key)
	end := 1 + ShortBuildRecordSize
	assert.NotEqual(t, data1[1:end], data2[1:end],
		"two encryptions of the same record should produce different ciphertext")
}

// convertToI2NPRecord converts a tunnel.BuildRequestRecord to i2np.BuildRequestRecord.
func convertToI2NPRecord(rec tunnel.BuildRequestRecord) BuildRequestRecord {
	return BuildRequestRecord{
		ReceiveTunnel: rec.ReceiveTunnel,
		OurIdent:      rec.OurIdent,
		NextTunnel:    rec.NextTunnel,
		NextIdent:     rec.NextIdent,
		LayerKey:      rec.LayerKey,
		IVKey:         rec.IVKey,
		ReplyKey:      rec.ReplyKey,
		ReplyIV:       rec.ReplyIV,
		Flag:          rec.Flag,
		RequestTime:   rec.RequestTime,
		SendMessageID: rec.SendMessageID,
		Padding:       rec.Padding,
	}
}

// TestSTBMLayerKeys_CreatorMatchesHop verifies the F062/F063 fix end-to-end:
// the tunnel creator's derived layer/IV keys (stored on result.Records by
// updateLayerKeysFromHKDF) must be byte-identical to the keys each transit hop
// independently derives from the same Noise chaining key (DeriveSTBMLayerKeys).
// If these diverge, tunnel data encrypted by the creator cannot be decrypted
// by the hops.
func TestSTBMLayerKeys_CreatorMatchesHop(t *testing.T) {
	hop1RI, hop1KS := createTestHop(t)
	hop2RI, hop2KS := createTestHop(t)

	rec1 := createTestTunnelRecord(t)
	rec2 := createTestTunnelRecord(t)
	rec2.ReceiveTunnel = tunnel.TunnelID(54321)
	rec2.SendMessageID = 99

	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(12345),
		Hops:          []router_info.RouterInfo{*hop1RI, *hop2RI},
		Records:       []tunnel.BuildRequestRecord{rec1, rec2},
		UseShortBuild: true,
		IsInbound:     false,
	}

	tm := &TunnelManager{}
	msg, err := tm.createShortTunnelBuildMessage(result, 1001)
	require.NoError(t, err, "createShortTunnelBuildMessage should not fail")
	require.NotNil(t, msg)

	baseMsg := msg.(*BaseI2NPMessage)
	data := baseMsg.GetData()
	require.Equal(t, 1+2*ShortBuildRecordSize, len(data))

	encRec1Data := data[1 : 1+ShortBuildRecordSize]
	encRec2Data := data[1+ShortBuildRecordSize : 1+2*ShortBuildRecordSize]

	// Hop 1 side: decrypt its record, derive the reply key, then the layer keys.
	var enc1 [ShortBuildRecordSize]byte
	copy(enc1[:], encRec1Data)
	ck1, _, err := DecryptSTBMRecordReturningChainingKeyAndHash(enc1, hop1KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err)
	rk1, postReplyCK1, err := DeriveSTBMReplyKey(ck1)
	require.NoError(t, err)
	hop1LayerKey, hop1IVKey, _, err := DeriveSTBMLayerKeys(postReplyCK1)
	require.NoError(t, err)

	// Creator side must have derived the SAME keys for hop 1 (F063).
	assert.Equal(t, hop1LayerKey[:], result.Records[0].LayerKey[:],
		"creator's hop-1 layer key must match the hop's derived layer key")
	assert.Equal(t, hop1IVKey[:], result.Records[0].IVKey[:],
		"creator's hop-1 IV key must match the hop's derived IV key")

	// Hop 2 side: peel hop 1's layer, decrypt, derive keys.
	var enc2 [ShortBuildRecordSize]byte
	copy(enc2[:], encRec2Data)
	require.NoError(t, chacha20XORRecord(&enc2, rk1, 1), "peeling hop1 layer off record 2")

	ck2, _, err := DecryptSTBMRecordReturningChainingKeyAndHash(enc2, hop2KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err)
	_, postReplyCK2, err := DeriveSTBMReplyKey(ck2)
	require.NoError(t, err)
	hop2LayerKey, hop2IVKey, _, err := DeriveSTBMLayerKeys(postReplyCK2)
	require.NoError(t, err)

	// Creator side must have derived the SAME keys for hop 2 (F063).
	assert.Equal(t, hop2LayerKey[:], result.Records[1].LayerKey[:],
		"creator's hop-2 layer key must match the hop's derived layer key")
	assert.Equal(t, hop2IVKey[:], result.Records[1].IVKey[:],
		"creator's hop-2 IV key must match the hop's derived IV key")

	// Keys must be non-zero (F062 guard).
	assert.NotEqual(t, make([]byte, 32), result.Records[0].LayerKey[:], "hop-1 layer key must be non-zero")
	assert.NotEqual(t, make([]byte, 32), result.Records[1].LayerKey[:], "hop-2 layer key must be non-zero")
	assert.NotEqual(t, make([]byte, 32), result.Records[0].IVKey[:], "hop-1 IV key must be non-zero")
	assert.NotEqual(t, make([]byte, 32), result.Records[1].IVKey[:], "hop-2 IV key must be non-zero")
}

// TestDeriveSTBMLayerKeys_Deterministic verifies that DeriveSTBMLayerKeys is a
// pure function of the post-reply chaining key (both creator and hop derive
// identical output for identical input) and that the OBEP garlic key chain is
// built on the same intermediate keys.
func TestDeriveSTBMLayerKeys_Deterministic(t *testing.T) {
	var ck [32]byte
	for i := range ck {
		ck[i] = byte(i)
	}

	lk1, iv1, next1, err := DeriveSTBMLayerKeys(ck)
	require.NoError(t, err)
	lk2, iv2, next2, err := DeriveSTBMLayerKeys(ck)
	require.NoError(t, err)

	assert.Equal(t, lk1, lk2, "layer key derivation must be deterministic")
	assert.Equal(t, iv1, iv2, "IV key derivation must be deterministic")
	assert.Equal(t, next1, next2, "chaining key derivation must be deterministic")
	assert.NotEqual(t, [32]byte{}, lk1, "layer key must be non-zero")
	assert.NotEqual(t, [32]byte{}, iv1, "IV key must be non-zero")

	// The OBEP garlic key chain must consume the same intermediate chaining key.
	garlicKey, tag, err := DeriveSTBMOBEPGarlicKeyAndTag(ck)
	require.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, garlicKey, "garlic key must be non-zero")
	assert.NotEqual(t, [8]byte{}, tag, "garlic tag must be non-zero")
}

// Test helper methods for backward compatibility with existing tests.
// These wrap the new serialized methods and parse results back to Message objects.

func (tm *TunnelManager) createShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (Message, error) {
	if tm.messageFactory == nil {
		tm.messageFactory = NewBuildMessageFactory()
	}
	data, err := tm.createSerializedShortTunnelBuildMessage(result, messageID)
	if err != nil {
		return nil, err
	}
	// Parse the serialized message back into a Message object
	msg := &BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return msg, nil
}
