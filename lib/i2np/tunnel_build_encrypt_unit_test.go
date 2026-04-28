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
	assert.Equal(t, rec1.SendMessageID, decrypted1.SendMessageID,
		"decrypted SendMessageID should match original")

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
	rk1, err := DeriveSTBMReplyKey(ck1)
	require.NoError(t, err, "deriving hop1 reply key should succeed")
	require.NoError(t, peelSTBMRecordLayer(&enc2, rk1, 1), "peeling hop1 layer off record 2 should succeed")

	decrypted2, err := DecryptShortBuildRequestRecord(enc2, hop2KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err, "decryption of record 2 should succeed with hop2's key after layer peel")
	assert.Equal(t, rec2.ReceiveTunnel, decrypted2.ReceiveTunnel,
		"decrypted ReceiveTunnel should match original")
	assert.Equal(t, rec2.SendMessageID, decrypted2.SendMessageID,
		"decrypted SendMessageID should match original")

	// Cross-check: hop2's key should NOT decrypt record 1 successfully
	_, err = DecryptShortBuildRequestRecord(enc1, hop2KS.GetEncryptionPrivateKey().Bytes())
	assert.Error(t, err, "record 1 should NOT decrypt with hop2's key")
}

// TestCreateBuildMessage_EncryptsRecords verifies that both TunnelBuild (type 21)
// and VariableTunnelBuild (type 23) encrypt records correctly.
func TestCreateBuildMessage_EncryptsRecords(t *testing.T) {
	tests := []struct {
		name         string
		createMsg    func(*TunnelManager, *tunnel.TunnelBuildResult, int) (I2NPMessage, error)
		expectedLen  int
		recordOffset int
		checkPrefix  bool
		tunnelID     tunnel.TunnelID
		msgID        int
	}{
		{
			name: "TunnelBuild_Type21_Fixed8Records",
			createMsg: func(tm *TunnelManager, r *tunnel.TunnelBuildResult, id int) (I2NPMessage, error) {
				return tm.createTunnelBuildMessage(r, id)
			},
			expectedLen:  8 * 528,
			recordOffset: 0,
			tunnelID:     tunnel.TunnelID(11111),
			msgID:        2002,
		},
		{
			name: "VariableTunnelBuild_Type23_CountPrefix",
			createMsg: func(tm *TunnelManager, r *tunnel.TunnelBuildResult, id int) (I2NPMessage, error) {
				return tm.createVariableTunnelBuildMessage(r, id)
			},
			expectedLen:  1 + 1*528,
			recordOffset: 1,
			checkPrefix:  true,
			tunnelID:     tunnel.TunnelID(11112),
			msgID:        2003,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hop1RI, hop1KS := createTestHop(t)
			rec1 := createTestTunnelRecord(t)
			result := makeSingleHopBuildResult(*hop1RI, rec1, tt.tunnelID, false)

			tm := &TunnelManager{}
			msg, err := tt.createMsg(tm, result, tt.msgID)
			require.NoError(t, err)
			require.NotNil(t, msg)

			baseMsg := msg.(*BaseI2NPMessage)
			data := baseMsg.GetData()
			require.Equal(t, tt.expectedLen, len(data))

			if tt.checkPrefix {
				assert.Equal(t, byte(1), data[0], "First byte should be record count")
			}

			var enc1 [528]byte
			copy(enc1[:], data[tt.recordOffset:tt.recordOffset+528])
			decrypted1, err := DecryptBuildRequestRecord(enc1, hop1KS.GetEncryptionPrivateKey().Bytes())
			require.NoError(t, err, "decryption of record 1 should succeed")
			assert.Equal(t, rec1.ReceiveTunnel, decrypted1.ReceiveTunnel)
			assert.Equal(t, rec1.SendMessageID, decrypted1.SendMessageID)
		})
	}
}

// TestSelectBuildMessage_ShortBuild verifies that selectBuildMessage routes
// to STBM when UseShortBuild is true.
func TestSelectBuildMessage_ShortBuild(t *testing.T) {
	hopRI, _ := createTestHop(t)
	rec := createTestTunnelRecord(t)

	result := makeSingleHopBuildResult(*hopRI, rec, tunnel.TunnelID(33333), true)

	tm := &TunnelManager{}
	msg, err := tm.selectBuildMessage(result, 3003)
	require.NoError(t, err)
	assert.Equal(t, I2NPMessageTypeShortTunnelBuild, msg.Type(),
		"should create SHORT_TUNNEL_BUILD message")
}

// TestSelectBuildMessage_LegacyBuild verifies that selectBuildMessage routes
// to VTB when UseShortBuild is false.
func TestSelectBuildMessage_LegacyBuild(t *testing.T) {
	hopRI, _ := createTestHop(t)
	rec := createTestTunnelRecord(t)

	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(44444),
		Hops:          []router_info.RouterInfo{*hopRI},
		Records:       []tunnel.BuildRequestRecord{rec},
		UseShortBuild: false,
		IsInbound:     false,
	}

	tm := &TunnelManager{}
	msg, err := tm.selectBuildMessage(result, 4004)
	require.NoError(t, err)
	assert.Equal(t, I2NPMessageTypeTunnelBuild, msg.Type(),
		"should create TUNNEL_BUILD message")
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

// TestCreateTunnelBuildMessage_MismatchedHops verifies error handling
// for the TunnelBuild (type 21) path.
func TestCreateTunnelBuildMessage_MismatchedHops(t *testing.T) {
	hopRI, _ := createTestHop(t)
	rec1 := createTestTunnelRecord(t)
	rec2 := createTestTunnelRecord(t)

	// 2 records but only 1 hop — should fail
	result := &tunnel.TunnelBuildResult{
		TunnelID:      tunnel.TunnelID(66666),
		Hops:          []router_info.RouterInfo{*hopRI},
		Records:       []tunnel.BuildRequestRecord{rec1, rec2},
		UseShortBuild: false,
		IsInbound:     false,
	}

	tm := &TunnelManager{}
	_, err := tm.createTunnelBuildMessage(result, 6006)
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
