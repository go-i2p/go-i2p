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

	// The message data should be: 1 byte count + 2*528 bytes encrypted records
	baseMsg := msg.(*BaseI2NPMessage)
	data := baseMsg.GetData()
	require.Equal(t, 1+2*528, len(data), "STBM data should be 1 + 2*528 bytes")

	// First byte is the record count
	assert.Equal(t, byte(2), data[0], "record count should be 2")

	// Extract encrypted records
	encRec1Data := data[1 : 1+528]
	encRec2Data := data[1+528 : 1+2*528]

	// Verify records are NOT cleartext (first 222 bytes should differ from cleartext)
	i2npRec1 := convertToI2NPRecord(rec1)
	cleartextRec1 := i2npRec1.Bytes()
	assert.NotEqual(t, cleartextRec1, encRec1Data[:222],
		"encrypted record should not contain cleartext data")

	// Decrypt record 1 with hop1's private key and verify
	var enc1 [528]byte
	copy(enc1[:], encRec1Data)
	decrypted1, err := DecryptBuildRequestRecord(enc1, hop1KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err, "decryption of record 1 should succeed with hop1's key")
	assert.Equal(t, rec1.ReceiveTunnel, decrypted1.ReceiveTunnel,
		"decrypted ReceiveTunnel should match original")
	assert.Equal(t, rec1.SendMessageID, decrypted1.SendMessageID,
		"decrypted SendMessageID should match original")

	// Decrypt record 2 with hop2's private key and verify
	var enc2 [528]byte
	copy(enc2[:], encRec2Data)
	decrypted2, err := DecryptBuildRequestRecord(enc2, hop2KS.GetEncryptionPrivateKey().Bytes())
	require.NoError(t, err, "decryption of record 2 should succeed with hop2's key")
	assert.Equal(t, rec2.ReceiveTunnel, decrypted2.ReceiveTunnel,
		"decrypted ReceiveTunnel should match original")
	assert.Equal(t, rec2.SendMessageID, decrypted2.SendMessageID,
		"decrypted SendMessageID should match original")

	// Cross-check: hop2's key should NOT decrypt record 1 successfully
	_, err = DecryptBuildRequestRecord(enc1, hop2KS.GetEncryptionPrivateKey().Bytes())
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

	// The encrypted records should differ (ECIES uses ephemeral keys)
	assert.NotEqual(t, data1[1:529], data2[1:529],
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
