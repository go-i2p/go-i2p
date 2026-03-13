package i2np

import (
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupProcessorWithForwarder creates a MessageProcessor wired to a mock build reply forwarder.
func setupProcessorWithForwarder(t *testing.T) (*MessageProcessor, *mockBuildReplyForwarder) {
	t.Helper()
	processor := NewMessageProcessor()
	fwd := newMockBuildReplyForwarder()
	processor.SetBuildReplyForwarder(fwd)
	return processor, fwd
}

// setupFloodfillTest creates a DatabaseManager with a mock NetDB containing n floodfill routers.
func setupFloodfillTest(t *testing.T, n int) (*DatabaseManager, *mockFloodfillNetDB) {
	t.Helper()
	mockNetDB := newMockFloodfillNetDB()
	for i := 0; i < n; i++ {
		mockNetDB.addFloodfillRouter()
	}
	dbManager := NewDatabaseManager(mockNetDB)
	dbManager.SetFloodfillSelector(mockNetDB)
	return dbManager, mockNetDB
}

// buildResponseRecordTestData creates common test data for build response record tests:
// a 32-byte hash (with hash[31] set to hashEndByte), 495-byte random data, and their concatenation.
func buildResponseRecordTestData(hashEndByte byte) (hash []byte, randomData []byte, data []byte) {
	hash = make([]byte, 32)
	hash[31] = hashEndByte
	randomData = make([]byte, 495)
	randomData[493] = 0x33
	randomData[494] = 0x74
	data = append(hash, randomData...)
	return
}

// setupNewGarlicSession creates a GarlicSessionManager with a freshly generated ECIES
// key pair, returning the manager, destination public key, and destination hash.
func setupNewGarlicSession(t *testing.T) (*GarlicSessionManager, [32]byte, [32]byte) {
	t.Helper()
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])
	return sm, destPubKey, destHash
}

// makeBenchmarkReplyKeys generates random reply key, IV, and random data for benchmark tests.
func makeBenchmarkReplyKeys() (session_key.SessionKey, [16]byte, [495]byte) {
	var replyKey session_key.SessionKey
	var replyIV [16]byte
	var randomData [495]byte
	rand.Read(replyKey[:])
	rand.Read(replyIV[:])
	rand.Read(randomData[:])
	return replyKey, replyIV, randomData
}

// makeSSUExpirationData creates a 5-byte SSU expiration test buffer:
// 1 type byte (0x00) followed by 4-byte big-endian seconds.
func makeSSUExpirationData(seconds uint32) []byte {
	data := make([]byte, 5)
	data[0] = 0x00
	binary.BigEndian.PutUint32(data[1:5], seconds)
	return data
}

// setupSearchReplyProcessor creates a MessageProcessor with expiration checks
// disabled and a mock search reply handler attached.
func setupSearchReplyProcessor(t *testing.T) (*MessageProcessor, *mockSearchReplyHandler) {
	t.Helper()
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()
	handler := &mockSearchReplyHandler{}
	processor.SetSearchReplyHandler(handler)
	return processor, handler
}

// generateRandomBuildKeys creates random cryptographic keys and identities
// used when constructing BuildRequestRecord test data.
func generateRandomBuildKeys() (layerKey, ivKey, replyKey session_key.SessionKey, replyIV [16]byte, padding [29]byte, ourIdent, nextIdent common.Hash) {
	rand.Read(layerKey[:])
	rand.Read(ivKey[:])
	rand.Read(replyKey[:])
	rand.Read(replyIV[:])
	rand.Read(padding[:])
	rand.Read(ourIdent[:])
	rand.Read(nextIdent[:])
	return
}

// buildOurIdentTestData creates test data for build request record OurIdent tests:
// a 4-byte receive tunnel followed by an identity of the specified length.
func buildOurIdentTestData(identLen int, identByte byte) (testData []byte, ourIdent []byte) {
	receiveTunnel := []byte{0x00, 0x00, 0x00, 0x01}
	ourIdent = make([]byte, identLen)
	ourIdent[identLen-1] = identByte
	testData = append(receiveTunnel, ourIdent...)
	return
}

// assertDeserializeCloveError asserts that deserializeGarlicClove returns an error
// containing errMsg and a nil clove.
func assertDeserializeCloveError(t *testing.T, cloveData []byte, errMsg string) {
	t.Helper()
	clove, _, err := deserializeGarlicClove(cloveData, 0)
	require.Error(t, err)
	assert.Nil(t, clove)
	assert.Contains(t, err.Error(), errMsg)
}

// processDirectBuildRecord creates a test build request record with NextTunnel=0
// (direct router forwarding) and calls processSingleBuildRecord.
func processDirectBuildRecord(t *testing.T, processor *MessageProcessor, messageID int) BuildRequestRecord {
	t.Helper()
	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0
	processor.processSingleBuildRecord(messageID, 0, record, false)
	return record
}

// marshalUnmarshalLookup marshals a DatabaseLookup, verifies the wire size equals
// expectedSize, then unmarshals it and returns the parsed result.
func marshalUnmarshalLookup(t *testing.T, lookup *DatabaseLookup, expectedSize int) DatabaseLookup {
	t.Helper()
	data, err := lookup.MarshalBinary()
	require.Nil(t, err)
	require.Equal(t, expectedSize, len(data))
	parsed, err := ReadDatabaseLookup(data)
	require.Nil(t, err)
	return parsed
}

// mustParseDatabaseLookupFlags calls readDatabaseLookupFlags and fatals on error.
func mustParseDatabaseLookupFlags(t *testing.T, length int, data []byte) (int, byte) {
	t.Helper()
	length, flags, err := readDatabaseLookupFlags(length, data)
	if err != nil {
		t.Fatalf("readDatabaseLookupFlags failed: %v", err)
	}
	return length, flags
}

// assertLookupFieldsMatch asserts that the common DatabaseLookup fields match
// the expected values from a lookupExpected struct.
func assertLookupFieldsMatch(t *testing.T, dl DatabaseLookup, exp lookupExpected) {
	t.Helper()
	assert.Equal(t, exp.Key, dl.Key)
	assert.Equal(t, exp.From, dl.From)
	assert.Equal(t, exp.Flags, dl.Flags)
	assert.Equal(t, exp.TunnelID, dl.ReplyTunnelID)
	assert.Equal(t, exp.Size, dl.Size)
	assert.Equal(t, exp.Peers, dl.ExcludedPeers)
	assert.Equal(t, exp.ReplyKey, dl.ReplyKey)
}

// registerPendingBuild creates a ReplyProcessor with the given config, generates
// numKeys reply keys, and registers a pending build for the given tunnel ID.
func registerPendingBuild(t *testing.T, config ReplyProcessorConfig, tunnelID tunnel.TunnelID, numKeys int, isInbound bool) *ReplyProcessor {
	t.Helper()
	rp := NewReplyProcessor(config, nil)
	replyKeys, replyIVs := generateReplyKeys(t, numKeys)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, isInbound, numKeys)
	require.NoError(t, err)
	return rp
}

// serializeAndAssertInstructions serializes delivery instructions and verifies
// the output length and leading flag byte.
func serializeAndAssertInstructions(t *testing.T, instructions *GarlicCloveDeliveryInstructions, expectedLen int, expectedFlag byte) []byte {
	t.Helper()
	serialized, err := serializeDeliveryInstructions(instructions)
	require.NoError(t, err)
	assert.Len(t, serialized, expectedLen)
	assert.Equal(t, expectedFlag, serialized[0], "flag")
	return serialized
}

// makeSingleHopBuildResult creates a TunnelBuildResult with one hop and one record.
func makeSingleHopBuildResult(hopRI router_info.RouterInfo, rec tunnel.BuildRequestRecord, tunnelID tunnel.TunnelID, useShortBuild bool) *tunnel.TunnelBuildResult {
	return &tunnel.TunnelBuildResult{
		TunnelID:      tunnelID,
		Hops:          []router_info.RouterInfo{hopRI},
		Records:       []tunnel.BuildRequestRecord{rec},
		UseShortBuild: useShortBuild,
		IsInbound:     false,
	}
}
