package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	cryptotunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Section 9: lib/tunnel — Tunnel Messages
// =============================================================================

// --- Fixed Size (1028 bytes) ---

func TestTunnelMessages_FixedSize_EncryptedTunnelMessageIs1028(t *testing.T) {
	// EncryptedTunnelMessage is an alias for tunnel.TunnelData which is [1028]byte
	var msg EncryptedTunnelMessage
	assert.Equal(t, 1028, len(msg[:]), "EncryptedTunnelMessage must be exactly 1028 bytes")
}

func TestTunnelMessages_FixedSize_DecryptedTunnelMessageIs1028(t *testing.T) {
	// DecryptedTunnelMessage is [1028]byte
	var msg DecryptedTunnelMessage
	assert.Equal(t, 1028, len(msg[:]), "DecryptedTunnelMessage must be exactly 1028 bytes")
}

func TestTunnelMessages_FixedSize_LayoutTunnelID4Bytes(t *testing.T) {
	// Tunnel ID occupies bytes [0:4]
	var msg DecryptedTunnelMessage
	binary.BigEndian.PutUint32(msg[0:4], 0xDEADBEEF)
	assert.Equal(t, TunnelID(0xDEADBEEF), msg.ID(), "Tunnel ID must be read from bytes [0:4]")
}

func TestTunnelMessages_FixedSize_LayoutIV16Bytes(t *testing.T) {
	// IV occupies bytes [4:20] (16 bytes)
	var msg DecryptedTunnelMessage
	for i := 4; i < 20; i++ {
		msg[i] = byte(i - 4 + 1)
	}
	iv := msg.IV()
	assert.Equal(t, 16, len(iv), "IV must be 16 bytes")
	for i := 0; i < 16; i++ {
		assert.Equal(t, byte(i+1), iv[i], "IV byte %d mismatch", i)
	}
}

func TestTunnelMessages_FixedSize_LayoutChecksum4Bytes(t *testing.T) {
	// Checksum occupies bytes [20:24] (4 bytes)
	var msg DecryptedTunnelMessage
	msg[20] = 0xAA
	msg[21] = 0xBB
	msg[22] = 0xCC
	msg[23] = 0xDD
	checksum := msg.Checksum()
	assert.Equal(t, 4, len(checksum), "Checksum must be 4 bytes")
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, checksum)
}

func TestTunnelMessages_FixedSize_EncryptedDataIs1004Bytes(t *testing.T) {
	// EncryptedTunnelMessage.Data() returns bytes after tunnel ID (4) + IV (16) + checksum (4) = [24:]
	// which is 1028 - 24 = 1004 bytes
	var msg EncryptedTunnelMessage
	data := msg.Data()
	assert.Equal(t, 1004, len(data), "Encrypted data area must be 1028 - 24 = 1004 bytes")
}

func TestTunnelMessages_FixedSize_GatewayProduces1028ByteOutput(t *testing.T) {
	// Gateway.buildTunnelMessage must produce exactly 1028 bytes
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	// Create small delivery instructions and message
	di := []byte{0x00, 0x00, 0x05} // DT_LOCAL, unfragmented, size=5
	payload := []byte{1, 2, 3, 4, 5}

	msg, err := gw.buildTunnelMessage(di, payload)
	require.NoError(t, err)
	assert.Equal(t, 1028, len(msg), "Gateway.buildTunnelMessage must produce exactly 1028 bytes")
}

func TestTunnelMessages_FixedSize_EndpointRejectsNon1028(t *testing.T) {
	// Endpoint.Receive must reject data that isn't exactly 1028 bytes
	enc := &specMockEncryptor{}
	handler := func(msgBytes []byte) error { return nil }
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	// Too short
	err = ep.Receive(make([]byte, 1027))
	assert.ErrorIs(t, err, ErrInvalidTunnelData, "Must reject data shorter than 1028 bytes")

	// Too long
	err = ep.Receive(make([]byte, 1029))
	assert.ErrorIs(t, err, ErrInvalidTunnelData, "Must reject data longer than 1028 bytes")

	// Empty
	err = ep.Receive([]byte{})
	assert.ErrorIs(t, err, ErrInvalidTunnelData, "Must reject empty data")
}

func TestTunnelMessages_FixedSize_ParticipantRejectsNon1028(t *testing.T) {
	// Participant also processes 1028-byte messages only
	enc := &specMockEncryptor{}
	p, err := NewParticipant(TunnelID(1), enc)
	require.NoError(t, err)

	_, _, err = p.Process(make([]byte, 500))
	assert.Error(t, err, "Participant must reject data that is not 1028 bytes")
}

func TestTunnelMessages_FixedSize_MaxTunnelPayloadConstant(t *testing.T) {
	// maxTunnelPayload = 1028 - 4(tunnelID) - 16(IV) - 4(checksum) - 1(zero byte) = 1003
	assert.Equal(t, 1003, maxTunnelPayload,
		"maxTunnelPayload must be 1003 (1028 - 25 bytes overhead)")
}

func TestTunnelMessages_FixedSize_ChecksumIsSHA256First4Bytes(t *testing.T) {
	// Checksum = first 4 bytes of SHA256(data_after_checksum + IV)
	// Build a tunnel message via Gateway and verify the checksum
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	di := []byte{0x00, 0x00, 0x05}
	payload := []byte{1, 2, 3, 4, 5}

	msg, err := gw.buildTunnelMessage(di, payload)
	require.NoError(t, err)

	// Extract components
	iv := msg[4:20]
	storedChecksum := msg[20:24]
	dataAfterChecksum := msg[24:]

	// Recompute checksum: SHA256(dataAfterChecksum + IV), take first 4 bytes
	checksumInput := make([]byte, len(dataAfterChecksum)+len(iv))
	copy(checksumInput, dataAfterChecksum)
	copy(checksumInput[len(dataAfterChecksum):], iv)
	hash := sha256.Sum256(checksumInput)
	expectedChecksum := hash[:4]

	assert.Equal(t, expectedChecksum, storedChecksum,
		"Checksum must be first 4 bytes of SHA256(data_after_checksum + IV)")
}

func TestTunnelMessages_FixedSize_NonZeroPadding(t *testing.T) {
	// I2P spec requires padding bytes to be non-zero
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	di := []byte{0x00, 0x00, 0x05}
	payload := []byte{1, 2, 3, 4, 5}

	msg, err := gw.buildTunnelMessage(di, payload)
	require.NoError(t, err)

	// Find the zero separator byte
	paddingStart := 24 // after tunnelID(4) + IV(16) + checksum(4)
	zeroBytePos := -1
	for i := paddingStart; i < len(msg); i++ {
		if msg[i] == 0x00 {
			zeroBytePos = i
			break
		}
	}
	require.Greater(t, zeroBytePos, paddingStart, "Must have at least some padding before zero separator")

	// All bytes before the zero separator must be non-zero
	for i := paddingStart; i < zeroBytePos; i++ {
		assert.NotEqual(t, byte(0), msg[i],
			"Padding byte at offset %d must be non-zero (I2P spec requirement)", i)
	}
}

// --- Delivery Instructions ---

func TestTunnelMessages_DeliveryInstructions_FirstFragmentFlagBit7Is0(t *testing.T) {
	// First fragment: bit 7 = 0
	di := NewLocalDeliveryInstructions(100)
	data, err := di.Bytes()
	require.NoError(t, err)
	assert.Equal(t, byte(0), data[0]&0x80, "First fragment flag byte bit 7 must be 0")
}

func TestTunnelMessages_DeliveryInstructions_FollowOnFragmentFlagBit7Is1(t *testing.T) {
	// Follow-on fragment: bit 7 = 1
	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 1,
		lastFragment:   false,
		messageID:      0x12345678,
		fragmentSize:   200,
	}
	data, err := di.Bytes()
	require.NoError(t, err)
	assert.Equal(t, byte(0x80), data[0]&0x80, "Follow-on fragment flag byte bit 7 must be 1")
}

func TestTunnelMessages_DeliveryInstructions_FirstFragmentDeliveryTypes(t *testing.T) {
	// Bits 6-5 encode delivery type: LOCAL=0x00, TUNNEL=0x01, ROUTER=0x02
	tests := []struct {
		name         string
		di           *DeliveryInstructions
		expectedBits byte
	}{
		{
			name:         "DT_LOCAL",
			di:           NewLocalDeliveryInstructions(10),
			expectedBits: 0x00, // bits 6-5 = 00
		},
		{
			name:         "DT_TUNNEL",
			di:           NewTunnelDeliveryInstructions(1234, [32]byte{0xAA}, 10),
			expectedBits: 0x20, // bits 6-5 = 01
		},
		{
			name:         "DT_ROUTER",
			di:           NewRouterDeliveryInstructions([32]byte{0xBB}, 10),
			expectedBits: 0x40, // bits 6-5 = 10
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.di.Bytes()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBits, data[0]&0x60,
				"Delivery type bits 6-5 must encode %s correctly", tt.name)
		})
	}
}

func TestTunnelMessages_DeliveryInstructions_FirstFragmentSizes(t *testing.T) {
	// LOCAL = 3 bytes (flag + size)
	// ROUTER unfragmented = 35 bytes (flag + hash(32) + size(2))
	// TUNNEL unfragmented = 39 bytes (flag + tunnelID(4) + hash(32) + size(2))
	// ROUTER fragmented = 39 bytes (flag + hash(32) + msgID(4) + size(2))
	// TUNNEL fragmented = 43 bytes (flag + tunnelID(4) + hash(32) + msgID(4) + size(2))

	localDI := NewLocalDeliveryInstructions(100)
	localBytes, err := localDI.Bytes()
	require.NoError(t, err)
	assert.Equal(t, 3, len(localBytes), "LOCAL delivery instructions must be 3 bytes")

	routerDI := NewRouterDeliveryInstructions([32]byte{0xBB}, 100)
	routerBytes, err := routerDI.Bytes()
	require.NoError(t, err)
	assert.Equal(t, 35, len(routerBytes), "ROUTER unfragmented delivery instructions must be 35 bytes")

	tunnelDI := NewTunnelDeliveryInstructions(1234, [32]byte{0xAA}, 100)
	tunnelBytes, err := tunnelDI.Bytes()
	require.NoError(t, err)
	assert.Equal(t, 39, len(tunnelBytes), "TUNNEL unfragmented delivery instructions must be 39 bytes")

	// Fragmented ROUTER = 39 bytes
	routerFragDI := NewRouterDeliveryInstructions([32]byte{0xBB}, 100)
	routerFragDI.fragmented = true
	routerFragDI.messageID = 0x12345678
	routerFragBytes, err := routerFragDI.Bytes()
	require.NoError(t, err)
	assert.Equal(t, 39, len(routerFragBytes), "ROUTER fragmented delivery instructions must be 39 bytes")

	// Fragmented TUNNEL = 43 bytes
	tunnelFragDI := NewTunnelDeliveryInstructions(1234, [32]byte{0xAA}, 100)
	tunnelFragDI.fragmented = true
	tunnelFragDI.messageID = 0x12345678
	tunnelFragBytes, err := tunnelFragDI.Bytes()
	require.NoError(t, err)
	assert.Equal(t, 43, len(tunnelFragBytes), "TUNNEL fragmented delivery instructions must be 43 bytes")
}

func TestTunnelMessages_DeliveryInstructions_FollowOnFragmentIs7Bytes(t *testing.T) {
	// Follow-on fragment is exactly 7 bytes: flag(1) + messageID(4) + size(2)
	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 5,
		lastFragment:   false,
		messageID:      0xABCD1234,
		fragmentSize:   500,
	}
	data, err := di.Bytes()
	require.NoError(t, err)
	assert.Equal(t, 7, len(data), "Follow-on fragment delivery instructions must be exactly 7 bytes")
}

func TestTunnelMessages_DeliveryInstructions_FollowOnFragmentNumberBits6to1(t *testing.T) {
	// Follow-on fragment number is encoded in bits 6-1 of flag byte
	for fragNum := 1; fragNum <= 63; fragNum++ {
		di := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: fragNum,
			lastFragment:   false,
			messageID:      1,
			fragmentSize:   10,
		}
		data, err := di.Bytes()
		require.NoError(t, err)

		// Extract fragment number from bits 6-1
		extractedNum := int((data[0] & 0x7E) >> 1)
		assert.Equal(t, fragNum, extractedNum,
			"Fragment number %d must be correctly encoded in bits 6-1", fragNum)
	}
}

func TestTunnelMessages_DeliveryInstructions_FollowOnLastFragmentBit0(t *testing.T) {
	// Last fragment flag is bit 0 of follow-on flag byte
	diNotLast := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 3,
		lastFragment:   false,
		messageID:      1,
		fragmentSize:   10,
	}
	dataNotLast, err := diNotLast.Bytes()
	require.NoError(t, err)
	assert.Equal(t, byte(0), dataNotLast[0]&0x01, "Non-last fragment must have bit 0 = 0")

	diLast := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 3,
		lastFragment:   true,
		messageID:      1,
		fragmentSize:   10,
	}
	dataLast, err := diLast.Bytes()
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), dataLast[0]&0x01, "Last fragment must have bit 0 = 1")
}

func TestTunnelMessages_DeliveryInstructions_FragmentedBit3(t *testing.T) {
	// Fragmented flag is bit 3 of first fragment flag byte
	diFrag := NewLocalDeliveryInstructions(100)
	diFrag.fragmented = true
	diFrag.messageID = 0x12345678
	dataFrag, err := diFrag.Bytes()
	require.NoError(t, err)
	assert.Equal(t, byte(0x08), dataFrag[0]&0x08, "Fragmented bit 3 must be set when fragmented")

	diNoFrag := NewLocalDeliveryInstructions(100)
	dataNoFrag, err := diNoFrag.Bytes()
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), dataNoFrag[0]&0x08, "Fragmented bit 3 must be clear when not fragmented")
}

func TestTunnelMessages_DeliveryInstructions_DT_UNUSEDRejected(t *testing.T) {
	// DT_UNUSED (0x03) delivery type must be rejected
	// Create raw bytes with delivery type 0x03 in bits 6-5
	raw := []byte{0x60, 0x00, 0x05} // flag = 0x60 means bits 6-5 = 11 = DT_UNUSED
	_, err := NewDeliveryInstructions(raw)
	assert.Error(t, err, "DT_UNUSED (0x03) delivery type must be rejected")
}

func TestTunnelMessages_DeliveryInstructions_SerializeDeserializeRoundtrip(t *testing.T) {
	// Test roundtrip for each delivery type
	tests := []struct {
		name string
		di   *DeliveryInstructions
	}{
		{
			name: "LOCAL unfragmented",
			di:   NewLocalDeliveryInstructions(100),
		},
		{
			name: "TUNNEL unfragmented",
			di:   NewTunnelDeliveryInstructions(5678, [32]byte{0x01, 0x02, 0x03}, 200),
		},
		{
			name: "ROUTER unfragmented",
			di:   NewRouterDeliveryInstructions([32]byte{0xAA, 0xBB, 0xCC}, 300),
		},
		{
			name: "Follow-on fragment",
			di: &DeliveryInstructions{
				fragmentType:   FOLLOW_ON_FRAGMENT,
				fragmentNumber: 7,
				lastFragment:   true,
				messageID:      0xDEADBEEF,
				fragmentSize:   500,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.di.Bytes()
			require.NoError(t, err)

			parsed, err := NewDeliveryInstructions(data)
			require.NoError(t, err)

			fragType, err := parsed.Type()
			require.NoError(t, err)
			origType, _ := tt.di.Type()
			assert.Equal(t, origType, fragType, "Fragment type must survive roundtrip")

			fragSize, err := parsed.FragmentSize()
			require.NoError(t, err)
			origSize, _ := tt.di.FragmentSize()
			assert.Equal(t, origSize, fragSize, "Fragment size must survive roundtrip")

			if fragType == FOLLOW_ON_FRAGMENT {
				parsedMsgID, err := parsed.MessageID()
				require.NoError(t, err)
				origMsgID, _ := tt.di.MessageID()
				assert.Equal(t, origMsgID, parsedMsgID, "MessageID must survive roundtrip")

				parsedFragNum, err := parsed.FragmentNumber()
				require.NoError(t, err)
				origFragNum, _ := tt.di.FragmentNumber()
				assert.Equal(t, origFragNum, parsedFragNum, "Fragment number must survive roundtrip")

				parsedIsLast, err := parsed.LastFollowOnFragment()
				require.NoError(t, err)
				origIsLast, _ := tt.di.LastFollowOnFragment()
				assert.Equal(t, origIsLast, parsedIsLast, "Last fragment flag must survive roundtrip")
			}

			if fragType == FIRST_FRAGMENT {
				parsedDT, err := parsed.DeliveryType()
				require.NoError(t, err)
				origDT, _ := tt.di.DeliveryType()
				assert.Equal(t, origDT, parsedDT, "Delivery type must survive roundtrip")
			}
		})
	}
}

func TestTunnelMessages_DeliveryInstructions_TunnelIDPresence(t *testing.T) {
	// TunnelID is only present for DT_TUNNEL
	tunnelDI := NewTunnelDeliveryInstructions(9999, [32]byte{0xFF}, 50)
	tid, err := tunnelDI.TunnelID()
	require.NoError(t, err)
	assert.Equal(t, uint32(9999), tid)

	localDI := NewLocalDeliveryInstructions(50)
	_, err = localDI.TunnelID()
	assert.Error(t, err, "TunnelID must not be available for DT_LOCAL")
}

func TestTunnelMessages_DeliveryInstructions_HashPresence(t *testing.T) {
	// Hash present for DT_TUNNEL and DT_ROUTER, not for DT_LOCAL
	expectedHash := common.Hash{0x01, 0x02, 0x03}

	tunnelDI := NewTunnelDeliveryInstructions(1, [32]byte(expectedHash), 50)
	hash, err := tunnelDI.Hash()
	require.NoError(t, err)
	assert.Equal(t, expectedHash, hash, "DT_TUNNEL must include gateway hash")

	routerDI := NewRouterDeliveryInstructions([32]byte(expectedHash), 50)
	hash, err = routerDI.Hash()
	require.NoError(t, err)
	assert.Equal(t, expectedHash, hash, "DT_ROUTER must include router hash")

	localDI := NewLocalDeliveryInstructions(50)
	_, err = localDI.Hash()
	assert.Error(t, err, "DT_LOCAL must not have hash")
}

// --- Fragment Reassembly ---

func TestTunnelMessages_FragmentReassembly_UnfragmentedMessageDelivered(t *testing.T) {
	// A non-fragmented message should be delivered directly
	var delivered []byte
	handler := func(msgBytes []byte) error {
		delivered = make([]byte, len(msgBytes))
		copy(delivered, msgBytes)
		return nil
	}

	enc := &mockPassthroughEncryptor{}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	// Build a valid tunnel message with unfragmented LOCAL delivery
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	tunnelMsg := buildTestTunnelMessage(t, DT_LOCAL, false, 0, 0, [32]byte{}, payload)

	err = ep.Receive(tunnelMsg)
	require.NoError(t, err)
	assert.Equal(t, payload, delivered, "Unfragmented message must be delivered intact")
}

func TestTunnelMessages_FragmentReassembly_TwoFragmentsReassembled(t *testing.T) {
	// Fragment a message into 2 parts, deliver via endpoint, verify reassembly
	var delivered []byte
	handler := func(msgBytes []byte) error {
		delivered = make([]byte, len(msgBytes))
		copy(delivered, msgBytes)
		return nil
	}

	enc := &mockPassthroughEncryptor{}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	msgID := uint32(0x12345678)
	part1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	part2 := []byte{0x06, 0x07, 0x08, 0x09, 0x0A}

	// First fragment
	firstMsg := buildTestTunnelMessage(t, DT_LOCAL, true, msgID, 0, [32]byte{}, part1)
	err = ep.Receive(firstMsg)
	require.NoError(t, err)
	assert.Nil(t, delivered, "Message should not be delivered after first fragment only")

	// Follow-on fragment (last)
	followOnMsg := buildTestFollowOnTunnelMessage(t, msgID, 1, true, part2)
	err = ep.Receive(followOnMsg)
	require.NoError(t, err)
	require.NotNil(t, delivered, "Message must be delivered after all fragments received")

	expected := append(part1, part2...)
	assert.Equal(t, expected, delivered, "Reassembled message must contain all fragments in order")
}

func TestTunnelMessages_FragmentReassembly_ThreeFragmentsReassembled(t *testing.T) {
	var delivered []byte
	handler := func(msgBytes []byte) error {
		delivered = make([]byte, len(msgBytes))
		copy(delivered, msgBytes)
		return nil
	}

	enc := &mockPassthroughEncryptor{}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	msgID := uint32(0xAABBCCDD)
	part1 := []byte{0x10, 0x20, 0x30}
	part2 := []byte{0x40, 0x50, 0x60}
	part3 := []byte{0x70, 0x80, 0x90}

	// Send first fragment
	msg1 := buildTestTunnelMessage(t, DT_LOCAL, true, msgID, 0, [32]byte{}, part1)
	require.NoError(t, ep.Receive(msg1))
	assert.Nil(t, delivered)

	// Send follow-on fragment 1 (not last)
	msg2 := buildTestFollowOnTunnelMessage(t, msgID, 1, false, part2)
	require.NoError(t, ep.Receive(msg2))
	assert.Nil(t, delivered)

	// Send follow-on fragment 2 (last)
	msg3 := buildTestFollowOnTunnelMessage(t, msgID, 2, true, part3)
	require.NoError(t, ep.Receive(msg3))
	require.NotNil(t, delivered)

	expected := append(append(part1, part2...), part3...)
	assert.Equal(t, expected, delivered, "3 fragments must reassemble in order")
}

func TestTunnelMessages_FragmentReassembly_OutOfOrderFragments(t *testing.T) {
	// Fragments arriving out of order should still reassemble correctly
	var delivered []byte
	handler := func(msgBytes []byte) error {
		delivered = make([]byte, len(msgBytes))
		copy(delivered, msgBytes)
		return nil
	}

	enc := &mockPassthroughEncryptor{}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	msgID := uint32(0x11223344)
	part1 := []byte{0xAA}
	part2 := []byte{0xBB}
	part3 := []byte{0xCC}

	// Send follow-on fragment 2 (last) first
	msg3 := buildTestFollowOnTunnelMessage(t, msgID, 2, true, part3)
	require.NoError(t, ep.Receive(msg3))
	assert.Nil(t, delivered)

	// Send first fragment
	msg1 := buildTestTunnelMessage(t, DT_LOCAL, true, msgID, 0, [32]byte{}, part1)
	require.NoError(t, ep.Receive(msg1))
	assert.Nil(t, delivered)

	// Send follow-on fragment 1 (not last)
	msg2 := buildTestFollowOnTunnelMessage(t, msgID, 1, false, part2)
	require.NoError(t, ep.Receive(msg2))
	require.NotNil(t, delivered)

	expected := append(append(part1, part2...), part3...)
	assert.Equal(t, expected, delivered, "Out-of-order fragments must reassemble correctly")
}

func TestTunnelMessages_FragmentReassembly_DuplicateFragmentRejected(t *testing.T) {
	// Duplicate fragments should be detected and rejected
	handler := func(msgBytes []byte) error { return nil }

	enc := &mockPassthroughEncryptor{}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	msgID := uint32(0x55667788)
	part1 := []byte{0x01, 0x02}
	part2 := []byte{0x03, 0x04}
	part3 := []byte{0x05, 0x06}

	// Send first fragment
	msg1 := buildTestTunnelMessage(t, DT_LOCAL, true, msgID, 0, [32]byte{}, part1)
	require.NoError(t, ep.Receive(msg1))

	// Send follow-on fragment 1 (not last)
	msg2 := buildTestFollowOnTunnelMessage(t, msgID, 1, false, part2)
	require.NoError(t, ep.Receive(msg2))

	// Send same follow-on fragment 1 again (duplicate — before message completes)
	msg2dup := buildTestFollowOnTunnelMessage(t, msgID, 1, false, part2)
	err = ep.Receive(msg2dup)
	assert.ErrorIs(t, err, ErrDuplicateFragment, "Duplicate fragment must be rejected")

	// Send last fragment to complete the message
	msg3 := buildTestFollowOnTunnelMessage(t, msgID, 2, true, part3)
	require.NoError(t, ep.Receive(msg3))
}

func TestTunnelMessages_FragmentReassembly_MaxFragments63(t *testing.T) {
	// Fragment number is 6-bit field (1-63), so max follow-on fragments = 63
	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 63,
		lastFragment:   true,
		messageID:      1,
		fragmentSize:   5,
	}
	data, err := di.Bytes()
	require.NoError(t, err)

	parsed, err := NewDeliveryInstructions(data)
	require.NoError(t, err)

	fragNum, err := parsed.FragmentNumber()
	require.NoError(t, err)
	assert.Equal(t, 63, fragNum, "Maximum fragment number must be 63")
}

func TestTunnelMessages_FragmentReassembly_MaxConcurrentAssemblies(t *testing.T) {
	// Verify the constant for maximum concurrent assemblies
	assert.Equal(t, 5000, maxConcurrentAssemblies,
		"maxConcurrentAssemblies must be 5000 to prevent memory exhaustion")
}

func TestTunnelMessages_FragmentReassembly_StaleFragmentTimeout(t *testing.T) {
	// Default fragment timeout is 60 seconds
	enc := &mockPassthroughEncryptor{}
	handler := func(msgBytes []byte) error { return nil }
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	assert.Equal(t, 60*1000*1000*1000, int(ep.fragmentTimeout.Nanoseconds()),
		"Default fragment timeout must be 60 seconds")
}

// --- Message ID ---

func TestTunnelMessages_MessageID_Is4Bytes(t *testing.T) {
	// Message ID is 4 bytes in both first-fragment and follow-on delivery instructions
	// First fragment: message ID present when fragmented=true
	di := NewLocalDeliveryInstructions(100)
	di.fragmented = true
	di.messageID = 0xDEADBEEF
	data, err := di.Bytes()
	require.NoError(t, err)

	// LOCAL fragmented: flag(1) + messageID(4) + size(2) = 7
	assert.Equal(t, 7, len(data), "LOCAL fragmented must be 7 bytes (includes 4-byte messageID)")

	// Verify messageID is in the data at correct position
	msgIDBytes := data[1:5] // after flag byte
	extractedMsgID := binary.BigEndian.Uint32(msgIDBytes)
	assert.Equal(t, uint32(0xDEADBEEF), extractedMsgID, "Message ID must be stored as 4-byte big-endian")
}

func TestTunnelMessages_MessageID_FollowOnFragment4Bytes(t *testing.T) {
	// Follow-on fragment message ID at bytes [1:5]
	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 2,
		lastFragment:   false,
		messageID:      0xCAFEBABE,
		fragmentSize:   100,
	}
	data, err := di.Bytes()
	require.NoError(t, err)

	extractedMsgID := binary.BigEndian.Uint32(data[1:5])
	assert.Equal(t, uint32(0xCAFEBABE), extractedMsgID,
		"Follow-on fragment message ID must be at bytes [1:5] as 4-byte big-endian")
}

func TestTunnelMessages_MessageID_CorrelatesFragments(t *testing.T) {
	// Verify that message ID correctly correlates first and follow-on fragments
	msgID := uint32(0x99887766)

	firstDI := NewLocalDeliveryInstructions(50)
	firstDI.fragmented = true
	firstDI.messageID = msgID

	followDI := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 1,
		lastFragment:   true,
		messageID:      msgID,
		fragmentSize:   50,
	}

	firstID, err := firstDI.MessageID()
	require.NoError(t, err)

	followID, err := followDI.MessageID()
	require.NoError(t, err)

	assert.Equal(t, firstID, followID,
		"First fragment and follow-on fragment must share the same message ID for correlation")
	assert.Equal(t, msgID, firstID, "Message IDs must match the original value")
}

func TestTunnelMessages_MessageID_NotPresentWhenUnfragmented(t *testing.T) {
	// Unfragmented first fragment must not have a message ID
	di := NewLocalDeliveryInstructions(100)
	_, err := di.MessageID()
	assert.Error(t, err, "Message ID must not be available on unfragmented first fragment")
}

func TestTunnelMessages_MessageID_GatewayUsesMonotonicCounter(t *testing.T) {
	// Gateway uses atomic counter for message IDs during fragmentation
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	// The msgIDSeq is an atomic uint32 counter starting at 0
	// Each call to sendFragmented increments it
	assert.Equal(t, uint32(0), gw.msgIDSeq, "Message ID counter must start at 0")
}

func TestTunnelMessages_MessageID_FragmentSizeField2Bytes(t *testing.T) {
	// Fragment size is 2-byte big-endian uint16
	// For follow-on: at bytes [5:7]
	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: 1,
		lastFragment:   true,
		messageID:      1,
		fragmentSize:   996, // Max valid follow-on fragment size per spec
	}
	data, err := di.Bytes()
	require.NoError(t, err)

	extractedSize := binary.BigEndian.Uint16(data[5:7])
	assert.Equal(t, uint16(996), extractedSize,
		"Fragment size must be at bytes [5:7] as 2-byte big-endian, max 996")
}

// =============================================================================
// Test Helpers
// =============================================================================

// specMockEncryptor is a minimal mock implementing TunnelEncryptor that
// returns input unchanged (for testing message structure without real crypto).
type specMockEncryptor struct{}

func (m *specMockEncryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *specMockEncryptor) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *specMockEncryptor) Type() cryptotunnel.TunnelEncryptionType {
	return cryptotunnel.TunnelEncryptionAES
}

// buildTestTunnelMessage constructs a valid 1028-byte tunnel message for testing.
// Uses passthrough encryption (no actual crypto) so the endpoint can process it directly.
func buildTestTunnelMessage(t *testing.T, deliveryType byte, fragmented bool, msgID uint32, tunnelID uint32, hash [32]byte, payload []byte) []byte {
	t.Helper()

	var di *DeliveryInstructions
	switch deliveryType {
	case DT_TUNNEL:
		di = NewTunnelDeliveryInstructions(tunnelID, hash, uint16(len(payload)))
	case DT_ROUTER:
		di = NewRouterDeliveryInstructions(hash, uint16(len(payload)))
	default:
		di = NewLocalDeliveryInstructions(uint16(len(payload)))
	}

	if fragmented {
		di.fragmented = true
		di.messageID = msgID
	}

	diBytes, err := di.Bytes()
	require.NoError(t, err)

	return assembleTunnelMessage(t, diBytes, payload)
}

// buildTestFollowOnTunnelMessage constructs a follow-on fragment tunnel message for testing.
func buildTestFollowOnTunnelMessage(t *testing.T, msgID uint32, fragNum int, isLast bool, payload []byte) []byte {
	t.Helper()

	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: fragNum,
		lastFragment:   isLast,
		messageID:      msgID,
		fragmentSize:   uint16(len(payload)),
	}

	diBytes, err := di.Bytes()
	require.NoError(t, err)

	return assembleTunnelMessage(t, diBytes, payload)
}

// assembleTunnelMessage creates a valid 1028-byte tunnel message from delivery instructions and payload.
func assembleTunnelMessage(t *testing.T, diBytes []byte, payload []byte) []byte {
	t.Helper()

	msg := make([]byte, 1028)

	// Tunnel ID at [0:4]
	binary.BigEndian.PutUint32(msg[0:4], 1) // dummy tunnel ID

	// IV at [4:20] - use deterministic values for testing
	for i := 4; i < 20; i++ {
		msg[i] = byte(i)
	}

	// Calculate space for padding
	// Layout: tunnelID(4) + IV(16) + checksum(4) + padding(N) + zero(1) + DI + payload
	dataSize := len(diBytes) + len(payload)
	paddingSize := 1028 - 24 - 1 - dataSize
	if paddingSize < 0 {
		t.Fatalf("payload too large for tunnel message: diBytes=%d, payload=%d", len(diBytes), len(payload))
	}

	// Non-zero padding at [24:24+paddingSize]
	for i := 0; i < paddingSize; i++ {
		msg[24+i] = byte(i%254 + 1) // non-zero
	}

	// Zero byte separator
	msg[24+paddingSize] = 0x00

	// Delivery instructions + payload
	offset := 24 + paddingSize + 1
	copy(msg[offset:], diBytes)
	copy(msg[offset+len(diBytes):], payload)

	// Checksum at [20:24] = first 4 bytes of SHA256(data_after_checksum + IV)
	dataAfterChecksum := msg[24:]
	iv := msg[4:20]
	checksumInput := make([]byte, len(dataAfterChecksum)+len(iv))
	copy(checksumInput, dataAfterChecksum)
	copy(checksumInput[len(dataAfterChecksum):], iv)
	h := sha256.Sum256(checksumInput)
	copy(msg[20:24], h[:4])

	return msg
}
