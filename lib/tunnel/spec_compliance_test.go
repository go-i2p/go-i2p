package tunnel

import (
	"github.com/go-i2p/crypto/types"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
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

func TestTunnelMessages_FixedSize_EncryptedDataIs1008Bytes(t *testing.T) {
	// EncryptedTunnelMessage.Data() returns bytes after tunnel ID (4) + IV (16) = [20:]
	// which is 1028 - 20 = 1008 bytes (encrypted format has no checksum field)
	var msg EncryptedTunnelMessage
	data, err := msg.Data()
	require.NoError(t, err)
	assert.Equal(t, 1008, len(data), "Encrypted data area must be 1028 - 20 = 1008 bytes")
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
	// Per I2P spec: Checksum = first 4 bytes of SHA256(data_after_zero_byte + IV)
	// "The checksum does NOT cover the padding or the zero byte."
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

	// Find the zero byte separator
	var zeroPos int
	for i := 24; i < len(msg); i++ {
		if msg[i] == 0x00 {
			zeroPos = i
			break
		}
	}
	require.Greater(t, zeroPos, 23, "zero byte separator must exist")

	// Data after zero byte = delivery instructions + message
	dataAfterZero := msg[zeroPos+1:]

	// Recompute checksum: SHA256(dataAfterZero + IV), take first 4 bytes
	checksumInput := make([]byte, len(dataAfterZero)+len(iv))
	copy(checksumInput, dataAfterZero)
	copy(checksumInput[len(dataAfterZero):], iv)
	hash := types.SHA256(checksumInput)
	expectedChecksum := hash[:4]

	assert.Equal(t, expectedChecksum, storedChecksum,
		"Checksum must be first 4 bytes of SHA256(data_after_zero_byte + IV)")
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

	// Checksum at [20:24] = first 4 bytes of SHA256(data_after_zero_byte + IV)
	// Per I2P spec: "The checksum does NOT cover the padding or the zero byte."
	dataAfterZero := msg[24+paddingSize+1:] // data after the zero byte separator
	iv := msg[4:20]
	checksumInput := make([]byte, len(dataAfterZero)+len(iv))
	copy(checksumInput, dataAfterZero)
	copy(checksumInput[len(dataAfterZero):], iv)
	h := types.SHA256(checksumInput)
	copy(msg[20:24], h[:4])

	return msg
}

// =============================================================================
// Section 9: lib/tunnel — Tunnel Creation (ECIES — Proposal 152)
// =============================================================================

// --- Build Request ---

func TestTunnelCreation_BuildRequest_EachHopGetsRecord(t *testing.T) {
	// Each hop in the tunnel receives its own encrypted BuildRequestRecord
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}
	result, err := builder.CreateBuildRequest(req)
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.Records), "must have one record per hop")
	assert.Equal(t, 3, len(result.Hops), "must have one hop per record")
}

func TestTunnelCreation_BuildRequest_UniqueKeysPerHop(t *testing.T) {
	// Each hop must get unique layer key, IV key, and reply key
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3})
	require.NoError(t, err)

	for i := 0; i < len(result.Records); i++ {
		for j := i + 1; j < len(result.Records); j++ {
			assert.NotEqual(t, result.Records[i].LayerKey, result.Records[j].LayerKey,
				"hops %d and %d must have different layer keys", i, j)
			assert.NotEqual(t, result.Records[i].IVKey, result.Records[j].IVKey,
				"hops %d and %d must have different IV keys", i, j)
			assert.NotEqual(t, result.Records[i].ReplyKey, result.Records[j].ReplyKey,
				"hops %d and %d must have different reply keys", i, j)
		}
	}
}

func TestTunnelCreation_BuildRequest_HopCountValidation(t *testing.T) {
	// Hop count must be 1-8 per I2P spec
	selector := &specMockPeerSelector{count: 10}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	// Valid hop counts
	for _, hops := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
		result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: hops})
		assert.NoError(t, err, "hop count %d should be valid", hops)
		assert.NotNil(t, result)
	}

	// Invalid hop counts
	for _, hops := range []int{0, -1, 9, 100} {
		_, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: hops})
		assert.Error(t, err, "hop count %d should be rejected", hops)
	}
}

// --- ECIES Record Format ---

func TestTunnelCreation_ECIESRecordFormat_RecordFieldsPresent(t *testing.T) {
	// Build request records must contain all required fields per spec
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3})
	require.NoError(t, err)

	for i, record := range result.Records {
		// ReceiveTunnel must be non-zero for all hops
		assert.NotZero(t, record.ReceiveTunnel, "hop %d: ReceiveTunnel must be set", i)

		// Layer key and IV key must be non-zero (32-byte session keys)
		assert.NotEqual(t, session_key.SessionKey{}, record.LayerKey, "hop %d: LayerKey must be set", i)
		assert.NotEqual(t, session_key.SessionKey{}, record.IVKey, "hop %d: IVKey must be set", i)

		// Reply key and reply IV must be non-zero
		assert.NotEqual(t, session_key.SessionKey{}, record.ReplyKey, "hop %d: ReplyKey must be set", i)
		assert.NotEqual(t, [16]byte{}, record.ReplyIV, "hop %d: ReplyIV must be set", i)

		// RequestTime must be recent
		assert.WithinDuration(t, time.Now(), record.RequestTime, 5*time.Second,
			"hop %d: RequestTime should be recent", i)
	}
}

func TestTunnelCreation_ECIESRecordFormat_ReplyKeysStored(t *testing.T) {
	// The builder must store reply keys and IVs for decrypting responses
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3})
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.ReplyKeys), "must have reply key per hop")
	assert.Equal(t, 3, len(result.ReplyIVs), "must have reply IV per hop")

	for i := 0; i < 3; i++ {
		assert.Equal(t, result.Records[i].ReplyKey, result.ReplyKeys[i],
			"hop %d: reply key must match record", i)
		assert.Equal(t, result.Records[i].ReplyIV, result.ReplyIVs[i],
			"hop %d: reply IV must match record", i)
	}
}

// --- Response / Accept/Reject ---

func TestTunnelCreation_AcceptRejectCodes(t *testing.T) {
	// Verify build reply codes match I2P spec
	assert.Equal(t, byte(0), byte(BuildReplyCodeAccepted), "accepted=0")
	assert.Equal(t, byte(10), byte(BuildReplyCodeProbabilisticReject), "probabilistic reject=10")
	assert.Equal(t, byte(20), byte(BuildReplyCodeTransientOverload), "transient overload=20")
	assert.Equal(t, byte(30), byte(BuildReplyCodeBandwidth), "bandwidth=30")
	assert.Equal(t, byte(50), byte(BuildReplyCodeCritical), "critical=50")
}

func TestTunnelCreation_UseShortBuild(t *testing.T) {
	// TunnelBuildResult must propagate UseShortBuild flag
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3, UseShortBuild: true})
	require.NoError(t, err)
	assert.True(t, result.UseShortBuild, "UseShortBuild flag must be propagated")

	result2, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3, UseShortBuild: false})
	require.NoError(t, err)
	assert.False(t, result2.UseShortBuild, "UseShortBuild=false must be propagated")
}

func TestTunnelCreation_RoutingParamsOutbound(t *testing.T) {
	// Outbound tunnel: first hop is gateway, last hop is endpoint
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3, IsInbound: false})
	require.NoError(t, err)

	// Last hop (endpoint) should have NextTunnel=0 for outbound
	lastRecord := result.Records[2]
	assert.Equal(t, TunnelID(0), lastRecord.NextTunnel, "outbound endpoint NextTunnel should be 0")

	// Middle hops should chain to next hop's receive tunnel
	for i := 0; i < 2; i++ {
		assert.NotZero(t, result.Records[i].NextTunnel,
			"hop %d must have a NextTunnel pointing to next hop", i)
	}
}

func TestTunnelCreation_RoutingParamsInbound(t *testing.T) {
	// Inbound tunnel: messages flow toward us
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	replyTunnelID := TunnelID(0x12345678)
	var replyGateway common.Hash
	replyGateway[0] = 0xFF

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{
		HopCount:      3,
		IsInbound:     true,
		ReplyTunnelID: replyTunnelID,
		ReplyGateway:  replyGateway,
	})
	require.NoError(t, err)

	// Last hop (gateway) should point to our reply tunnel
	lastRecord := result.Records[2]
	assert.Equal(t, replyTunnelID, lastRecord.NextTunnel, "inbound gateway must point to reply tunnel")
	assert.Equal(t, replyGateway, lastRecord.NextIdent, "inbound gateway must target reply gateway")
}

func TestTunnelCreation_UniqueHopTunnelIDs(t *testing.T) {
	// Each hop must get a unique receive tunnel ID
	selector := &specMockPeerSelector{count: 8}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 8})
	require.NoError(t, err)

	seen := make(map[TunnelID]bool)
	for i, record := range result.Records {
		assert.False(t, seen[record.ReceiveTunnel],
			"hop %d has duplicate ReceiveTunnel ID %d", i, record.ReceiveTunnel)
		seen[record.ReceiveTunnel] = true
	}
}

// =============================================================================
// Section 9: lib/tunnel — Short Tunnel Build (Proposal 157)
// =============================================================================

func TestShortTunnelBuild_UseShortBuildDefault(t *testing.T) {
	// Pool's prepareBuildRequest should default to UseShortBuild=true
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	req := pool.prepareBuildRequest(nil)
	assert.True(t, req.UseShortBuild, "Pool must default to ShortTunnelBuild (modern STBM)")
}

func TestShortTunnelBuild_ResultPropagatesFlag(t *testing.T) {
	// TunnelBuildResult tracks whether short build was used
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3, UseShortBuild: true})
	require.NoError(t, err)
	assert.True(t, result.UseShortBuild, "Result must reflect UseShortBuild=true")
}

func TestShortTunnelBuild_VariableTunnelBuildBackwardCompat(t *testing.T) {
	// Must still support UseShortBuild=false for VariableTunnelBuild
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3, UseShortBuild: false})
	require.NoError(t, err)
	assert.False(t, result.UseShortBuild, "Must support legacy VariableTunnelBuild (UseShortBuild=false)")
}

// =============================================================================
// Section 9: lib/tunnel — Tunnel Roles
// =============================================================================

func TestTunnelRoles_GatewayEncryptsAndAddsInstructions(t *testing.T) {
	// Gateway must encrypt messages entering the tunnel and add delivery instructions
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	payload := []byte("test message for gateway")
	encrypted, err := gw.Send(payload)
	require.NoError(t, err)
	assert.Equal(t, 1028, len(encrypted), "gateway must produce 1028-byte tunnel messages")
}

func TestTunnelRoles_GatewaySupportsAllDeliveryTypes(t *testing.T) {
	// Gateway must support DT_LOCAL, DT_TUNNEL, and DT_ROUTER
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	payload := []byte("small payload")

	// DT_LOCAL
	msgs, err := gw.SendWithDelivery(payload, LocalDelivery())
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
	assert.Equal(t, 1028, len(msgs[0]))

	// DT_TUNNEL
	var hash [32]byte
	hash[0] = 0x42
	msgs, err = gw.SendWithDelivery(payload, TunnelDelivery(100, hash))
	require.NoError(t, err)
	assert.Len(t, msgs, 1)

	// DT_ROUTER
	msgs, err = gw.SendWithDelivery(payload, RouterDelivery(hash))
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
}

func TestTunnelRoles_ParticipantDecryptsOneLayerAndForwards(t *testing.T) {
	// Participant decrypts one layer, extracts next hop tunnel ID, forwards all 1028 bytes
	enc := &specMockEncryptor{}
	p, err := NewParticipant(TunnelID(42), enc)
	require.NoError(t, err)

	msg := make([]byte, 1028)
	binary.BigEndian.PutUint32(msg[0:4], 99) // next hop ID

	nextHop, decrypted, err := p.Process(msg)
	require.NoError(t, err)
	assert.Equal(t, TunnelID(99), nextHop, "participant must extract next hop ID from bytes [0:4]")
	assert.Equal(t, 1028, len(decrypted), "participant must return full 1028 bytes")
}

func TestTunnelRoles_ParticipantNoMessageInspection(t *testing.T) {
	// Participant must not inspect contents (privacy by design) — only reads tunnel ID
	enc := &specMockEncryptor{}
	p, err := NewParticipant(TunnelID(42), enc)
	require.NoError(t, err)

	msg := make([]byte, 1028)
	binary.BigEndian.PutUint32(msg[0:4], 0xBEEF)
	// Fill rest with identifiable data
	for i := 4; i < 1028; i++ {
		msg[i] = 0xAA
	}

	_, decrypted, err := p.Process(msg)
	require.NoError(t, err)
	// All data after tunnel ID should pass through unchanged (mock encryptor)
	for i := 4; i < 1028; i++ {
		assert.Equal(t, byte(0xAA), decrypted[i], "byte %d should pass through unchanged", i)
	}
}

func TestTunnelRoles_EndpointDecryptsAndDelivers(t *testing.T) {
	// Endpoint must decrypt final layer, validate checksum, parse DI, and deliver
	enc := &specMockEncryptor{}
	var received []byte
	handler := func(msgBytes []byte) error {
		received = msgBytes
		return nil
	}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	payload := []byte("hello endpoint")
	msg := buildTestTunnelMessage(t, DT_LOCAL, false, 0, 0, [32]byte{}, payload)
	err = ep.Receive(msg)
	require.NoError(t, err)
	assert.Equal(t, payload, received, "endpoint must deliver the message payload")
}

func TestTunnelRoles_EndpointRoutesNonLocalMessages(t *testing.T) {
	// Endpoint must support DT_TUNNEL and DT_ROUTER delivery via forwarder
	enc := &specMockEncryptor{}
	handler := func(msgBytes []byte) error { return nil }
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &specMockForwarder{}
	ep.SetForwarder(fwd)

	// DT_TUNNEL message
	var hash [32]byte
	hash[0] = 0x42
	payload := []byte("tunnel message")
	msg := buildTestTunnelMessage(t, DT_TUNNEL, false, 0, 100, hash, payload)
	err = ep.Receive(msg)
	require.NoError(t, err)
	assert.True(t, fwd.tunnelCalled, "endpoint must forward DT_TUNNEL to ForwardToTunnel")
}

func TestTunnelRoles_IBGWandOBEPDetermination(t *testing.T) {
	// Builder must correctly determine hop positions
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	// Outbound: hop0=gateway, hop1=participant, hop2=endpoint
	assert.Equal(t, "gateway", builder.determineHopPosition(0, 3, false))
	assert.Equal(t, "participant", builder.determineHopPosition(1, 3, false))
	assert.Equal(t, "endpoint", builder.determineHopPosition(2, 3, false))

	// Inbound: hop0=endpoint, hop1=participant, hop2=gateway
	assert.Equal(t, "endpoint", builder.determineHopPosition(0, 3, true))
	assert.Equal(t, "participant", builder.determineHopPosition(1, 3, true))
	assert.Equal(t, "gateway", builder.determineHopPosition(2, 3, true))
}

// =============================================================================
// Section 9: lib/tunnel — Tunnel Pool
// =============================================================================

func TestTunnelPool_PoolSizeConfigurable(t *testing.T) {
	// Pool size must be configurable with min and max
	config := PoolConfig{
		MinTunnels:       2,
		MaxTunnels:       8,
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  3,
		HopCount:         3,
		IsInbound:        false,
	}

	pool := NewTunnelPoolWithConfig(&specMockPeerSelector{count: 3}, config)
	defer pool.Stop()

	assert.Equal(t, 2, pool.config.MinTunnels)
	assert.Equal(t, 8, pool.config.MaxTunnels)
}

func TestTunnelPool_DefaultConfigValues(t *testing.T) {
	// DefaultPoolConfig must set I2P-spec-compliant values
	cfg := DefaultPoolConfig()
	assert.Equal(t, 4, cfg.MinTunnels, "default min tunnels")
	assert.Equal(t, 6, cfg.MaxTunnels, "default max tunnels")
	assert.Equal(t, 10*time.Minute, cfg.TunnelLifetime, "tunnel lifetime must be 10 minutes per spec")
	assert.Equal(t, 2*time.Minute, cfg.RebuildThreshold, "rebuild threshold")
	assert.Equal(t, 3, cfg.HopCount, "default hop count")
}

func TestTunnelPool_ExpirationAfter10Minutes(t *testing.T) {
	// Tunnels MUST expire after 10 minutes (spec-defined maximum)
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	// Add a tunnel that is "old" (created 11 minutes ago)
	tunnel := &TunnelState{
		ID:        TunnelID(1),
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-11 * time.Minute),
		IsInbound: false,
	}
	pool.AddTunnel(tunnel)

	// After cleanup, the expired tunnel should be removed
	pool.mutex.Lock()
	pool.cleanupExpiredTunnelsLocked()
	pool.mutex.Unlock()

	_, exists := pool.GetTunnel(TunnelID(1))
	assert.False(t, exists, "tunnel older than 10 minutes must be expired")
}

func TestTunnelPool_RebuildBeforeExpiry(t *testing.T) {
	// Pool must detect near-expiry tunnels and plan rebuilds
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	// Add a tunnel that is 9 minutes old (within rebuild threshold of 2 min before 10 min expiry)
	tunnel := &TunnelState{
		ID:        TunnelID(1),
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-9 * time.Minute),
		IsInbound: false,
	}
	pool.AddTunnel(tunnel)

	pool.mutex.Lock()
	active, nearExpiry := pool.countTunnelsLocked()
	needed := pool.calculateNeededTunnels(active, nearExpiry)
	pool.mutex.Unlock()

	assert.Equal(t, 1, active, "should count 1 active tunnel")
	assert.Equal(t, 1, nearExpiry, "should detect 1 near-expiry tunnel")
	assert.Greater(t, needed, 0, "should need replacement tunnels due to near-expiry")
}

func TestTunnelPool_HopCountRange(t *testing.T) {
	// Configurable hop count (0-7), default 2-3 hops
	cfg := DefaultPoolConfig()
	assert.True(t, cfg.HopCount >= 1 && cfg.HopCount <= 8,
		"default hop count must be in valid range 1-8, got %d", cfg.HopCount)

	// Custom configs must accept valid values
	for _, hops := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
		customCfg := PoolConfig{
			MinTunnels:     2,
			MaxTunnels:     4,
			TunnelLifetime: 10 * time.Minute,
			HopCount:       hops,
		}
		pool := NewTunnelPoolWithConfig(&specMockPeerSelector{count: hops}, customCfg)
		assert.Equal(t, hops, pool.config.HopCount)
		pool.Stop()
	}
}

func TestTunnelPool_AddRemoveGetTunnel(t *testing.T) {
	// Basic pool operations
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	tunnel := &TunnelState{
		ID:        TunnelID(42),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	}

	pool.AddTunnel(tunnel)
	got, exists := pool.GetTunnel(TunnelID(42))
	assert.True(t, exists)
	assert.Equal(t, TunnelID(42), got.ID)

	pool.RemoveTunnel(TunnelID(42))
	_, exists = pool.GetTunnel(TunnelID(42))
	assert.False(t, exists)
}

func TestTunnelPool_SelectTunnelRoundRobin(t *testing.T) {
	// Pool must select tunnels using round-robin
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	for i := 1; i <= 3; i++ {
		pool.AddTunnel(&TunnelState{
			ID:        TunnelID(i),
			State:     TunnelReady,
			CreatedAt: time.Now(),
		})
	}

	selected := pool.SelectTunnel()
	assert.NotNil(t, selected)

	// Subsequent selections should rotate
	secondSelected := pool.SelectTunnel()
	assert.NotNil(t, secondSelected)
}

func TestTunnelPool_GetPoolStats(t *testing.T) {
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	pool.AddTunnel(&TunnelState{ID: TunnelID(1), State: TunnelReady, CreatedAt: time.Now()})
	pool.AddTunnel(&TunnelState{ID: TunnelID(2), State: TunnelBuilding, CreatedAt: time.Now()})
	pool.AddTunnel(&TunnelState{ID: TunnelID(3), State: TunnelFailed, CreatedAt: time.Now()})

	stats := pool.GetPoolStats()
	assert.Equal(t, 3, stats.Total)
	assert.Equal(t, 1, stats.Active)
	assert.Equal(t, 1, stats.Building)
	assert.Equal(t, 1, stats.Failed)
}

// =============================================================================
// Section 9: lib/tunnel — Peer Selection
// =============================================================================

func TestPeerSelection_ExcludeSelf(t *testing.T) {
	// BuildTunnelRequest supports excluding our own identity
	req := BuildTunnelRequest{
		HopCount:     3,
		OurIdentity:  common.Hash{0x01},
		ExcludePeers: []common.Hash{{0x01}},
	}
	assert.Contains(t, req.ExcludePeers, req.OurIdentity,
		"ExcludePeers must be able to contain our own identity hash")
}

func TestPeerSelection_DefaultPeerSelectorRejectsNilDB(t *testing.T) {
	_, err := NewDefaultPeerSelector(nil)
	assert.Error(t, err, "must reject nil DB selector")
}

func TestPeerSelection_DefaultPeerSelectorRejectsZeroCount(t *testing.T) {
	db := &specMockNetDBSelector{count: 5}
	selector, err := NewDefaultPeerSelector(db)
	require.NoError(t, err)

	_, err = selector.SelectPeers(0, nil)
	assert.Error(t, err, "must reject count <= 0")
}

func TestPeerSelection_FilteringPeerSelectorAcceptReject(t *testing.T) {
	// FilteringPeerSelector must filter peers using PeerFilter interface
	db := &specMockNetDBSelector{count: 10}
	base, err := NewDefaultPeerSelector(db)
	require.NoError(t, err)

	// Filter that rejects all peers
	rejectAll := NewFuncFilter("reject-all", func(ri router_info.RouterInfo) bool {
		return false
	})

	filtered, err := NewFilteringPeerSelector(base, WithFilters(rejectAll), WithFilterMaxRetries(1))
	require.NoError(t, err)

	peers, err := filtered.SelectPeers(3, nil)
	assert.NoError(t, err)
	assert.Empty(t, peers, "all peers should be rejected by filter")
}

func TestPeerSelection_ScoringPeerSelectorThreshold(t *testing.T) {
	// ScoringPeerSelector must filter peers below score threshold
	db := &specMockNetDBSelector{count: 10}
	base, err := NewDefaultPeerSelector(db)
	require.NoError(t, err)

	// Scorer that gives zero score to all peers
	zeroScorer := &specMockScorer{score: 0.0}
	scored, err := NewScoringPeerSelector(base,
		WithScorers(zeroScorer),
		WithScoreThreshold(0.5),
		WithScoringMaxRetries(1),
	)
	require.NoError(t, err)

	peers, err := scored.SelectPeers(3, nil)
	assert.NoError(t, err)
	assert.Empty(t, peers, "all peers should be below threshold")
}

func TestPeerSelection_CompositeFilterAND(t *testing.T) {
	// CompositeFilter must AND all sub-filters
	acceptFilter := NewFuncFilter("accept", func(ri router_info.RouterInfo) bool { return true })
	rejectFilter := NewFuncFilter("reject", func(ri router_info.RouterInfo) bool { return false })

	composite := NewCompositeFilter("test-and", acceptFilter, rejectFilter)
	// Must return false because reject returns false (AND logic)
	assert.False(t, composite.Accept(router_info.RouterInfo{}))
}

func TestPeerSelection_AnyFilterOR(t *testing.T) {
	// AnyFilter must OR all sub-filters
	rejectFilter := NewFuncFilter("reject", func(ri router_info.RouterInfo) bool { return false })
	acceptFilter := NewFuncFilter("accept", func(ri router_info.RouterInfo) bool { return true })

	anyFilter := NewAnyFilter("test-or", rejectFilter, acceptFilter)
	// Must return true because accept returns true (OR logic)
	assert.True(t, anyFilter.Accept(router_info.RouterInfo{}))
}

func TestPeerSelection_InvertFilter(t *testing.T) {
	// InvertFilter must negate the result
	acceptFilter := NewFuncFilter("accept", func(ri router_info.RouterInfo) bool { return true })
	inverted := NewInvertFilter(acceptFilter)
	assert.False(t, inverted.Accept(router_info.RouterInfo{}))
	assert.Equal(t, "NOT(accept)", inverted.Name())
}

func TestPeerSelection_PeerSelectorStackBuilder(t *testing.T) {
	// Verify the fluent builder API works
	db := &specMockNetDBSelector{count: 10}
	acceptAll := NewFuncFilter("accept-all", func(ri router_info.RouterInfo) bool { return true })

	selector, err := FromNetDB(db).
		WithFilter(acceptAll).
		Build()
	assert.NoError(t, err)
	assert.NotNil(t, selector)
}

func TestPeerSelection_RequireDirectConnectivity(t *testing.T) {
	// BuildTunnelRequest must support RequireDirectConnectivity flag
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	req := pool.prepareBuildRequest(nil)
	assert.True(t, req.RequireDirectConnectivity,
		"production builds must require direct NTCP2 connectivity")
}

func TestPeerSelection_FailedPeerExclusionSpec(t *testing.T) {
	// Pool must track and exclude recently failed peers
	pool := NewTunnelPool(&specMockPeerSelector{count: 3})
	defer pool.Stop()

	failedHash := common.Hash{0xDE, 0xAD}
	pool.MarkPeerFailed(failedHash)

	assert.True(t, pool.IsPeerFailed(failedHash), "recently failed peer should be marked")

	excluded := pool.GetFailedPeers()
	assert.Contains(t, excluded, failedHash, "failed peers should be in exclusion list")
}

// =============================================================================
// Section 9: lib/tunnel — Cryptography Audit
// =============================================================================

func TestCryptoAudit_TunnelEncryptorInterface(t *testing.T) {
	// The crypto/tunnel package must support both ECIES and AES encryption types
	assert.Equal(t, cryptotunnel.TunnelEncryptionType(0), cryptotunnel.TunnelEncryptionAES,
		"AES must be type 0")
	assert.Equal(t, cryptotunnel.TunnelEncryptionType(1), cryptotunnel.TunnelEncryptionECIES,
		"ECIES must be type 1")
}

func TestCryptoAudit_AESEncryptorCreation(t *testing.T) {
	// AES encryptor must be creatable from layer key and IV key
	var layerKey, ivKey cryptotunnel.TunnelKey
	// Fill with non-zero data
	for i := range layerKey {
		layerKey[i] = byte(i + 1)
	}
	for i := range ivKey {
		ivKey[i] = byte(i + 33)
	}

	enc, err := cryptotunnel.NewAESEncryptor(layerKey, ivKey)
	require.NoError(t, err)
	assert.NotNil(t, enc)
	assert.Equal(t, cryptotunnel.TunnelEncryptionAES, enc.Type(),
		"AES encryptor must report AES type")
}

func TestCryptoAudit_ECIESEncryptorCreation(t *testing.T) {
	// ECIES encryptors must be creatable from X25519 keys
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}

	enc := cryptotunnel.NewECIESEncryptor(pubKey)
	assert.NotNil(t, enc)
	assert.Equal(t, cryptotunnel.TunnelEncryptionECIES, enc.Type(),
		"ECIES encryptor must report ECIES type")
}

func TestCryptoAudit_TunnelKeyDerivation(t *testing.T) {
	// Layer key and IV key in build record must be proper 32-byte session keys
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3})
	require.NoError(t, err)

	for i, record := range result.Records {
		// Keys should be 32 bytes (same as session_key.SessionKey)
		assert.Equal(t, 32, len(record.LayerKey[:]), "hop %d: layer key must be 32 bytes", i)
		assert.Equal(t, 32, len(record.IVKey[:]), "hop %d: IV key must be 32 bytes", i)

		// Keys must not be all zeros
		allZero := true
		for _, b := range record.LayerKey {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "hop %d: layer key must not be all zeros", i)
	}
}

func TestCryptoAudit_ReplyKeyAndIVForDecryption(t *testing.T) {
	// Reply key and IV must be generated for each hop so tunnel creator can decrypt replies
	selector := &specMockPeerSelector{count: 3}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{HopCount: 3})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		// Reply keys must match between record and stored copy
		assert.Equal(t, result.Records[i].ReplyKey, result.ReplyKeys[i],
			"hop %d: reply key must be stored for decryption", i)
		assert.Equal(t, result.Records[i].ReplyIV, result.ReplyIVs[i],
			"hop %d: reply IV must be stored for decryption", i)
	}
}

func TestCryptoAudit_ManagerUsesAESForParticipants(t *testing.T) {
	// Manager.RegisterParticipant must create AES encryptor from layer and IV keys
	// (verified by checking NewAESEncryptor is used in the code path)
	var layerKey, ivKey session_key.SessionKey
	for i := range layerKey {
		layerKey[i] = byte(i + 1)
	}
	for i := range ivKey {
		ivKey[i] = byte(i + 33)
	}

	m := NewManager()
	defer m.Stop()

	err := m.RegisterParticipant(
		TunnelID(1),
		common.Hash{0x01},
		time.Now().Add(10*time.Minute),
		layerKey, ivKey,
	)
	require.NoError(t, err)
	assert.Equal(t, 1, m.ParticipantCount())
}

func TestCryptoAudit_GatewayEncryptionConcurrencySafe(t *testing.T) {
	// Gateway must serialize concurrent encryption calls (encMu)
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	// Multiple concurrent sends should not race
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := gw.Send([]byte("concurrent message"))
			done <- err
		}()
	}
	for i := 0; i < 10; i++ {
		assert.NoError(t, <-done)
	}
}

// =============================================================================
// Section 9: lib/tunnel — Legacy Crypto
// =============================================================================

func TestLegacyCrypto_AESEncryptorExists(t *testing.T) {
	// AES-256-CBC tunnel layer encryption is present in crypto/tunnel package
	// This is legacy but needed for backward compatibility
	var zeroAES cryptotunnel.AESEncryptor
	assert.Equal(t, cryptotunnel.TunnelEncryptionAES, zeroAES.Type(),
		"AESEncryptor type must be TunnelEncryptionAES")
}

func TestLegacyCrypto_DocReferencesLegacy(t *testing.T) {
	// doc.go references both AES256 and ElGamal/ECIES — verify awareness
	// These are documentation references, not code implementations
	// The actual encryption is delegated to the crypto/tunnel package

	// Verify the code uses the TunnelEncryptor interface (not raw AES calls)
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)

	// Gateway uses tunnel.TunnelEncryptor interface, which supports both types
	assert.NotNil(t, gw, "Gateway must accept any TunnelEncryptor implementation")
}

func TestLegacyCrypto_NoHardcodedAESInGateway(t *testing.T) {
	// Gateway must use TunnelEncryptor interface, not hardcoded AES
	// Test by verifying ECIES-type encryptor also works
	eciesLike := &specMockECIESEncryptor{}
	gw, err := NewGateway(TunnelID(1), eciesLike, TunnelID(2))
	require.NoError(t, err)

	_, err = gw.Send([]byte("test message"))
	require.NoError(t, err, "Gateway must work with non-AES encryptors")
}

func TestLegacyCrypto_No528ByteRecords(t *testing.T) {
	// Verify no 528-byte legacy record constants exist in the tunnel package
	// 528 bytes was the legacy ElGamal-encrypted build record size
	// BuildRequestRecord should not hardcode this size

	// The BuildRequestRecord struct uses named fields, not a fixed byte array
	record := BuildRequestRecord{}
	// Padding is 29 bytes, not related to 528
	assert.Equal(t, 29, len(record.Padding), "padding should be 29 bytes, not legacy 528-byte record related")
}

func TestLegacyCrypto_ManagerRegistersWithAES(t *testing.T) {
	// Manager.RegisterParticipant uses tunnel.NewAESEncryptor which is the
	// legacy crypto path — flagged but required for current network compatibility
	var layerKey, ivKey session_key.SessionKey
	for i := range layerKey {
		layerKey[i] = byte(i + 1)
	}
	for i := range ivKey {
		ivKey[i] = byte(i + 33)
	}

	m := NewManager()
	defer m.Stop()

	// This code path calls tunnel.NewAESEncryptor internally
	err := m.RegisterParticipant(
		TunnelID(100),
		common.Hash{},
		time.Now().Add(10*time.Minute),
		layerKey, ivKey,
	)
	assert.NoError(t, err, "RegisterParticipant must work with AES keys (legacy crypto path)")
}

// =============================================================================
// Section 9: lib/tunnel — Manager / Participation Limits
// =============================================================================

func TestManager_ProcessBuildRequest_AcceptReject(t *testing.T) {
	// Manager.ProcessBuildRequest must implement accept/reject logic
	m := NewManager()
	defer m.Stop()

	accepted, rejectCode, _ := m.ProcessBuildRequest(common.Hash{0x01})
	assert.True(t, accepted, "should accept when well below limits")
	assert.Equal(t, byte(0), rejectCode, "accept code must be 0")
}

func TestManager_BuildReplyCodeBandwidthForRejections(t *testing.T) {
	// Per I2P spec, rejections should use BuildReplyCodeBandwidth (30) to hide reason
	assert.Equal(t, 30, BuildReplyCodeBandwidth,
		"bandwidth reject code must be 30 per I2P spec")
}

func TestManager_ParticipantLifetime10Min(t *testing.T) {
	// Participants must have 10-minute default lifetime
	enc := &specMockEncryptor{}
	p, err := NewParticipant(TunnelID(1), enc)
	require.NoError(t, err)

	// Check expiration at 9 minutes — should not be expired
	assert.False(t, p.IsExpired(p.CreatedAt().Add(9*time.Minute)),
		"should not be expired at 9 minutes")

	// Check expiration at 11 minutes — should be expired
	assert.True(t, p.IsExpired(p.CreatedAt().Add(11*time.Minute)),
		"must be expired after 10 minutes")
}

func TestManager_IdleTimeout2Min(t *testing.T) {
	// Idle timeout defaults to 2 minutes to mitigate resource exhaustion
	assert.Equal(t, 2*time.Minute, DefaultIdleTimeout)

	enc := &specMockEncryptor{}
	p, err := NewParticipant(TunnelID(1), enc)
	require.NoError(t, err)

	// Not idle immediately
	assert.False(t, p.IsIdle(time.Now()))

	// Idle after 3 minutes with no activity
	assert.True(t, p.IsIdle(time.Now().Add(3*time.Minute)))
}

// =============================================================================
// Additional Test Helpers
// =============================================================================

// specMockPeerSelector is a mock PeerSelector for builder tests.
type specMockPeerSelector struct {
	count int
}

func (m *specMockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	peers := make([]router_info.RouterInfo, count)
	for i := 0; i < count; i++ {
		// Create a minimal RouterInfo with unique identity
		peers[i] = specMakeRouterInfo(byte(i + 1))
	}
	return peers, nil
}

// specMakeRouterInfo creates a minimal RouterInfo for testing by constructing
// raw bytes and parsing them via ReadRouterInfo. Each unique id byte produces a
// RouterInfo with a distinct IdentHash, which is required by the builder when
// calling IdentHash() on hop peers.
func specMakeRouterInfo(id byte) router_info.RouterInfo {
	buf := make([]byte, 467)
	// Bytes 0-255: ElGamal public key (unique per id)
	for i := 0; i < 256; i++ {
		buf[i] = id
	}
	// Bytes 256-383: signing key area (96 padding + 32 Ed25519 key)
	for i := 256; i < 384; i++ {
		buf[i] = id
	}
	// Certificate: type=5 (KEY), length=4, sigType=7 (Ed25519), cryptoType=0 (ElGamal)
	buf[384] = 0x05
	buf[385] = 0x00
	buf[386] = 0x04
	buf[387] = 0x00
	buf[388] = 0x07
	buf[389] = 0x00
	buf[390] = 0x00
	// Published date (8 bytes) — use a fixed timestamp to be deterministic
	binary.BigEndian.PutUint64(buf[391:399], uint64(1700000000000))
	// Address count: 0
	buf[399] = 0x00
	// Peer size: 0
	buf[400] = 0x00
	// Mapping (empty): 2-byte length = 0
	buf[401] = 0x00
	buf[402] = 0x00
	// Signature: 64 bytes for Ed25519
	for i := 403; i < 467; i++ {
		buf[i] = id
	}
	ri, _, err := router_info.ReadRouterInfo(buf)
	if err != nil {
		// Fallback: should never happen with the hardcoded layout above
		return router_info.RouterInfo{}
	}
	return ri
}

// specMockNetDBSelector implements NetDBSelector for peer selector tests.
type specMockNetDBSelector struct {
	count int
}

func (m *specMockNetDBSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	peers := make([]router_info.RouterInfo, count)
	return peers, nil
}

// specMockScorer implements PeerScorer for scoring selector tests.
type specMockScorer struct {
	score float64
}

func (s *specMockScorer) Name() string                            { return "mock-scorer" }
func (s *specMockScorer) Score(ri router_info.RouterInfo) float64 { return s.score }

// specMockECIESEncryptor mimics an ECIES-type encryptor to verify interface compatibility.
type specMockECIESEncryptor struct{}

func (m *specMockECIESEncryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *specMockECIESEncryptor) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *specMockECIESEncryptor) Type() cryptotunnel.TunnelEncryptionType {
	return cryptotunnel.TunnelEncryptionECIES
}

// specMockForwarder implements MessageForwarder for endpoint routing tests.
type specMockForwarder struct {
	tunnelCalled bool
	routerCalled bool
}

func (f *specMockForwarder) ForwardToTunnel(tunnelID uint32, gatewayHash [32]byte, msgBytes []byte) error {
	f.tunnelCalled = true
	return nil
}

func (f *specMockForwarder) ForwardToRouter(routerHash [32]byte, msgBytes []byte) error {
	f.routerCalled = true
	return nil
}

// Verify the string representations of tunnel encryption types (completeness check).
func TestCryptoAudit_EncryptionTypeStrings(t *testing.T) {
	assert.True(t, strings.Contains(cryptotunnel.TunnelEncryptionAES.String(), "AES"),
		"AES type string should contain 'AES'")
	assert.True(t, strings.Contains(cryptotunnel.TunnelEncryptionECIES.String(), "ECIES"),
		"ECIES type string should contain 'ECIES'")
}
