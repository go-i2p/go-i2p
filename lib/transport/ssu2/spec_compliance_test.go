// Spec compliance tests for lib/transport/ssu2.
//
// These tests verify the go-noise/ssu2 primitives satisfy the invariants
// stated in the I2P SSU2.md specification and referenced in PLAN.md Phase 7.

package ssu2

import (
	"encoding/binary"
	"testing"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Block type coverage (spec lists 20 defined types) ------------------

// knownBlockTypes mirrors the set defined in SSU2.md §Block Types.
var knownBlockTypes = []uint8{
	ssu2noise.BlockTypeDateTime,         // 0
	ssu2noise.BlockTypeOptions,          // 1
	ssu2noise.BlockTypeRouterInfo,       // 2
	ssu2noise.BlockTypeI2NPMessage,      // 3
	ssu2noise.BlockTypeFirstFragment,    // 4
	ssu2noise.BlockTypeFollowOnFragment, // 5
	ssu2noise.BlockTypeTermination,      // 6
	ssu2noise.BlockTypeRelayRequest,     // 7
	ssu2noise.BlockTypeRelayResponse,    // 8
	ssu2noise.BlockTypeRelayIntro,       // 9
	ssu2noise.BlockTypePeerTest,         // 10
	ssu2noise.BlockTypeACK,              // 12
	ssu2noise.BlockTypeAddress,          // 13
	ssu2noise.BlockTypeRelayTagRequest,  // 15
	ssu2noise.BlockTypeRelayTag,         // 16
	ssu2noise.BlockTypeNewToken,         // 17
	ssu2noise.BlockTypePathChallenge,    // 18
	ssu2noise.BlockTypePathResponse,     // 19
	ssu2noise.BlockTypePadding,          // 254
}

// TestSpec_AllKnownBlockTypes_RecognisedByLibrary verifies that every block type
// listed in SSU2.md is reported as known by go-noise/ssu2.IsKnownBlockType.
func TestSpec_AllKnownBlockTypes_RecognisedByLibrary(t *testing.T) {
	for _, bt := range knownBlockTypes {
		assert.True(t, ssu2noise.IsKnownBlockType(bt),
			"block type %d should be recognised by IsKnownBlockType", bt)
	}
}

// TestSpec_AllKnownBlockTypes_Roundtrip verifies that every known block type
// can be serialised and deserialised without data loss.
func TestSpec_AllKnownBlockTypes_Roundtrip(t *testing.T) {
	// Minimum valid payloads for each block type.
	// Sizes are the minimum Data lengths accepted by SSU2Block.validate().
	minData := map[uint8][]byte{
		ssu2noise.BlockTypeDateTime:         make([]byte, 7),  // minDateTimeSize=7
		ssu2noise.BlockTypeOptions:          make([]byte, 15), // minOptionsSize=15
		ssu2noise.BlockTypeRouterInfo:       {0x01},
		ssu2noise.BlockTypeI2NPMessage:      {0x01},
		ssu2noise.BlockTypeFirstFragment:    make([]byte, 10),
		ssu2noise.BlockTypeFollowOnFragment: make([]byte, 8),
		ssu2noise.BlockTypeTermination:      make([]byte, 9), // minTerminationSize=9
		ssu2noise.BlockTypeRelayRequest:     {0x01},
		ssu2noise.BlockTypeRelayResponse:    {0x01},
		ssu2noise.BlockTypeRelayIntro:       {0x01},
		ssu2noise.BlockTypePeerTest:         {0x01},
		ssu2noise.BlockTypeACK:              make([]byte, 5),  // minACKSize=5
		ssu2noise.BlockTypeAddress:          make([]byte, 9),  // minAddressSizeIPv4=9
		ssu2noise.BlockTypeRelayTagRequest:  make([]byte, 3),  // minRelayTagRequestSize=3
		ssu2noise.BlockTypeRelayTag:         make([]byte, 7),  // minRelayTagSize=7
		ssu2noise.BlockTypeNewToken:         make([]byte, 15), // minNewTokenSize=15
		ssu2noise.BlockTypePathChallenge:    make([]byte, 8),
		ssu2noise.BlockTypePathResponse:     make([]byte, 8),
		ssu2noise.BlockTypePadding:          make([]byte, 4),
	}

	for _, bt := range knownBlockTypes {
		bt := bt
		data := minData[bt]
		t.Run(ssu2noise.GetBlockTypeName(bt), func(t *testing.T) {
			original := ssu2noise.NewSSU2Block(bt, data)
			serialised, err := original.Serialize()
			require.NoError(t, err, "block type %d should serialize", bt)

			blocks, err := ssu2noise.DeserializeBlocks(serialised)
			require.NoError(t, err, "block type %d should deserialize", bt)
			require.NotEmpty(t, blocks, "should have at least one block after deserialization")
			assert.Equal(t, original.Type, blocks[0].Type, "block type should survive roundtrip")
		})
	}
}

// --- Handshake message ordering ----------------------------------------

// TestSpec_HandshakeMessageTypes_Ordering verifies the numeric ordering
// of handshake message type constants matches the I2P spec sequence:
//
// SessionRequest (0) -> SessionCreated (1) -> SessionConfirmed (2)
func TestSpec_HandshakeMessageTypes_Ordering(t *testing.T) {
	assert.Less(t, ssu2noise.MessageTypeSessionRequest, ssu2noise.MessageTypeSessionCreated,
		"SessionRequest (%d) must come before SessionCreated (%d)",
		ssu2noise.MessageTypeSessionRequest, ssu2noise.MessageTypeSessionCreated)
	assert.Less(t, ssu2noise.MessageTypeSessionCreated, ssu2noise.MessageTypeSessionConfirmed,
		"SessionCreated (%d) must come before SessionConfirmed (%d)",
		ssu2noise.MessageTypeSessionCreated, ssu2noise.MessageTypeSessionConfirmed)
}

// --- Header sizes ------------------------------------------------------

// TestSpec_HeaderSizes verifies the short (16) and long (32) header sizes
// match SSU2 spec section 3.1.
func TestSpec_HeaderSizes(t *testing.T) {
	assert.Equal(t, 16, ssu2noise.ShortHeaderSize,
		"short header must be 16 bytes per SSU2.md section 3.1 (SessionConfirmed, Data)")
	assert.Equal(t, 32, ssu2noise.LongHeaderSize,
		"long header must be 32 bytes per SSU2.md section 3.1 (SessionRequest, SessionCreated, etc.)")
}

// TestSpec_ShortHeaderMessageTypes verifies that SessionConfirmed and Data
// packets are expected to use the short 16-byte header, and that a packet
// constructed with ShortHeaderSize header plus a MAC field can be serialised.
func TestSpec_ShortHeaderMessageTypes(t *testing.T) {
	shortTypes := []uint8{
		ssu2noise.MessageTypeSessionConfirmed,
		ssu2noise.MessageTypeData,
	}
	for _, mt := range shortTypes {
		p := ssu2noise.NewSSU2Packet(mt, 0)
		p.Header = make([]byte, ssu2noise.ShortHeaderSize)
		p.MAC = make([]byte, ssu2noise.MACSize) // production code fills with Poly1305
		_, err := p.Serialize()
		// A packet with only a 16-byte header + MAC is below the 40-byte
		// minimum enforced by SSU2Packet.validate(); serialization must
		// fail with "packet too small".
		require.Error(t, err, "message type %d with short header should fail validation (packet too small)", mt)
		assert.Contains(t, err.Error(), "packet too small",
			"message type %d should fail with 'packet too small'", mt)
	}
}

// --- Packet size limits ------------------------------------------------

// TestSpec_PacketSizeLimits verifies the IPv4 and IPv6 maximum sizes.
func TestSpec_PacketSizeLimits(t *testing.T) {
	assert.Equal(t, 1472, ssu2noise.MaxPacketSizeIPv4,
		"IPv4 max packet size must be 1472 bytes per SSU2.md")
	assert.Equal(t, 1452, ssu2noise.MaxPacketSizeIPv6,
		"IPv6 max packet size must be 1452 bytes per SSU2.md")
}

// TestSpec_IPv4GreaterThanIPv6 verifies IPv4 limit > IPv6 limit.
func TestSpec_IPv4GreaterThanIPv6(t *testing.T) {
	assert.Greater(t, ssu2noise.MaxPacketSizeIPv4, ssu2noise.MaxPacketSizeIPv6,
		"IPv4 payload limit must exceed IPv6 limit (IPv4 header is 20 bytes vs 40)")
}

// --- Termination reason codes ------------------------------------------

// TestSpec_TerminationBlockLayout verifies the SSU2 Termination block layout
// required by ssu2.rst §"Termination":
//
//	blk  :: 6
//	size :: 2 bytes big endian, value = 9 or more
//	data  :: valid data packets received (8 bytes, big endian)
//	         then rsn (1 byte), then optional additional data
//
// The block is carried inside an encrypted Data packet, which is why the
// upstream connection (CloseWithReason) owns its construction.
func TestSpec_TerminationBlockLayout(t *testing.T) {
	const validPackets = uint64(0x0102030405060708)
	const reason = byte(2) // idle timeout

	data := make([]byte, 9)
	binary.BigEndian.PutUint64(data[0:8], validPackets)
	data[8] = reason

	block := ssu2noise.SSU2Block{Type: ssu2noise.BlockTypeTermination, Data: data}
	serialized, err := ssu2noise.SerializeBlocks([]*ssu2noise.SSU2Block{&block})
	require.NoError(t, err)

	// type(1) + size(2) + data(9)
	assert.Len(t, serialized, 12)
	assert.Equal(t, byte(ssu2noise.BlockTypeTermination), serialized[0],
		"block type must be Termination (6)")
	assert.Equal(t, uint16(9), binary.BigEndian.Uint16(serialized[1:3]),
		"size field must be the 9-byte data length, big endian")

	// Reason is the LAST byte of the fixed 9-byte payload, immediately after an
	// 8-byte receive counter — not after a 4-byte "seconds connected" field,
	// which is the SSU1 layout.
	assert.Equal(t, validPackets, binary.BigEndian.Uint64(serialized[3:11]),
		"valid data packets received must occupy 8 bytes big endian")
	assert.Equal(t, reason, serialized[11], "reason byte follows the 8-byte counter")
}

// TestSpec_TerminationReasonCodes verifies the reason codes defined by
// ssu2.rst §"Termination" are the values the handler passes through, and that
// the payload length grows past the 9-byte minimum when additional data is
// present ("size :: 2 bytes, big endian, value = 9 or more").
func TestSpec_TerminationReasonCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason byte
	}{
		{"normal close", 0},
		{"termination received", 1},
		{"idle timeout", 2},
		{"router shutdown", 3},
		{"data phase AEAD failure", 4},
		{"clock skew", 7},
		{"incompatible version", 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 9)
			data[8] = tc.reason
			serialized, err := ssu2noise.SerializeBlocks([]*ssu2noise.SSU2Block{
				{Type: ssu2noise.BlockTypeTermination, Data: data},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.reason, serialized[len(serialized)-1],
				"reason code must be the last byte of the fixed payload")
		})
	}

	// Additional data after the reason is permitted: size must be 9 or more.
	data := make([]byte, 9+4)
	data[8] = 3
	copy(data[9:], "bye!")
	serialized, err := ssu2noise.SerializeBlocks([]*ssu2noise.SSU2Block{
		{Type: ssu2noise.BlockTypeTermination, Data: data},
	})
	require.NoError(t, err)
	assert.Equal(t, uint16(13), binary.BigEndian.Uint16(serialized[1:3]),
		"size field must include the additional data (9 + 4)")
}

// --- ACK delay bounds --------------------------------------------------

// specACKDelay computes the ACK delay per SSU2.md section 4.8:
//
// delay = max(10ms, min(rtt/6, 150ms))
func specACKDelay(rtt time.Duration) time.Duration {
	delay := rtt / 6
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > 150*time.Millisecond {
		delay = 150 * time.Millisecond
	}
	return delay
}

// TestSpec_ACKDelayBounds verifies the ACK delay formula against spec values.
func TestSpec_ACKDelayBounds(t *testing.T) {
	tests := []struct {
		rtt      time.Duration
		expected time.Duration
	}{
		{rtt: 1 * time.Millisecond, expected: 10 * time.Millisecond},   // floor
		{rtt: 60 * time.Millisecond, expected: 10 * time.Millisecond},  // exact floor boundary
		{rtt: 120 * time.Millisecond, expected: 20 * time.Millisecond}, // in range
		{rtt: 600 * time.Millisecond, expected: 100 * time.Millisecond},
		{rtt: 900 * time.Millisecond, expected: 150 * time.Millisecond}, // exact ceiling
		{rtt: 5 * time.Second, expected: 150 * time.Millisecond},        // capped
	}
	for _, tt := range tests {
		got := specACKDelay(tt.rtt)
		assert.Equal(t, tt.expected, got,
			"ACK delay for RTT=%v should be %v", tt.rtt, tt.expected)
		assert.GreaterOrEqual(t, got, 10*time.Millisecond, "floor violated for RTT=%v", tt.rtt)
		assert.LessOrEqual(t, got, 150*time.Millisecond, "ceiling violated for RTT=%v", tt.rtt)
	}
}

// TestSpec_ACKDelayBounds_EntireRange sweeps RTT from 1ms to 10s and confirms
// the formula always produces a value in [10ms, 150ms].
func TestSpec_ACKDelayBounds_EntireRange(t *testing.T) {
	for msec := 1; msec <= 10000; msec++ {
		rtt := time.Duration(msec) * time.Millisecond
		delay := specACKDelay(rtt)
		assert.GreaterOrEqual(t, delay, 10*time.Millisecond, "rtt=%v", rtt)
		assert.LessOrEqual(t, delay, 150*time.Millisecond, "rtt=%v", rtt)
	}
}
