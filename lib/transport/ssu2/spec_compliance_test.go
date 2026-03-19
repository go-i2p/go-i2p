package ssu2

// Spec compliance tests for lib/transport/ssu2.
//
// These tests verify the go-noise/ssu2 primitives satisfy the invariants
// stated in the I2P SSU2.md specification and referenced in PLAN.md Phase 7.

import (
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
		serialised, err := p.Serialize()
		require.NoError(t, err, "message type %d with short header should serialize", mt)
		assert.GreaterOrEqual(t, len(serialised), ssu2noise.ShortHeaderSize,
			"serialised packet for message type %d must be >= ShortHeaderSize", mt)
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

// TestSpec_TerminationReasonCode_NormalClose verifies that reason code 0
// corresponds to the normal-close condition (no error).
func TestSpec_TerminationReasonCode_NormalClose(t *testing.T) {
	block := buildTerminationBlock(0)
	assert.Equal(t, byte(ssu2noise.BlockTypeTermination), block[0],
		"first byte must be BlockTypeTermination (6)")
	assert.Len(t, block, 12,
		"termination block must be 12 bytes (type=1, length=2, data=9)")
	assert.Equal(t, byte(0), block[11],
		"last byte must be the reason code (0 = normal close)")
}

// TestSpec_TerminationBlock_CustomReason verifies arbitrary reason bytes
// are preserved in the termination block.
func TestSpec_TerminationBlock_CustomReason(t *testing.T) {
	for _, reason := range []byte{0, 1, 2, 9, 255} {
		block := buildTerminationBlock(reason)
		assert.Equal(t, reason, block[11],
			"reason byte 0x%02x should be preserved in termination block", reason)
	}
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
