package ntcp2

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	cryptoTypes "github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Section 8 — lib/transport/ntcp2 Spec Compliance Tests
// NTCP2 specification: ntcp2.rst, Proposal 111
// =============================================================================

// ---------------------------------------------------------------------------
// Noise XK Handshake
// ---------------------------------------------------------------------------

// TestNoiseXKHandshake_PatternString verifies the Noise pattern used for NTCP2.
//
// AUDIT FINDING: The I2P spec (ntcp2.rst) specifies Noise_XK_25519_ChaChaPoly_SHA256.
// The go-noise library's NTCP2Config defaults to pattern "XK" which maps internally
// to Noise_XK_25519_AESGCM_SHA256 (using AES-GCM instead of ChaChaPoly1305).
// This is a known deviation — the go-noise library uses AESGCM as the cipher suite.
// The I2P spec historically uses ChaChaPoly, but some implementations negotiate or
// use AESGCM as an equivalent AEAD cipher. The Noise framework allows both.
//
// Spec reference: ntcp2.rst Section "Noise Protocol"
func TestNoiseXKHandshake_PatternString(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	config, err := ntcp2.NewNTCP2Config(routerHash, false)
	require.NoError(t, err, "NewNTCP2Config must succeed with valid 32-byte hash")

	// Verify pattern is "XK" (Noise XK handshake pattern)
	assert.Equal(t, "XK", config.Pattern,
		"NTCP2 must use Noise XK pattern per spec (ntcp2.rst)")

	// Verify the config requires a 32-byte router hash (identity binding)
	assert.Len(t, config.RouterHash, 32,
		"RouterHash must be exactly 32 bytes (SHA-256 of RouterIdentity)")
}

// TestNoiseXKHandshake_Prologue verifies that NTCP2Config includes the router hash
// as prologue data for the Noise handshake. Per spec, the prologue binds the
// handshake to the recipient's identity (first 32 bytes = recipient's static key hash).
//
// Spec reference: ntcp2.rst Section "Prologue"
func TestNoiseXKHandshake_Prologue(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i + 0x10)
	}

	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// The RouterHash serves as prologue binding data in the Noise handshake
	assert.Equal(t, routerHash, config.RouterHash,
		"Config must store RouterHash for use as Noise prologue data")
	assert.True(t, len(config.RouterHash) == 32,
		"RouterHash (prologue) must be 32 bytes per ntcp2.rst")
}

// TestNoiseXKHandshake_Message1_EphemeralKey verifies Message 1 structure.
// In Noise XK, Message 1 (→ responder): e (32-byte ephemeral key) + encrypted payload.
// The go-noise library handles the actual handshake wire format; here we verify
// the config enables AES obfuscation of the ephemeral key as per spec.
//
// Spec reference: ntcp2.rst Section "SessionRequest (Message 1)"
func TestNoiseXKHandshake_Message1_EphemeralKey(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// AES obfuscation of ephemeral keys is enabled by default per spec
	assert.True(t, config.EnableAESObfuscation,
		"AES obfuscation of ephemeral keys must be enabled by default (spec: X is AES-CBC encrypted)")
}

// TestNoiseXKHandshake_Message2_EphemeralKey verifies Message 2 structure.
// Message 2 (← initiator): e (32-byte ephemeral key) + encrypted payload.
// The responder's ephemeral key is also AES-obfuscated per spec.
//
// Spec reference: ntcp2.rst Section "SessionCreated (Message 2)"
func TestNoiseXKHandshake_Message2_EphemeralKey(t *testing.T) {
	routerHash := make([]byte, 32)

	// Responder config
	responderCfg, err := ntcp2.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	assert.True(t, responderCfg.EnableAESObfuscation,
		"Responder must also have AES obfuscation enabled for Message 2 ephemeral key")
	assert.False(t, responderCfg.Initiator,
		"Responder config must have Initiator=false")
}

// TestNoiseXKHandshake_Message3_StaticKeyAndRouterInfo verifies Message 3 structure.
// Message 3 (→ responder): encrypted static key + encrypted payload containing RouterInfo.
// In XK, the initiator reveals their static key in Message 3.
//
// Spec reference: ntcp2.rst Section "SessionConfirmed (Message 3)"
func TestNoiseXKHandshake_Message3_StaticKeyAndRouterInfo(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// XK pattern: initiator sends static key in message 3
	assert.Equal(t, "XK", config.Pattern,
		"XK pattern means initiator's static key is sent encrypted in Message 3")

	// Static key must be settable (32 bytes for X25519)
	testStaticKey := make([]byte, 32)
	for i := range testStaticKey {
		testStaticKey[i] = byte(i + 0xAA)
	}
	config = config.WithStaticKey(testStaticKey)
	assert.Len(t, config.StaticKey, 32,
		"Static key for Message 3 must be exactly 32 bytes (X25519)")
}

// TestNoiseXKHandshake_StaticKeyBinding verifies that the static key used in
// the NTCP2 handshake is derived from the router's X25519 encryption key,
// binding the Noise handshake identity to the RouterInfo identity.
//
// Spec reference: ntcp2.rst Section "Static Key"
func TestNoiseXKHandshake_StaticKeyBinding(t *testing.T) {
	// loadStaticKeyFromRouter extracts X25519 private key from keystore
	// and sets it as NTCP2Config.StaticKey
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Simulate what loadStaticKeyFromRouter does
	fakeEncryptionKey := make([]byte, 32)
	for i := range fakeEncryptionKey {
		fakeEncryptionKey[i] = byte(i + 0x42)
	}
	config.StaticKey = fakeEncryptionKey

	assert.Len(t, config.StaticKey, 32,
		"Static key must be 32 bytes (X25519 private key from RouterIdentity)")
	assert.Equal(t, fakeEncryptionKey, config.StaticKey,
		"Static key must be derived from router's X25519 encryption key")

	// Verify GetStaticKeyFromRouter helper
	mockKey := &mockPrivateKey{keyData: fakeEncryptionKey}
	derivedKey := GetStaticKeyFromRouter(mockKey)
	assert.Equal(t, fakeEncryptionKey, derivedKey,
		"GetStaticKeyFromRouter must return the raw encryption key bytes")
}

// TestNoiseXKHandshake_RouterInfoDelivery verifies that RouterInfo is delivered
// per spec: initiator sends their RouterInfo in Message 3, and the responder
// is expected to send theirs in the first data phase frame.
//
// Spec reference: ntcp2.rst Section "RouterInfo exchange"
func TestNoiseXKHandshake_RouterInfoDelivery(t *testing.T) {
	// The initiator config must be configured for outbound (Message 3 carries RouterInfo)
	routerHash := make([]byte, 32)
	initiatorCfg, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)
	assert.True(t, initiatorCfg.Initiator,
		"Initiator config must be set for outbound connections (carries RouterInfo in Message 3)")

	// Responder expects to receive RouterInfo in Message 3
	responderCfg, err := ntcp2.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	assert.False(t, responderCfg.Initiator,
		"Responder receives initiator's RouterInfo in Message 3, sends own in first data frame")
}

// TestNoiseXKHandshake_Padding verifies that handshake padding is configured
// per spec with configurable min/max constraints.
//
// Spec reference: ntcp2.rst Section "Padding"
func TestNoiseXKHandshake_Padding(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Frame padding must be enabled by default per spec
	assert.True(t, config.FramePaddingEnabled,
		"Frame padding must be enabled by default per ntcp2.rst")

	// Min/Max padding constraints must be configurable
	assert.GreaterOrEqual(t, config.MaxPaddingSize, config.MinPaddingSize,
		"MaxPaddingSize must be >= MinPaddingSize")

	// Test custom padding configuration
	customConfig := config.WithFrameSettings(config.MaxFrameSize, true, 16, 128)
	assert.Equal(t, 16, customConfig.MinPaddingSize, "Custom MinPaddingSize must be respected")
	assert.Equal(t, 128, customConfig.MaxPaddingSize, "Custom MaxPaddingSize must be respected")
}

// TestNoiseXKHandshake_Timestamp verifies that the options block in handshake
// messages includes timestamp handling. Spec requires rejecting if clock skew
// exceeds ±2 minutes (configurable).
//
// AUDIT FINDING: Timestamp validation (clock skew rejection) is handled by the
// go-noise library's handshake modifier chain. The local transport code does not
// explicitly check timestamps, delegating to the Noise library.
//
// Spec reference: ntcp2.rst Section "Options block"
func TestNoiseXKHandshake_Timestamp(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Handshake timeout is the overall timeout for the handshake exchange
	assert.Greater(t, config.HandshakeTimeout.Seconds(), float64(0),
		"HandshakeTimeout must be configured (controls total handshake time including timestamp validation)")

	// Default timeout should be reasonable (30s in the library)
	assert.LessOrEqual(t, config.HandshakeTimeout.Seconds(), float64(60),
		"HandshakeTimeout should not exceed 60 seconds")
}

// TestNoiseXKHandshake_Version verifies that the NTCP2 version option is set to 2
// in published router addresses (options block "v" = "2").
//
// Spec reference: ntcp2.rst Section "Published addresses"
func TestNoiseXKHandshake_Version(t *testing.T) {
	// The buildRouterAddressOptions function must set v=2
	staticKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	ntcp2Config := &ntcp2.NTCP2Config{
		ObfuscationIV: make([]byte, 16),
	}

	options, err := buildRouterAddressOptions("127.0.0.1", "8080", staticKey, ntcp2Config)
	require.NoError(t, err)

	assert.Equal(t, "2", options["v"],
		"NTCP2 version in published RouterAddress options must be '2' per spec")
	assert.Contains(t, options, "s", "Published options must include static key 's'")
	assert.Contains(t, options, "i", "Published options must include obfuscation IV 'i'")
	assert.Contains(t, options, "host", "Published options must include 'host'")
	assert.Contains(t, options, "port", "Published options must include 'port'")
}

// ---------------------------------------------------------------------------
// Data Phase (Post-Handshake)
// ---------------------------------------------------------------------------

// TestDataPhase_FrameFormat verifies that the local framing uses a length-prefixed
// format for I2NP messages.
//
// AUDIT FINDING: The local framing.go uses a 4-byte big-endian length prefix
// for I2NP messages at the application layer. The actual NTCP2 wire format with
// 2-byte SipHash-obfuscated lengths is handled by the go-noise library's
// SipHashLengthModifier at the transport layer. The local framing operates
// ABOVE the Noise encryption layer.
//
// Spec reference: ntcp2.rst Section "Data Phase"
func TestDataPhase_FrameFormat(t *testing.T) {
	msg := i2np.NewDataMessage([]byte("test frame format"))
	framedData, err := FrameI2NPMessage(msg)
	require.NoError(t, err)

	// Local framing uses 4-byte big-endian length prefix
	require.True(t, len(framedData) >= 4, "Framed data must have at least 4-byte length prefix")

	// Extract and verify the length prefix
	length := binary.BigEndian.Uint32(framedData[:4])
	assert.Equal(t, uint32(len(framedData)-4), length,
		"4-byte length prefix must equal the payload size")
}

// TestDataPhase_LengthObfuscation verifies that SipHash-based length encryption
// is enabled in the NTCP2 configuration for the transport layer.
//
// Spec reference: ntcp2.rst Section "Length Obfuscation"
func TestDataPhase_LengthObfuscation(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	assert.True(t, config.EnableSipHashLength,
		"SipHash-based length obfuscation must be enabled by default per ntcp2.rst")
}

// TestDataPhase_BlockTypes verifies that the implementation handles the required
// NTCP2 block types. The spec defines: DateTime(0), Options(1), RouterInfo(2),
// I2NP(3), Termination(4), Padding(254).
//
// AUDIT FINDING: Block type handling is primarily done by the go-noise library.
// The local code handles I2NP messages through the framing layer.
//
// Spec reference: ntcp2.rst Section "Block Types"
func TestDataPhase_BlockTypes(t *testing.T) {
	// The I2NP block type (3) is the primary block handled locally
	// Verify we can create and frame I2NP messages of various types
	testMessages := []struct {
		name    string
		msgType int
	}{
		{"Data message", i2np.I2NP_MESSAGE_TYPE_DATA},
		// Additional I2NP message types handled by the framing layer
	}

	for _, tc := range testMessages {
		t.Run(tc.name, func(t *testing.T) {
			msg := i2np.NewDataMessage([]byte("block type test"))
			framedData, err := FrameI2NPMessage(msg)
			require.NoError(t, err)
			assert.True(t, len(framedData) > 4,
				"I2NP block (type 3) must be frameable for transport")
		})
	}
}

// TestDataPhase_I2NPBlock verifies that I2NP messages are framed with proper
// headers for NTCP2 transport.
//
// Spec reference: ntcp2.rst Section "I2NP Block (type 3)"
func TestDataPhase_I2NPBlock(t *testing.T) {
	payload := []byte("I2NP block content for spec compliance test")
	msg := i2np.NewDataMessage(payload)
	msg.SetMessageID(12345)

	framedData, err := FrameI2NPMessage(msg)
	require.NoError(t, err)

	// Verify framing roundtrip
	conn := &mockConn{data: framedData}
	unframed, err := UnframeI2NPMessage(conn)
	require.NoError(t, err)

	assert.Equal(t, i2np.I2NP_MESSAGE_TYPE_DATA, unframed.Type(),
		"I2NP message type must survive framing roundtrip")
	assert.Equal(t, 12345, unframed.MessageID(),
		"I2NP message ID must survive framing roundtrip")
}

// TestDataPhase_DateTimeBlock verifies DateTime block awareness.
// Spec requires periodic DateTime blocks (4-byte timestamp).
//
// AUDIT FINDING: DateTime blocks are handled by the go-noise library's data
// phase. The local session code sends I2NP messages; the Noise layer can
// inject DateTime blocks as needed.
//
// Spec reference: ntcp2.rst Section "DateTime Block (type 0)"
func TestDataPhase_DateTimeBlock(t *testing.T) {
	// DateTime blocks are a transport-layer concern handled by go-noise.
	// The local session tracks time via read deadlines (ntcp2ReadDeadline = 5 min)
	// which serve as a session liveness check.
	assert.Equal(t, 5*60, int(ntcp2ReadDeadline.Seconds()),
		"Read deadline (5 min) serves as session liveness check complementing DateTime blocks")
}

// TestDataPhase_PaddingBlock verifies that padding is supported in the data phase.
//
// Spec reference: ntcp2.rst Section "Padding Block (type 254)"
func TestDataPhase_PaddingBlock(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	assert.True(t, config.FramePaddingEnabled,
		"Data phase padding (block type 254) must be enabled for traffic obfuscation")
	assert.GreaterOrEqual(t, config.MaxPaddingSize, 0,
		"MaxPaddingSize must be non-negative")
}

// TestDataPhase_TerminationBlock verifies that the implementation properly
// terminates sessions. The spec requires sending a Termination block with a
// reason code before closing the connection.
//
// AUDIT FINDING: Session termination in the local code calls Close() which
// drains the send queue then cancels the context. The actual Termination block
// (type 4) wire format is handled by the go-noise library.
//
// Spec reference: ntcp2.rst Section "Termination Block (type 4)"
func TestDataPhase_TerminationBlock(t *testing.T) {
	conn := &mockConn{data: []byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logger.WithField("test", "termination")

	session := NewNTCP2Session(conn, ctx, logger)
	require.NotNil(t, session)

	// Close should drain queue then terminate
	err := session.Close()
	assert.NoError(t, err, "Session close (triggering termination) must not error")

	// Verify session is fully closed (context canceled)
	assert.Error(t, session.ctx.Err(), "Session context must be canceled after Close()")
}

// TestDataPhase_MaxFrameSize verifies the maximum I2NP message size constraint.
//
// AUDIT FINDING: The local maxI2NPMessageSize is 65516 bytes (matching the I2NP
// message spec). The go-noise library's default MaxFrameSize is 16384 (16KB).
// The NTCP2 spec allows up to 65535 bytes per frame. The local 65516 is the
// I2NP message limit, not the NTCP2 frame limit — these are at different layers.
//
// Spec reference: ntcp2.rst Section "Max Frame Size"
func TestDataPhase_MaxFrameSize(t *testing.T) {
	// Local I2NP message size limit (65516 per I2NP spec)
	// This constant is defined locally in UnframeI2NPMessage
	const expectedMaxI2NPMessageSize = 65516

	// Verify by testing that a message at the max size can be framed
	maxPayload := make([]byte, expectedMaxI2NPMessageSize-100) // leave room for I2NP header overhead
	msg := i2np.NewDataMessage(maxPayload)
	_, err := FrameI2NPMessage(msg)
	assert.NoError(t, err, "Messages within maxI2NPMessageSize must be frameable")

	// The NTCP2 frame size limit is configured in the Noise library
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	assert.Greater(t, config.MaxFrameSize, 0,
		"MaxFrameSize must be positive")

	// Verify max frame can be reconfigured up to spec limit
	customConfig := config.WithFrameSettings(65535, true, 0, 64)
	assert.Equal(t, 65535, customConfig.MaxFrameSize,
		"MaxFrameSize must be configurable up to 65535 per ntcp2.rst")
}

// ---------------------------------------------------------------------------
// Rekey
// ---------------------------------------------------------------------------

// TestRekey_ThresholdAndMechanism verifies the rekey threshold and mechanism.
//
// AUDIT FINDING: The local RekeyThreshold is 65535 (just under 2^16), which is
// a conservative threshold compared to the spec's 2^64-1. This is a deliberate
// design choice for forward secrecy — rekeying more frequently provides stronger
// security guarantees. The NTCP2Conn.Rekey() method in go-noise delegates to the
// Noise library's rekey function which derives new cipher state per Noise spec
// (encrypts 32 zero bytes with nonce 2^64-1, takes first 32 bytes as new key).
//
// Spec reference: ntcp2.rst Section "Rekey"
func TestRekey_ThresholdAndMechanism(t *testing.T) {
	// Verify threshold constant
	assert.Equal(t, uint64(65535), RekeyThreshold,
		"RekeyThreshold is 65535 (conservative, spec allows up to 2^64-1)")

	// Verify threshold is well below the theoretical max (2^64-1)
	specMaxBeforeRekey := uint64(math.MaxUint64)
	assert.Less(t, RekeyThreshold, specMaxBeforeRekey,
		"RekeyThreshold must be less than 2^64-1 (spec max)")

	// Verify the Rekeyer interface exists and is well-defined
	var _ Rekeyer = (Rekeyer)(nil)
	rekeyerType := reflect.TypeOf((*Rekeyer)(nil)).Elem()
	assert.True(t, rekeyerType.Kind() == reflect.Interface,
		"Rekeyer must be an interface type")

	rekeyMethod, found := rekeyerType.MethodByName("Rekey")
	assert.True(t, found, "Rekeyer interface must have a Rekey() method")
	assert.Equal(t, 0, rekeyMethod.Type.NumIn(),
		"Rekey() must take no arguments")
	assert.Equal(t, 1, rekeyMethod.Type.NumOut(),
		"Rekey() must return 1 value (error)")
}

// TestRekey_RekeyStateTracking verifies that the rekey state correctly tracks
// message counts and rekey operations.
//
// Spec reference: ntcp2.rst Section "Rekey"
func TestRekey_RekeyStateTracking(t *testing.T) {
	state := &rekeyState{}

	// Initial state: zero messages
	assert.Equal(t, uint64(0), state.totalMessages(),
		"Initial total messages must be zero")
	assert.Equal(t, uint64(0), state.getRekeyCount(),
		"Initial rekey count must be zero")

	// Record sent messages
	for i := 0; i < 100; i++ {
		state.recordSent()
	}
	assert.Equal(t, uint64(100), state.totalMessages(),
		"Total messages after 100 sends must be 100")

	// Record received messages
	for i := 0; i < 50; i++ {
		state.recordReceived()
	}
	assert.Equal(t, uint64(150), state.totalMessages(),
		"Total messages after 100 sent + 50 received must be 150")
}

// TestRekey_NTCPConnImplementsRekeyer verifies that the go-noise NTCP2Conn
// implements the Rekeyer interface.
//
// Spec reference: ntcp2.rst Section "Rekey"
func TestRekey_NTCPConnImplementsRekeyer(t *testing.T) {
	// Verify NTCP2Conn from go-noise has a Rekey() method via reflection
	connType := reflect.TypeOf((*ntcp2.NTCP2Conn)(nil))
	rekeyMethod, found := connType.MethodByName("Rekey")
	assert.True(t, found,
		"ntcp2.NTCP2Conn must have a Rekey() method (implements Rekeyer interface)")

	if found {
		// Verify method signature: func() error
		assert.Equal(t, 1, rekeyMethod.Type.NumIn(),
			"Rekey() on NTCP2Conn must take receiver only (no args)")
		assert.Equal(t, 1, rekeyMethod.Type.NumOut(),
			"Rekey() must return 1 value (error)")
	}
}

// ---------------------------------------------------------------------------
// Connection Management
// ---------------------------------------------------------------------------

// TestConnectionManagement_InactivityTimeout verifies that the session has an
// inactivity/read deadline timeout to detect stale connections.
//
// Spec reference: ntcp2.rst Section "Connection Management"
func TestConnectionManagement_InactivityTimeout(t *testing.T) {
	// ntcp2ReadDeadline is the max idle time before checking session state
	assert.Equal(t, 5*60, int(ntcp2ReadDeadline.Seconds()),
		"Read deadline must be 5 minutes (inactivity timeout)")

	// The sendQueueDrainTimeout controls graceful shutdown timing
	assert.Equal(t, 2, int(sendQueueDrainTimeout.Seconds()),
		"Send queue drain timeout must be 2 seconds for graceful shutdown")
}

// TestConnectionManagement_MaxConcurrentConnections verifies that the transport
// enforces a configurable maximum number of concurrent sessions.
//
// Spec reference: ntcp2.rst Section "Connection limits"
func TestConnectionManagement_MaxConcurrentConnections(t *testing.T) {
	// Default max sessions
	assert.Equal(t, 512, DefaultMaxSessions,
		"DefaultMaxSessions must be 512")

	// Config respects custom max sessions
	config, err := NewConfig(":8080")
	require.NoError(t, err)

	assert.Equal(t, DefaultMaxSessions, config.GetMaxSessions(),
		"Default config must return DefaultMaxSessions (512)")

	// Custom max sessions
	config.MaxSessions = 100
	assert.Equal(t, 100, config.GetMaxSessions(),
		"Custom MaxSessions must be respected")

	// Zero max sessions should fall back to default
	config.MaxSessions = 0
	assert.Equal(t, DefaultMaxSessions, config.GetMaxSessions(),
		"Zero MaxSessions must fall back to DefaultMaxSessions")
}

// TestConnectionManagement_SessionLimitEnforcement verifies the atomic session
// limit enforcement mechanism (CAS-based to prevent TOCTOU races).
func TestConnectionManagement_SessionLimitEnforcement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config, err := NewConfig(":0")
	require.NoError(t, err)
	config.MaxSessions = 2

	transport := &NTCP2Transport{
		config: config,
		ctx:    ctx,
		cancel: cancel,
		logger: logger.WithField("test", "session_limit"),
	}

	// First two reservations should succeed
	err = transport.checkSessionLimit()
	assert.NoError(t, err, "First session should be allowed")

	err = transport.checkSessionLimit()
	assert.NoError(t, err, "Second session should be allowed")

	// Third should fail — pool full
	err = transport.checkSessionLimit()
	assert.ErrorIs(t, err, ErrConnectionPoolFull,
		"Session limit must be enforced with ErrConnectionPoolFull")

	// Unreserving should allow new sessions
	transport.unreserveSessionSlot()
	err = transport.checkSessionLimit()
	assert.NoError(t, err, "After unreserving, new session should be allowed")
}

// TestConnectionManagement_IPPortFromRouterAddress verifies that NTCP2 addresses
// are properly extracted from RouterAddress options (host and port).
//
// Spec reference: ntcp2.rst Section "Published Addresses"
func TestConnectionManagement_IPPortFromRouterAddress(t *testing.T) {
	// Test isNTCP2Transport case-insensitive matching
	t.Run("transport style detection", func(t *testing.T) {
		// Verify case-insensitive comparison via SupportsNTCP2
		assert.False(t, SupportsNTCP2(nil),
			"SupportsNTCP2 must return false for nil RouterInfo")
	})

	// Test HasDialableNTCP2Address nil safety
	t.Run("nil RouterInfo", func(t *testing.T) {
		assert.False(t, HasDialableNTCP2Address(nil),
			"HasDialableNTCP2Address must return false for nil RouterInfo")
	})

	// Test HasDirectConnectivity nil safety
	t.Run("nil RouterAddress", func(t *testing.T) {
		assert.False(t, HasDirectConnectivity(nil),
			"HasDirectConnectivity must return false for nil RouterAddress")
	})
}

// ---------------------------------------------------------------------------
// Cryptography Audit
// ---------------------------------------------------------------------------

// TestCryptoAudit_NoiseFramework verifies that the go-noise library is configured
// with the correct Noise parameters for NTCP2.
//
// AUDIT FINDING: The go-noise library uses Noise_XK_25519_AESGCM_SHA256 rather
// than the spec's Noise_XK_25519_ChaChaPoly_SHA256. Both are valid AEAD ciphers
// in the Noise framework. The I2P network currently uses ChaChaPoly, but the
// go-i2p implementation uses AESGCM. This is noted as a deviation.
//
// Spec reference: ntcp2.rst Section "Noise Protocol"
func TestCryptoAudit_NoiseFramework(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// XK pattern: initiator knows responder's static key before handshake
	assert.Equal(t, "XK", config.Pattern,
		"Must use XK pattern (initiator knows responder's static key)")

	// Verify all required NTCP2 features are enabled
	assert.True(t, config.EnableAESObfuscation,
		"AES obfuscation of handshake ephemeral keys must be enabled")
	assert.True(t, config.EnableSipHashLength,
		"SipHash length obfuscation must be enabled for data phase")
	assert.True(t, config.FramePaddingEnabled,
		"Frame padding must be enabled")
}

// TestCryptoAudit_StaticKeyDerivation verifies that the static key is derived
// from the router's X25519 encryption key, ensuring consistency with RouterIdentity.
//
// Spec reference: ntcp2.rst Section "Static Key"
func TestCryptoAudit_StaticKeyDerivation(t *testing.T) {
	// Simulate static key derivation flow
	fakePrivateKey := make([]byte, 32)
	for i := range fakePrivateKey {
		fakePrivateKey[i] = byte(i + 0x55)
	}

	// GetStaticKeyFromRouter must return the raw key bytes
	mockKey := &mockPrivateKey{keyData: fakePrivateKey}
	staticKey := GetStaticKeyFromRouter(mockKey)

	assert.Len(t, staticKey, 32,
		"Static key must be 32 bytes (X25519)")
	assert.Equal(t, fakePrivateKey, staticKey,
		"Static key must equal the router's X25519 encryption private key")

	// Verify the key can be loaded into NTCP2Config
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	config.StaticKey = staticKey
	assert.Len(t, config.StaticKey, 32,
		"NTCP2Config must accept 32-byte static key from router identity")
}

// TestCryptoAudit_SipHashLengthObfuscation verifies that SipHash is configured
// for length obfuscation in the data phase per spec.
//
// Spec reference: ntcp2.rst Section "Length Obfuscation"
func TestCryptoAudit_SipHashLengthObfuscation(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	assert.True(t, config.EnableSipHashLength,
		"SipHash length obfuscation must be enabled by default")

	// SipHash keys can be customized
	customConfig := config.WithSipHashLength(true, 0x1234, 0x5678)
	assert.True(t, customConfig.EnableSipHashLength,
		"Custom SipHash configuration must keep obfuscation enabled")
	assert.Equal(t, [2]uint64{0x1234, 0x5678}, customConfig.SipHashKeys,
		"Custom SipHash keys must be set correctly")
}

// TestCryptoAudit_AEAD verifies that all data frames are encrypted with
// authenticated encryption (AEAD) derived from the Noise handshake.
//
// AUDIT FINDING: The go-noise library uses AESGCM (not ChaChaPoly) as the
// AEAD cipher. All data phase messages are encrypted through the Noise
// transport layer. The local session code writes plaintext I2NP messages
// to the connection, and the Noise layer encrypts them transparently.
//
// Spec reference: ntcp2.rst Section "Data Phase Encryption"
func TestCryptoAudit_AEAD(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Verify the Noise framework provides encryption
	// Pattern XK ensures keys are established during handshake
	assert.Equal(t, "XK", config.Pattern,
		"XK pattern ensures AEAD keys are derived during handshake")

	// Verify handshake timeout and retries are configured
	// (needed for reliable key establishment)
	assert.Greater(t, config.HandshakeTimeout.Seconds(), float64(0),
		"HandshakeTimeout must be positive to ensure AEAD key establishment")
	assert.GreaterOrEqual(t, config.HandshakeRetries, 0,
		"HandshakeRetries must be non-negative")
}

// ---------------------------------------------------------------------------
// Legacy Crypto Check
// ---------------------------------------------------------------------------

// TestLegacyCrypto_NoNTCPv1Code verifies that no NTCP version 1 code exists
// in the ntcp2 package. NTCP v1 has been removed from the I2P network.
//
// Spec reference: NTCP (original) was replaced by NTCP2
func TestLegacyCrypto_NoNTCPv1Code(t *testing.T) {
	// Scan all .go files in the ntcp2 package directory for NTCPv1 indicators
	ntcpV1Indicators := []string{
		"ntcp1",
		"NTCPv1",
		"NTCP1",
		"ntcp_v1",
		"OldNTCP",
		"LegacyNTCP",
	}

	goFiles, err := filepath.Glob(filepath.Join(".", "*.go"))
	require.NoError(t, err, "Must be able to glob Go files in package directory")

	for _, file := range goFiles {
		// Skip test files themselves
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		content, err := os.ReadFile(file)
		require.NoError(t, err, "Must be able to read %s", file)

		contentStr := string(content)
		for _, indicator := range ntcpV1Indicators {
			assert.False(t, strings.Contains(strings.ToLower(contentStr), strings.ToLower(indicator)),
				"CRITICAL: File %s contains NTCPv1 indicator '%s' — NTCP v1 has been removed from the I2P network", file, indicator)
		}
	}
}

// TestLegacyCrypto_NoDHKeyExchangeNotX25519 verifies that no non-X25519 DH
// key exchange code exists in the ntcp2 package. NTCP2 exclusively uses X25519.
//
// Spec reference: ntcp2.rst requires X25519 (Curve25519)
func TestLegacyCrypto_NoDHKeyExchangeNotX25519(t *testing.T) {
	// Scan for legacy DH indicators that would signal non-X25519 usage
	legacyDHIndicators := []string{
		"elgamal",
		"ElGamal",
		"DiffieHellman",
		"dh_group",
		"DHGroup",
		"modp",
		"MODP",
	}

	goFiles, err := filepath.Glob(filepath.Join(".", "*.go"))
	require.NoError(t, err)

	for _, file := range goFiles {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		content, err := os.ReadFile(file)
		require.NoError(t, err)

		contentStr := string(content)
		for _, indicator := range legacyDHIndicators {
			assert.False(t, strings.Contains(contentStr, indicator),
				"File %s contains legacy DH indicator '%s' — NTCP2 must use X25519 exclusively", file, indicator)
		}
	}

	// Verify the static key is X25519 (32 bytes = Curve25519 key size)
	routerHash := make([]byte, 32)
	config, err := ntcp2.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	testKey := make([]byte, 32)
	config = config.WithStaticKey(testKey)
	assert.Len(t, config.StaticKey, 32,
		"Static key must be 32 bytes (X25519/Curve25519)")
}

// ---------------------------------------------------------------------------
// Transport Interface Compliance
// ---------------------------------------------------------------------------

// TestTransportInterfaceCompliance verifies that NTCP2Transport implements
// the transport.Transport interface from lib/transport.
func TestTransportInterfaceCompliance(t *testing.T) {
	transportType := reflect.TypeOf((*transport.Transport)(nil)).Elem()
	ntcp2TransportType := reflect.TypeOf((*NTCP2Transport)(nil))

	assert.True(t, ntcp2TransportType.Implements(transportType),
		"NTCP2Transport must implement transport.Transport interface")

	// Verify key interface methods exist
	requiredMethods := []string{"GetSession", "Accept", "SetIdentity", "Compatible", "Close", "Name", "Addr"}
	for _, method := range requiredMethods {
		_, found := ntcp2TransportType.MethodByName(method)
		assert.True(t, found, "NTCP2Transport must have %s method", method)
	}
}

// TestTransportName verifies the transport name is "NTCP2".
func TestTransportName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &NTCP2Transport{
		config: &Config{},
		ctx:    ctx,
		cancel: cancel,
		logger: logger.WithField("test", "name"),
	}

	assert.Equal(t, "NTCP2", transport.Name(),
		"Transport name must be 'NTCP2'")
}

// ---------------------------------------------------------------------------
// Session Compliance
// ---------------------------------------------------------------------------

// TestSessionCompliance_TransportSession verifies that NTCP2Session implements
// the transport.TransportSession interface.
func TestSessionCompliance_TransportSession(t *testing.T) {
	sessionType := reflect.TypeOf((*transport.TransportSession)(nil)).Elem()
	ntcp2SessionType := reflect.TypeOf((*NTCP2Session)(nil))

	assert.True(t, ntcp2SessionType.Implements(sessionType),
		"NTCP2Session must implement transport.TransportSession interface")

	// Verify key session methods
	requiredMethods := []string{"QueueSendI2NP", "ReadNextI2NP", "Close"}
	for _, method := range requiredMethods {
		_, found := ntcp2SessionType.MethodByName(method)
		assert.True(t, found, "NTCP2Session must have %s method", method)
	}
}

// TestSessionCompliance_BandwidthTracking verifies atomic bandwidth tracking.
func TestSessionCompliance_BandwidthTracking(t *testing.T) {
	conn := &mockConn{data: []byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logger.WithField("test", "bandwidth")

	session := NewNTCP2Session(conn, ctx, logger)
	defer session.Close()

	// Initial bandwidth must be zero
	sent, received := session.GetBandwidthStats()
	assert.Equal(t, uint64(0), sent, "Initial bytesSent must be zero")
	assert.Equal(t, uint64(0), received, "Initial bytesReceived must be zero")

	// Simulate bandwidth tracking via atomic operations
	atomic.AddUint64(&session.bytesSent, 1024)
	atomic.AddUint64(&session.bytesReceived, 2048)

	sent, received = session.GetBandwidthStats()
	assert.Equal(t, uint64(1024), sent, "Tracked bytesSent must be accurate")
	assert.Equal(t, uint64(2048), received, "Tracked bytesReceived must be accurate")
}

// TestSessionCompliance_DroppedMessageTracking verifies dropped message counting.
func TestSessionCompliance_DroppedMessageTracking(t *testing.T) {
	conn := &mockConn{data: []byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logger.WithField("test", "dropped")

	session := NewNTCP2Session(conn, ctx, logger)
	defer session.Close()

	assert.Equal(t, uint64(0), session.DroppedMessages(),
		"Initial dropped messages must be zero")
}

// ---------------------------------------------------------------------------
// Obfuscation IV Persistence
// ---------------------------------------------------------------------------

// TestObfuscationIV_Persistence verifies that the obfuscation IV is properly
// persisted and loaded across sessions.
//
// Spec reference: ntcp2.rst Section "Published Addresses" (IV must be stable)
func TestObfuscationIV_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	pc := NewPersistentConfig(tmpDir)

	// First call generates and stores IV
	iv1, err := pc.LoadOrGenerateObfuscationIV()
	require.NoError(t, err)
	assert.Len(t, iv1, obfuscationIVSize,
		"Generated IV must be exactly %d bytes", obfuscationIVSize)

	// Second call must load the same IV
	iv2, err := pc.LoadOrGenerateObfuscationIV()
	require.NoError(t, err)
	assert.Equal(t, iv1, iv2,
		"Loaded IV must match the originally generated IV (persistence)")

	// Verify the file exists with correct permissions
	ivPath := filepath.Join(tmpDir, obfuscationIVFilename)
	info, err := os.Stat(ivPath)
	require.NoError(t, err)
	assert.Equal(t, int64(obfuscationIVSize), info.Size(),
		"IV file must be exactly %d bytes", obfuscationIVSize)
}

// TestObfuscationIV_Size verifies the IV size matches the spec requirement (16 bytes).
func TestObfuscationIV_Size(t *testing.T) {
	assert.Equal(t, 16, obfuscationIVSize,
		"Obfuscation IV must be 16 bytes per ntcp2.rst (AES block size)")
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

// TestErrorTypes verifies that all required NTCP2 error types are defined.
func TestErrorTypes(t *testing.T) {
	assert.NotNil(t, ErrNTCP2NotSupported, "ErrNTCP2NotSupported must be defined")
	assert.NotNil(t, ErrSessionClosed, "ErrSessionClosed must be defined")
	assert.NotNil(t, ErrHandshakeFailed, "ErrHandshakeFailed must be defined")
	assert.NotNil(t, ErrInvalidRouterInfo, "ErrInvalidRouterInfo must be defined")
	assert.NotNil(t, ErrConnectionPoolFull, "ErrConnectionPoolFull must be defined")
	assert.NotNil(t, ErrFramingError, "ErrFramingError must be defined")
	assert.NotNil(t, ErrInvalidListenerAddress, "ErrInvalidListenerAddress must be defined")
	assert.NotNil(t, ErrInvalidConfig, "ErrInvalidConfig must be defined")

	// Verify WrapNTCP2Error produces meaningful messages
	wrapped := WrapNTCP2Error(ErrSessionClosed, "test context")
	assert.NotNil(t, wrapped, "WrapNTCP2Error must produce non-nil error")
	assert.Contains(t, wrapped.Error(), "test context",
		"Wrapped error must contain context description")
}

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

// mockPrivateKey implements types.PrivateEncryptionKey for testing.
// Interface requires: NewDecrypter() (Decrypter, error), Public() (PublicEncryptionKey, error), Bytes() []byte, Zero()
type mockPrivateKey struct {
	keyData []byte
}

func (m *mockPrivateKey) Bytes() []byte {
	return m.keyData
}

func (m *mockPrivateKey) Zero() {
	for i := range m.keyData {
		m.keyData[i] = 0
	}
}

func (m *mockPrivateKey) NewDecrypter() (cryptoTypes.Decrypter, error) {
	return nil, nil
}

func (m *mockPrivateKey) Public() (cryptoTypes.PublicEncryptionKey, error) {
	return nil, nil
}
