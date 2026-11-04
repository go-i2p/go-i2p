// Regression tests for phase-2 spec-compliance findings W5, W6, W10.
//
// W5  — data-phase block ordering validation (ntcp2.rst:1455-1469, :1675, :1742)
// W6  — address option validation: v= / s= / i= present and valid before
//       dialing (ntcp2.rst:1861-1862), NTCP-published dual-protocol addresses
//       (ntcp2.rst:1864-1867), unpadded base64 interop
// W10 — I2NP may not be fragmented across ChaChaPoly frames (:1626-1628),
//       Termination block carries the real valid-frames count (:1691-1694),
//       static keys must be validated as curve points (:298, :1142),
//       last-shutdown time persistence (:1917-1918)

package ntcp2

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/testutil"
	gontcp2 "github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- frameSource: a net.Conn whose Read returns the queued frame payloads ---

type frameSource struct {
	mu       sync.Mutex
	frames   [][]byte
	pos      int
	written  [][]byte
	closed   bool
	deadline time.Time
}

func newFrameSource(frames ...[]byte) *frameSource {
	return &frameSource{frames: frames}
}

func (f *frameSource) queue(frame []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, frame)
}

func (f *frameSource) writtenFrames() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.written))
	copy(out, f.written)
	return out
}

func (f *frameSource) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pos >= len(f.frames) {
		if f.closed {
			return 0, io.EOF
		}
		// Block like a live socket until more frames arrive or close.
		select {
		case <-time.After(2 * time.Second):
			return 0, &mockTimeoutError{}
		}
	}
	frame := f.frames[f.pos]
	f.pos++
	n := copy(p, frame)
	return n, nil
}

func (f *frameSource) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	f.written = append(f.written, cp)
	return len(p), nil
}

func (f *frameSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *frameSource) LocalAddr() net.Addr                { return &mockAddr{"local"} }
func (f *frameSource) RemoteAddr() net.Addr               { return &mockAddr{"remote"} }
func (f *frameSource) SetDeadline(t time.Time) error      { return nil }
func (f *frameSource) SetWriteDeadline(t time.Time) error { return nil }
func (f *frameSource) SetReadDeadline(t time.Time) error  { return nil }

type mockTimeoutError struct{}

func (m *mockTimeoutError) Error() string   { return "i/o timeout" }
func (m *mockTimeoutError) Timeout() bool   { return true }
func (m *mockTimeoutError) Temporary() bool { return true }

func paddingBlock(size int) Block {
	return Block{Type: BlockTypePadding, Data: make([]byte, size)}
}

func i2npBlock(t *testing.T) Block {
	t.Helper()
	msg := i2np.NewDataMessage([]byte("w5 regression payload"))
	framed, err := FrameI2NPMessageAsBlock(msg)
	require.NoError(t, err)
	blocks, err := ParseBlocks(framed)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	return blocks[0]
}

// --- W5: ValidateDataPhaseBlockOrder (ntcp2.rst:1455-1469, :1675, :1742) ---

func TestW5_ValidateDataPhaseBlockOrder_Cases(t *testing.T) {
	msg := i2npBlock(t)
	datetime := NewDateTimeBlock()
	term := Block{Type: BlockTypeTermination, Data: make([]byte, 9)}

	cases := []struct {
		name     string
		blocks   []Block
		wantRule string
		wantRsn  byte
	}{
		{"single i2np", []Block{msg}, "", 0},
		{"i2np then padding last", []Block{msg, paddingBlock(16)}, "", 0},
		{"i2np termination padding", []Block{msg, term, paddingBlock(16)}, "", 0},
		{"i2np termination last", []Block{msg, term}, "", 0},
		{"padding not last", []Block{msg, paddingBlock(16), msg}, BlockOrderRulePaddingNotLast, TerminationPaddingViolation},
		{"multiple padding", []Block{msg, paddingBlock(4), paddingBlock(4)}, BlockOrderRuleMultiplePadding, TerminationPaddingViolation},
		{"termination then padding then more", []Block{msg, term, paddingBlock(4), msg}, BlockOrderRulePaddingNotLast, TerminationPaddingViolation},
		{"termination not last", []Block{term, msg}, BlockOrderRuleTerminationNotLast, TerminationPayloadFormatError},
		{"termination middle", []Block{msg, term, msg}, BlockOrderRuleTerminationNotLast, TerminationPayloadFormatError},
		{"padding before termination", []Block{msg, paddingBlock(4), term}, BlockOrderRulePaddingNotLast, TerminationPaddingViolation},
		{"datetime only valid", []Block{datetime}, "", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDataPhaseBlockOrder(tc.blocks)
			if tc.wantRule == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			var v *BlockOrderViolation
			require.ErrorAs(t, err, &v)
			assert.Equal(t, tc.wantRule, v.Rule)
			assert.Equal(t, tc.wantRsn, v.TerminationReason())
		})
	}
}

// The unframer must reject — not process — a frame whose blocks violate the
// ordering rules, and the session must close with the mapped reason code.
func TestW5_BlockUnframerRejectsMalformedFrame(t *testing.T) {
	msg := i2npBlock(t)
	// Padding followed by an I2NP block: padding is not last (:1463-1464, :1742).
	bad := SerializeBlocks(paddingBlock(8), msg)

	unframer := NewBlockUnframer(newFrameSource(bad))
	_, err := unframer.ReadNextMessage()
	require.Error(t, err, "malformed frame must be rejected")
	var v *BlockOrderViolation
	require.ErrorAs(t, err, &v)
	assert.Equal(t, BlockOrderRulePaddingNotLast, v.Rule)
	assert.Equal(t, byte(TerminationPaddingViolation), v.TerminationReason())
}

func TestW5_SessionClosesWithReasonOnMalformedFrame(t *testing.T) {
	msg := i2npBlock(t)
	// Termination not last (:1465-1469) -> reason 10.
	bad := SerializeBlocks(Block{Type: BlockTypeTermination, Data: make([]byte, 9)}, msg)

	conn := newFrameSource(bad)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	session := NewNTCP2Session(conn, ctx, logger.WithField("test", t.Name()))

	select {
	case <-session.GetContext().Done():
	case <-time.After(5 * time.Second):
		_ = session.Close()
		t.Fatal("session not closed after block ordering violation")
	}

	// The session must have sent a termination frame carrying the reason.
	deadline := time.After(2 * time.Second)
	for {
		var found bool
		for _, w := range conn.writtenFrames() {
			blocks, err := ParseBlocks(w)
			if err != nil {
				continue
			}
			for _, b := range blocks {
				if b.Type == BlockTypeTermination && len(b.Data) == 9 {
					assert.Equal(t, byte(TerminationPayloadFormatError), b.Data[8],
						"termination reason must map from the padding/termination rule violated")
					found = true
				}
			}
		}
		if found {
			return
		}
		select {
		case <-deadline:
			t.Fatal("no termination block written after violation")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// A well-formed frame must still process normally (no false positives).
func TestW5_BlockUnframerAcceptsValidFrame(t *testing.T) {
	msg := i2npBlock(t)
	good := SerializeBlocks(msg, paddingBlock(8))
	unframer := NewBlockUnframer(newFrameSource(good))
	got, err := unframer.ReadNextMessage()
	require.NoError(t, err)
	require.NotNil(t, got)
}

// --- W6: address option validation (ntcp2.rst:1852-1867) ---

func buildAddr(t *testing.T, style string, opts map[string]string) *router_address.RouterAddress {
	t.Helper()
	addr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), style, opts)
	require.NoError(t, err)
	return addr
}

func TestW6_ValidateNTCP2AddressOptions(t *testing.T) {
	validKey := validNTCP2TestKey(t)
	validIV := make([]byte, 16)
	for i := range validIV {
		validIV[i] = byte(i)
	}
	b64 := i2pbase64.EncodeToString
	b64NoPad := i2pbase64.EncodeToStringNoPadding

	base := func() map[string]string {
		return map[string]string{
			"host": "203.0.111.5",
			"port": "3333",
			"s":    b64(validKey),
			"i":    b64(validIV),
			"v":    "2",
		}
	}

	t.Run("all three valid", func(t *testing.T) {
		sk, iv, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", base()))
		require.NoError(t, err)
		assert.Len(t, sk, 32)
		assert.Len(t, iv, 16)
	})

	t.Run("missing v rejected", func(t *testing.T) {
		o := base()
		delete(o, "v")
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "v=")
	})

	t.Run("missing s rejected", func(t *testing.T) {
		o := base()
		delete(o, "s")
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
	})

	t.Run("missing i rejected", func(t *testing.T) {
		o := base()
		delete(o, "i")
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
	})

	t.Run("v=3 rejected", func(t *testing.T) {
		o := base()
		o["v"] = "3"
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "supported version")
	})

	t.Run("v=2,3 accepted", func(t *testing.T) {
		o := base()
		o["v"] = "2,3"
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.NoError(t, err)
	})

	t.Run("v=3,2 rejected out of order", func(t *testing.T) {
		o := base()
		o["v"] = "3,2"
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ascending")
	})

	t.Run("v=abc rejected", func(t *testing.T) {
		o := base()
		o["v"] = "abc"
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
	})

	t.Run("unpadded s and i accepted", func(t *testing.T) {
		o := base()
		o["s"] = strings.TrimRight(b64NoPad(validKey), "=")
		o["i"] = strings.TrimRight(b64NoPad(validIV), "=")
		require.NotContains(t, o["s"], "=")
		require.NotContains(t, o["i"], "=")
		sk, iv, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.NoError(t, err, "i2pd/Java unpadded base64 must interoperate")
		assert.Equal(t, validKey, sk)
		assert.Equal(t, validIV, iv)
	})

	t.Run("wrong length s rejected", func(t *testing.T) {
		o := base()
		o["s"] = b64(validKey[:20])
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
	})

	t.Run("non-curve s rejected", func(t *testing.T) {
		o := base()
		nonCurve := make([]byte, 32)
		nonCurve[0] = 2 // u=2: rhs of the Curve25519 equation is a Legendre non-residue
		o["s"] = b64(nonCurve)
		_, _, err := ValidateNTCP2AddressOptions(buildAddr(t, "NTCP2", o))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Curve25519", "error must identify the curve validation failure, got %v", err)
	})
}

// Dialing must refuse an address that fails option validation.
func TestW6_ConfigureDialRefusesInvalidOptions(t *testing.T) {
	validKey := validNTCP2TestKey(t)
	iv := make([]byte, 16)
	o := map[string]string{
		"host": "203.0.113.9",
		"port": "42069",
		"s":    i2pbase64.EncodeToString(validKey),
		"i":    i2pbase64.EncodeToString(iv),
		// v deliberately absent
	}
	addr := buildAddr(t, "NTCP2", o)

	cfg, err := gontcp2.NewNTCP2Config(newTestRouterHash(7), true)
	require.NoError(t, err)
	err = ConfigureDialConfigFromAddress(cfg, addr)
	require.Error(t, err, "must refuse to dial an address missing the v= option (ntcp2.rst:1861-1862)")
	assert.Contains(t, err.Error(), "v=")
}

// An "NTCP"-published address carrying full valid NTCP2 options is a dual
// protocol address (ntcp2.rst:1864-1867) and must be considered for NTCP2.
func TestW6_NTCPStyleAddressWithNTCP2OptionsIsCandidate(t *testing.T) {
	validKey := validNTCP2TestKey(t)
	iv := make([]byte, 16)

	addr := buildAddr(t, "NTCP", map[string]string{
		"host": "203.0.111.77",
		"port": "9999",
		"s":    i2pbase64.EncodeToString(validKey),
		"i":    i2pbase64.EncodeToString(iv),
		"v":    "1,2",
	})
	require.True(t, isNTCP2DialAddress(addr),
		"NTCP address with valid s/i/v options must be an NTCP2 dial candidate")

	// Without the NTCP2 options it is legacy NTCP only.
	plain := buildAddr(t, "NTCP", map[string]string{
		"host": "203.0.111.77",
		"port": "9999",
	})
	require.False(t, isNTCP2DialAddress(plain))

	// With invalid options (non-curve s) it must not qualify.
	nonCurve := make([]byte, 32)
	nonCurve[0] = 2
	bad := buildAddr(t, "NTCP", map[string]string{
		"host": "203.0.111.77",
		"port": "9999",
		"s":    i2pbase64.EncodeToString(nonCurve),
		"i":    i2pbase64.EncodeToString(iv),
		"v":    "2",
	})
	require.False(t, isNTCP2DialAddress(bad))
}

// Candidate extraction and the compatibility check must both honour the
// dual-protocol interpretation of NTCP-published addresses.
func TestW6_DialCandidatesAndSupportIncludeNTCPStyle(t *testing.T) {
	validKey := validNTCP2TestKey(t)
	iv := make([]byte, 16)

	addrOpts := map[string]string{
		"host": "127.0.0.1",
		"port": "36666",
		"s":    i2pbase64.EncodeToString(validKey),
		"i":    i2pbase64.EncodeToString(iv),
		"v":    "2",
	}
	ri := buildRouterInfoWithOptions(t, "NTCP", addrOpts)
	require.True(t, SupportsNTCP2(&ri), "NTCP address with full NTCP2 options implies NTCP2 support")

	cands, err := ExtractNTCP2DialCandidatesWithMetadata(ri)
	require.NoError(t, err, "NTCP-published dual-protocol address must yield a dial candidate")
	require.Len(t, cands, 1)
}

// --- W10: data phase ---

// I2NP messages may not be fragmented across ChaChaPoly frames
// (ntcp2.rst:1626-1628): an oversized message must be dropped, not split.
func TestW10_OversizedI2NPNotFragmented(t *testing.T) {
	// A framed block larger than the single-frame plaintext ceiling, but small
	// enough for the I2NP layer to marshal: a frame is 16 bytes of block and
	// short-header overhead plus the payload, and the ceiling is
	// maxOutboundFramePlaintext().
	oversize := maxOutboundFramePlaintext() + 48
	msg := i2np.NewDataMessage(make([]byte, oversize))
	framed, err := FrameI2NPMessageAsBlock(msg)
	require.NoError(t, err)
	require.Greater(t, len(framed), maxOutboundFramePlaintext())

	conn := newFrameSource()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	session := NewNTCP2SessionDeferred(conn, ctx, logger.WithField("test", t.Name()))
	session.StartWorkers()

	require.NoError(t, session.QueueSendI2NP(msg))

	// Wait for the send worker to process the message. Poll on the counter the
	// assertion below actually reads: the worker decrements the queue size
	// before it records the drop, so waiting only for the queue to empty can
	// observe dropped == 0 in the window between the two, which made this
	// flake under -race.
	deadline := time.Now().Add(5 * time.Second)
	for session.DroppedMessages() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	assert.Equal(t, 0, session.SendQueueSize(), "queue must drain")
	assert.GreaterOrEqual(t, session.DroppedMessages(), uint64(1), "oversized message must be counted as dropped")
	assert.Empty(t, conn.writtenFrames(), "oversized message must never be written (no fragmentation)")

	// The session must still be functional: a normal message gets written.
	small := i2np.NewDataMessage([]byte("still works"))
	require.NoError(t, session.QueueSendI2NP(small))
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(conn.writtenFrames()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.NotEmpty(t, conn.writtenFrames(), "normal messages must still be sent after a drop")
	_ = session.Close()
}

// Termination blocks in the data phase must carry the real receive nonce
// (ntcp2.rst:1691-1694), not a hardcoded 0.
func TestW10_TerminationCarriesRealValidFramesCount(t *testing.T) {
	p := newNTCP2TestKeyPair(t)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpLn.Close()

	ntcp2Ln, err := gontcp2.NewNTCP2Listener(tcpLn, p.responderConfig)
	require.NoError(t, err)
	defer ntcp2Ln.Close()

	transport := newTestTransport(ntcp2Ln, 10)
	defer transport.cancel()

	responderDone := make(chan *gontcp2.Conn, 1)
	go func() {
		conn, acceptErr := ntcp2Ln.Accept()
		if acceptErr != nil {
			responderDone <- nil
			return
		}
		responderConn, ok := conn.(*gontcp2.Conn)
		if !ok {
			responderDone <- nil
			return
		}
		if err := transport.executeHandshake(responderConn, context.Background()); err != nil {
			responderDone <- nil
			return
		}
		responderDone <- responderConn
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	initiator, err := gontcp2.DialNTCP2WithHandshakeContext(dialCtx, "tcp", tcpLn.Addr().String(), p.initiatorConfig)
	require.NoError(t, err)
	defer initiator.Close()

	responder := <-responderDone
	require.NotNil(t, responder, "responder handshake must succeed")
	defer responder.Close()

	// Exchange three valid data frames initiator -> responder.
	for i := 0; i < 3; i++ {
		_, err := initiator.Write([]byte{byte(i)})
		require.NoError(t, err)
		buf := make([]byte, 32)
		require.NoError(t, responder.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err = responder.Read(buf)
		require.NoError(t, err)
	}

	// The responder (Bob) now owns the receive nonce; close it through a
	// session so the termination block is built with the real count.
	session := NewNTCP2SessionDeferred(responder, context.Background(), logger.WithField("test", t.Name()))
	require.NoError(t, session.CloseWithReason(TerminationNormalClose))

	// Read the termination frame the responder sent on the initiator side.
	require.NoError(t, initiator.SetReadDeadline(time.Now().Add(5*time.Second)))
	blockBuf := make([]byte, 256)
	n, err := initiator.Read(blockBuf)
	require.NoError(t, err, "initiator must receive the termination frame")
	blocks, err := ParseBlocks(blockBuf[:n])
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, BlockTypeTermination, blocks[0].Type)

	frames := binary.BigEndian.Uint64(blocks[0].Data[0:8])
	assert.Equal(t, uint64(3), frames,
		"termination block must report the 3 valid data frames received (ntcp2.rst:1691-1694)")
	assert.Equal(t, byte(TerminationNormalClose), blocks[0].Data[8])
}

// validFramesReceived must return 0 for non-gonoise conns and the live nonce
// for established ones; handshake-phase conns report 0 per spec.
func TestW10_ValidFramesReceivedHelper(t *testing.T) {
	assert.Equal(t, uint64(0), validFramesReceived(&mockConn{data: []byte{}}))
	assert.Equal(t, uint64(0), validFramesReceived(nil))
}

// Static key curve validation (ntcp2.rst:298, :1142).
func TestW10_StaticKeyCurveValidation(t *testing.T) {
	// Valid generated keys pass.
	for i := 0; i < 5; i++ {
		key := validNTCP2TestKey(t)
		out, err := ValidateNTCP2StaticKey(key)
		require.NoError(t, err, "generated X25519 public key must validate")
		require.Len(t, out, 32)
	}

	// RFC 7748 §6.1 degenerate u-values must be rejected.
	degenerate := []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // u=0
		"0100000000000000000000000000000000000000000000000000000000000000", // u=1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u=p-1
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u=p
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u=p+1
	}
	for _, h := range degenerate {
		raw, err := hex.DecodeString(h)
		require.NoError(t, err)
		_, err = ValidateNTCP2StaticKey(raw)
		require.Error(t, err, "degenerate u %s must be rejected", h[:8])
	}

	// A non-curve u must be rejected by the Legendre check.
	raw, _ := hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	_, err := ValidateNTCP2StaticKey(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid point")

	// High-bit alias: same key with the high bit set must still validate and
	// canonicalise to the masked value.
	key := validNTCP2TestKey(t)
	aliased := append([]byte(nil), key...)
	aliased[31] |= 0x80
	out, err := ValidateNTCP2StaticKey(aliased)
	require.NoError(t, err)
	assert.Equal(t, key, out, "high-bit alias must canonicalise to the masked key")

	// Wrong lengths rejected.
	_, err = ValidateNTCP2StaticKey(key[:31])
	require.Error(t, err)
}

// The inbound gate must reject a Noise-authenticated key that is not a valid
// curve point even if it matches the published option (ntcp2.rst:1142).
func TestW10_VerifyRouterInfoRejectsInvalidCurvePoint(t *testing.T) {
	badKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	mock := &mockMsg3Conn{staticKey: badKey}
	err := verifyRouterInfoStaticKeyError(mock, badKey)
	require.Error(t, err, "degenerate authenticated static key must be rejected per ntcp2.rst:1142")
	assert.Contains(t, err.Error(), "curve point")

	// A valid key that matches must pass.
	good := validNTCP2TestKey(t)
	mock2 := &mockMsg3Conn{staticKey: good}
	require.NoError(t, verifyRouterInfoStaticKeyError(mock2, good))
}

// Last-shutdown persistence (ntcp2.rst:1917-1918).
func TestW10_LastShutdownPersistence(t *testing.T) {
	dir := t.TempDir()
	pc := NewPersistentConfig(dir)

	// Nothing stored yet.
	_, known := pc.PreviousDowntime()
	assert.False(t, known, "first run has no last-shutdown time")

	_, err := pc.LoadLastShutdownTime()
	require.NoError(t, err, "missing file is not an error")

	// Store and read back: second precision (8-byte BE unix seconds).
	stored := time.Now().Add(-2 * time.Hour)
	require.NoError(t, pc.SaveLastShutdownTime(stored))

	loaded, err := pc.LoadLastShutdownTime()
	require.NoError(t, err)
	assert.Equal(t, stored.Unix(), loaded.Unix())

	downtime, known := pc.PreviousDowntime()
	assert.True(t, known)
	assert.Greater(t, downtime, 119*time.Minute, "downtime must reflect the ~2h since shutdown")
	assert.Less(t, downtime, 121*time.Minute)

	// File uses the established naming/permission convention.
	path := filepath.Join(dir, "ntcp2_last_shutdown.dat")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "shutdown file must be owner-only like the IV file")

	// Zero time is not written.
	require.NoError(t, pc.SaveLastShutdownTime(time.Time{}))
	loaded2, err := pc.LoadLastShutdownTime()
	require.NoError(t, err)
	assert.Equal(t, stored.Unix(), loaded2.Unix(), "zero time must not overwrite the record")

	// Corrupt file surfaces as an error rather than a bogus downtime.
	require.NoError(t, os.WriteFile(path, []byte{1, 2, 3}, 0o600))
	_, err = pc.LoadLastShutdownTime()
	require.Error(t, err)
}

func TestW10_TransportClosePersistsLastShutdown(t *testing.T) {
	dir := t.TempDir()
	ntcp2Ln, err := gontcp2.NewNTCP2Listener(mustListen(t), newTestNTCP2Config(t, false))
	require.NoError(t, err)

	transport := newTestTransport(ntcp2Ln, 10)
	transport.config.Load().WorkingDir = dir

	before := time.Now().Add(-time.Second)
	require.NoError(t, transport.Close())

	pc := NewPersistentConfig(dir)
	loaded, err := pc.LoadLastShutdownTime()
	require.NoError(t, err, "Close must persist the last-shutdown time (ntcp2.rst:1917-1918)")
	assert.False(t, loaded.Before(before), "persisted time must be the shutdown instant")
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln
}

// buildRouterInfoWithAddr wraps RouterAddress options into a signed RouterInfo
// using the shared testutil builder.
func buildRouterInfoWithOptions(t *testing.T, style string, opts map[string]string) router_info.RouterInfo {
	t.Helper()
	cfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  style,
		Options:    opts,
	}
	ri := testutil.CreateSignedTestRouterInfo(t, nil, cfg)
	return *ri
}

// A frame whose Termination block is followed by other blocks (:1675,
// :1465-1469) must be rejected by the unframer before the termination — or
// any other block — is processed. Without the enforcement the unframer
// buffers the trailing I2NP block and returns it as a valid message.
func TestW5_BlockUnframerRejectsTerminationNotLast(t *testing.T) {
	msg := i2npBlock(t)
	bad := SerializeBlocks(Block{Type: BlockTypeTermination, Data: make([]byte, 9)}, msg)

	unframer := NewBlockUnframer(newFrameSource(bad))
	_, err := unframer.ReadNextMessage()
	require.Error(t, err, "termination-not-last frame must be rejected")
	var v *BlockOrderViolation
	require.ErrorAs(t, err, &v)
	assert.Equal(t, BlockOrderRuleTerminationNotLast, v.Rule)
	assert.Equal(t, byte(TerminationPayloadFormatError), v.TerminationReason())
}

// ExtractPeerStaticKey (used by the inbound identity gate and dial config)
// must ignore legacy NTCP addresses that do not carry full valid NTCP2
// options, while accepting NTCP-published dual-protocol addresses
// (ntcp2.rst:1864-1867).
func TestW6_ExtractPeerStaticKeyHonoursDualProtocol(t *testing.T) {
	validKey := validNTCP2TestKey(t)
	iv := make([]byte, 16)

	dual := buildRouterInfoWithOptions(t, "NTCP", map[string]string{
		"host": "203.0.111.90",
		"port": "8888",
		"s":    i2pbase64.EncodeToString(validKey),
		"i":    i2pbase64.EncodeToString(iv),
		"v":    "2",
	})
	got, err := ExtractPeerStaticKey(dual)
	require.NoError(t, err, "NTCP address with full NTCP2 options must yield the static key")
	assert.Equal(t, validKey, got)

	legacy := buildRouterInfoWithOptions(t, "NTCP", map[string]string{
		"host": "203.0.111.90",
		"port": "8888",
		"key":  i2pbase64.EncodeToString(validKey),
	})
	_, err = ExtractPeerStaticKey(legacy)
	require.Error(t, err, "legacy NTCP address without NTCP2 options must not be used for NTCP2")
}

// The dial path must refuse a peer whose only NTCP2 address carries an
// invalid (non-curve) static key — ntcp2.rst:298 — instead of starting an
// XK handshake that MixHashes a bad point.
func TestW10_DialRefusesInvalidCurvePoint(t *testing.T) {
	nonCurve := make([]byte, 32)
	nonCurve[0] = 2
	iv := make([]byte, 16)

	addr := buildAddr(t, "NTCP2", map[string]string{
		"host": "203.0.111.91",
		"port": "4444",
		"s":    i2pbase64.EncodeToString(nonCurve),
		"i":    i2pbase64.EncodeToString(iv),
		"v":    "2",
	})
	cfg, err := gontcp2.NewNTCP2Config(newTestRouterHash(3), true)
	require.NoError(t, err)
	err = ConfigureDialConfigFromAddress(cfg, addr)
	require.Error(t, err, "non-curve static key must refuse the dial (ntcp2.rst:298)")
	assert.Contains(t, err.Error(), "Curve25519")
}

// --- A6: a Termination block must not discard the I2NP messages that
// preceded it in the same frame (ntcp2.rst:1464, :1466) ---

// i2npBlockWithID frames a Data message carrying the given I2NP message ID,
// so a test can tell two blocks in one frame apart.
func i2npBlockWithID(t *testing.T, id uint32, payload string) Block {
	t.Helper()
	msg := i2np.NewDataMessage([]byte(payload))
	msg.SetMessageID(int(id))
	framed, err := FrameI2NPMessageAsBlock(msg)
	require.NoError(t, err)
	blocks, err := ParseBlocks(framed)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	return blocks[0]
}

// A conformant [I2NP, I2NP, Termination] frame must deliver both I2NP
// messages before the closure is reported. Before the fix, processBlocks
// returned (nil, true) on the Termination block and ReadNextMessage threw
// away firstMsg plus everything in bufferedMsgs.
func TestA6_TerminationFrameDeliversPrecedingI2NPMessages(t *testing.T) {
	term := Block{Type: BlockTypeTermination, Data: make([]byte, 9)}
	frame := SerializeBlocks(
		i2npBlockWithID(t, 0x1111, "a6 first"),
		i2npBlockWithID(t, 0x2222, "a6 second"),
		term,
	)

	unframer := NewBlockUnframer(newFrameSource(frame))

	first, err := unframer.ReadNextMessage()
	require.NoError(t, err, "first I2NP message in the terminated frame must be delivered")
	require.NotNil(t, first)
	assert.Equal(t, 0x1111, first.MessageID())

	second, err := unframer.ReadNextMessage()
	require.NoError(t, err, "second I2NP message in the terminated frame must be delivered")
	require.NotNil(t, second)
	assert.Equal(t, 0x2222, second.MessageID())

	// Only after the buffer drains does the unframer report the closure.
	_, err = unframer.ReadNextMessage()
	require.ErrorIs(t, err, io.EOF, "closure reported after buffered messages are delivered")
}

// A frame whose only block is a Termination block still reports EOF at once.
func TestA6_TerminationOnlyFrameStillReturnsEOF(t *testing.T) {
	term := Block{Type: BlockTypeTermination, Data: make([]byte, 9)}
	unframer := NewBlockUnframer(newFrameSource(SerializeBlocks(term)))
	_, err := unframer.ReadNextMessage()
	require.ErrorIs(t, err, io.EOF)
}

// The buffered-message path must not re-account the frame's bytes once per
// message: bytesRead is zeroed when draining the buffer.
func TestA6_BufferedMessagesDoNotDoubleCountBytes(t *testing.T) {
	term := Block{Type: BlockTypeTermination, Data: make([]byte, 9)}
	frame := SerializeBlocks(
		i2npBlockWithID(t, 0x3333, "a6 count one"),
		i2npBlockWithID(t, 0x4444, "a6 count two"),
		term,
	)
	unframer := NewBlockUnframer(newFrameSource(frame))

	_, err := unframer.ReadNextMessage()
	require.NoError(t, err)
	assert.Equal(t, len(frame), unframer.BytesRead(),
		"the frame's bytes are accounted exactly once, on the read that consumed it")

	_, err = unframer.ReadNextMessage()
	require.NoError(t, err)
	assert.Equal(t, 0, unframer.BytesRead(),
		"a buffered message must not re-account the frame's bytes")
}

// The single-frame plaintext ceiling is what the transport may hand conn.Write
// in one frame without go-noise fragmenting it. It must be the spec's own
// budget — 65535-byte frame minus the 16-byte tag minus the padding-block
// headroom — and not go-noise's 16 KiB default, which capped every outbound
// message at ~16 KB and silently dropped anything larger. i2pd uses the same
// ceiling for its outbound frames (NTCP2_UNENCRYPTED_FRAME_MAX_SIZE), so a
// message go-i2p is willing to send is one a peer can receive.
func TestW10_OutboundFrameBudgetIsSpecSized(t *testing.T) {
	const specFrame = 65535  // ntcp2.rst:1444 maximum ChaChaPoly frame
	const tag = 16           // ntcp2.rst:1445 Poly1305 tag
	const blockHeadroom = 67 // 3-byte block header + 64-byte default max padding

	assert.Equal(t, specFrame-tag-blockHeadroom, maxOutboundFramePlaintext(),
		"budget must be the spec frame minus the tag and the padding headroom")
	assert.Greater(t, maxOutboundFramePlaintext(), 16384,
		"budget must exceed go-noise's 16 KiB default, which silently capped outbound messages")

	// The worst-case padded, encrypted frame must still fit the wire format.
	assert.LessOrEqual(t, maxOutboundFramePlaintext()+blockHeadroom+tag, specFrame,
		"payload plus maximum padding plus tag must not exceed the maximum frame")

	// A config built by the transport carries the raised value into go-noise's
	// write path, which is what makes the budget real rather than nominal.
	cfg := applyNTCP2FrameSettings(newTestNTCP2Config(t, true))
	require.NotNil(t, cfg)
	assert.Equal(t, specFrame, cfg.MaxFrameSize,
		"dial config must raise MaxFrameSize to the spec maximum")

	// A message that would have been dropped under the old default must now be
	// accepted by the sizing check.
	oldDefaultCeiling := 16384 - tag - blockHeadroom
	msg := i2np.NewDataMessage(make([]byte, oldDefaultCeiling+1024))
	framed, err := FrameI2NPMessageAsBlock(msg)
	require.NoError(t, err)
	require.Greater(t, len(framed), oldDefaultCeiling,
		"precondition: the message exceeds the old default ceiling")
	assert.LessOrEqual(t, len(framed), maxOutboundFramePlaintext(),
		"a message within the spec budget must no longer be treated as oversized")
}

// TestW10_MidSizedI2NPDeliveredOnWire sends a message larger than go-noise's
// old 16 KiB default frame over a real NTCP2 handshake and reads it back whole.
//
// Before the outbound budget was raised, a message of this size was dropped by
// frameMessage — the peer received nothing and the caller got no error, so a
// tunnel build or a DatabaseStore above ~16 KB simply never arrived and the
// sender timed out. The write path must now carry it in a single frame
// (ntcp2.rst:1626-1628 forbids fragmenting an I2NP message across frames).
func TestW10_MidSizedI2NPDeliveredOnWire(t *testing.T) {
	p := newNTCP2TestKeyPair(t)
	p.initiatorConfig = applyNTCP2FrameSettings(p.initiatorConfig)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpLn.Close() })

	ntcp2Ln, err := gontcp2.NewNTCP2Listener(tcpLn, p.responderConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ntcp2Ln.Close() })

	tr := newTestTransport(ntcp2Ln, 10)
	t.Cleanup(tr.cancel)

	type responderResult struct {
		conn *gontcp2.Conn
		err  error
	}
	responderDone := make(chan responderResult, 1)
	go func() {
		conn, acceptErr := ntcp2Ln.Accept()
		if acceptErr != nil {
			responderDone <- responderResult{nil, acceptErr}
			return
		}
		rc, ok := conn.(*gontcp2.Conn)
		if !ok {
			responderDone <- responderResult{nil, errUnexpectedConnType}
			return
		}
		responderDone <- responderResult{rc, tr.executeHandshake(rc, context.Background())}
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(dialCancel)
	ic, dialErr := gontcp2.DialNTCP2WithHandshakeContext(dialCtx, "tcp", tcpLn.Addr().String(), p.initiatorConfig)
	res := <-responderDone
	require.NoError(t, dialErr, "initiator dial")
	require.NoError(t, res.err, "responder handshake")

	rc := res.conn
	body := make([]byte, 32*1024)
	for i := range body {
		body[i] = byte('A' + i%26)
	}
	short, err := i2np.MarshalMessageShort(i2np.NewDataMessage(body))
	require.NoError(t, err)
	frame := SerializeBlocks(NewI2NPBlock(short))
	require.Greater(t, len(frame), 16384, "the message must exceed go-noise's old default frame")
	require.LessOrEqual(t, len(frame), maxOutboundFramePlaintext())

	// One reader only: the unframer owns the responder connection.
	unframer := NewBlockUnframer(rc)
	written, writeErr := ic.Write(frame)
	require.NoError(t, writeErr)
	require.Equal(t, len(frame), written)

	type readResult struct {
		msg i2np.Message
		err error
	}
	reads := make(chan readResult, 2)
	go func() {
		msg, readErr := unframer.ReadNextMessage()
		reads <- readResult{msg, readErr}
	}()

	select {
	case got := <-reads:
		require.NoError(t, got.err, "a message within the spec budget must be delivered, not dropped")
		out, marshalErr := i2np.MarshalMessageShort(got.msg)
		require.NoError(t, marshalErr)
		require.Equal(t, short, out, "the message must arrive whole")
	case <-time.After(15 * time.Second):
		require.FailNow(t, "mid-sized message never arrived: it was dropped at the old ceiling")
	}

	_ = ic.Close()
	_ = rc.Close()
}
