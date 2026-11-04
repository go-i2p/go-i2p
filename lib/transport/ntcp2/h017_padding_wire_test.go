package ntcp2

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	gontcp2 "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/require"
)

// wireHandshakePairNoPadding is wireHandshakePair with the initiator's padding
// turned off, so a frame written by the initiator reaches the responder as
// exactly the block stream that was serialised.
func wireHandshakePairNoPadding(t *testing.T) (initiator, responder *gontcp2.Conn) {
	t.Helper()

	p := newNTCP2TestKeyPair(t)
	p.initiatorConfig = p.initiatorConfig.WithFrameSettings(0, true, 0, 0)

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
	initiator, dialErr := gontcp2.DialNTCP2WithHandshakeContext(dialCtx, "tcp", tcpLn.Addr().String(), p.initiatorConfig)

	res := <-responderDone
	require.NoError(t, dialErr, "initiator dial")
	require.NoError(t, res.err, "responder handshake")
	return initiator, res.conn
}

// TestWireBlockDataEndingFE0000Survives is the H-017 regression: an I2NP block
// whose data happens to end in FE 00 00.
//
// The padding stripper used to locate the trailing padding block by scanning
// backwards for bytes that look like a padding header, so it read those three
// bytes as "[type=254][size=0]" and removed them. The block then declared more
// bytes than the frame carried, the transport failed to parse it, and the whole
// session was torn down — a remote peer could kill a link by choosing message
// content that ends that way.
//
// The boundary is now taken from the block stream itself, so the bytes are
// reached as data inside the block and the message is delivered intact.
func TestWireBlockDataEndingFE0000Survives(t *testing.T) {
	ic, rc := wireHandshakePairNoPadding(t)

	// Only one reader may own the connection: the unframer below, not a session
	// worker. The frame is read straight off the wire so the padding layer is
	// the only thing between the peer's bytes and ParseBlocks.
	body := append([]byte("a payload whose last three bytes look like a padding header"), 0xFE, 0x00, 0x00)
	short, err := i2np.MarshalMessageShort(i2np.NewDataMessage(body))
	require.NoError(t, err)

	frame := SerializeBlocks(NewI2NPBlock(short))
	require.Equal(t, []byte{0xFE, 0x00, 0x00}, frame[len(frame)-3:],
		"precondition: the frame must end in the lookalike sequence")

	unframer := NewBlockUnframer(rc)

	type readResult struct {
		msg i2np.Message
		err error
	}
	reads := make(chan readResult, 4)
	go func() {
		for {
			msg, readErr := unframer.ReadNextMessage()
			reads <- readResult{msg, readErr}
			if readErr != nil {
				return
			}
		}
	}()

	_, writeErr := ic.Write(frame)
	require.NoError(t, writeErr)

	var got i2np.Message
	select {
	case res := <-reads:
		require.NoError(t, res.err, "H-017: the frame was not delivered intact")
		got = res.msg
	case <-time.After(10 * time.Second):
		require.FailNow(t, "no message delivered and no error: the frame was silently dropped")
	}

	require.NotNil(t, got)

	// The unframer hands back the message decoded from the block's short-header
	// payload. Re-serialising it must reproduce the bytes that were sent: a frame
	// the padding stripper shortened would either fail to parse or come back with
	// a truncated tail.
	out, marshalErr := i2np.MarshalMessageShort(got)
	require.NoError(t, marshalErr)
	require.True(t, bytes.Equal(short, out),
		"payload came back changed: got %d bytes, sent %d", len(out), len(short))

	// The session must still be usable afterwards. A truncated frame used to be
	// fatal, so a second message proves the connection survived the lookalike.
	second, secondErr := i2np.MarshalMessageShort(i2np.NewDataMessage([]byte("still alive")))
	require.NoError(t, secondErr)
	_, writeErr = ic.Write(SerializeBlocks(NewI2NPBlock(second)))
	require.NoError(t, writeErr)

	select {
	case res := <-reads:
		require.NoError(t, res.err, "second frame after the lookalike must still arrive")
		gotSecond, marshalSecondErr := i2np.MarshalMessageShort(res.msg)
		require.NoError(t, marshalSecondErr)
		require.True(t, bytes.Equal(second, gotSecond))
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the connection stopped delivering frames after the lookalike")
	}
}
