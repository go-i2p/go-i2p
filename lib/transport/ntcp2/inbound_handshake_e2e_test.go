package ntcp2

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	gontcp2 "github.com/go-i2p/go-noise/ntcp2"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errUnexpectedConnType is reported when the NTCP2 listener hands back a
// connection that is not the concrete *ntcp2.Conn the wire handshake requires.
var errUnexpectedConnType = errors.New("accepted connection is not *ntcp2.Conn")

// ntcp2TestKeyPair builds matched initiator/responder NTCP2 configs using real
// Curve25519 static keys, with AES header obfuscation disabled so the tests
// exercise handshake framing rather than the obfuscation layer.
type ntcp2TestKeyPair struct {
	initiatorConfig *gontcp2.Config
	responderConfig *gontcp2.Config
}

func newNTCP2TestKeyPair(t *testing.T) ntcp2TestKeyPair {
	t.Helper()

	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly,
		upstreamnoise.HashSHA256,
	)

	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	var initiatorHash data.Hash
	copy(initiatorHash[:], "initiator-hash-32-bytes-long!!!!")
	var responderHash data.Hash
	copy(responderHash[:], "responder-hash-32-bytes-long!!!!")

	responderConfig, err := gontcp2.NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	responderConfig = responderConfig.
		WithStaticKey(responderKP.Private).
		WithAESObfuscation(false, nil)

	// msg3 must carry a RouterInfo block advertising the initiator's Noise static
	// key, otherwise the responder's key-binding check rejects the handshake.
	// Upstream go-noise requires an initiator's BobRouterHash (the AES
	// ephemeral-obfuscation key RH_B) to equal its RemoteRouterHash: for an
	// initiator both are the responder's hash.
	initiatorConfig, err := gontcp2.NewNTCP2Config(responderHash, true)
	require.NoError(t, err)
	initiatorConfig = initiatorConfig.
		WithStaticKey(initiatorKP.Private).
		WithRemoteRouterHash(responderHash).
		WithRemoteStaticKey(responderKP.Public).
		WithAESObfuscation(false, nil).
		WithLocalRouterInfo(routerInfoAdvertisingKey(initiatorKP.Public))

	return ntcp2TestKeyPair{initiatorConfig: initiatorConfig, responderConfig: responderConfig}
}

// routerInfoAdvertisingKey builds RouterInfo bytes embedding the given
// Curve25519 public key as an s= option, satisfying the initiator-side
// static-key binding check without a fully signed RouterInfo document.
func routerInfoAdvertisingKey(pub []byte) []byte {
	return []byte("ri s=" + i2pbase64.EncodeToString(pub))
}

// TestExecuteHandshake_PerformsNTCP2WireHandshake is the regression test for the
// inbound NTCP2 handshake compliance bug (finding C1).
//
// ntcp2.rst §"Message Format" states the two-byte frame length field "is used in
// the data phase messages only. Message 1 and 2 AEAD frames are fixed length.
// Message 3 part 1 AEAD frame is fixed length." Performing the inbound handshake
// through the generic Noise handshake (UnderlyingConn().Handshake()) adds that
// prefix to messages 1-3, sends nil payloads (so the 16-byte options block is
// never written), never MixHashes the cleartext padding, and leaves the
// connection's established flag clear so data-phase I/O fails.
//
// This test drives a REAL initiator handshake against a responder whose handshake
// is performed by executeHandshake, then proves the responder reached the data
// phase by exchanging bytes and captured the peer's msg3 RouterInfo.
func TestExecuteHandshake_PerformsNTCP2WireHandshake(t *testing.T) {
	p := newNTCP2TestKeyPair(t)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpLn.Close()

	ntcp2Ln, err := gontcp2.NewNTCP2Listener(tcpLn, p.responderConfig)
	require.NoError(t, err)
	defer ntcp2Ln.Close()

	transport := newTestTransport(ntcp2Ln, 10)
	defer transport.cancel()

	type responderResult struct {
		conn *gontcp2.Conn
		err  error
	}
	responderDone := make(chan responderResult, 1)

	// The responder handshake must run concurrently with the initiator dial:
	// msg1/msg2 are interleaved, so waiting for Dial to return before handshaking
	// would deadlock.
	go func() {
		conn, acceptErr := ntcp2Ln.Accept()
		if acceptErr != nil {
			responderDone <- responderResult{nil, acceptErr}
			return
		}
		responderConn, ok := conn.(*gontcp2.Conn)
		if !ok {
			responderDone <- responderResult{nil, errUnexpectedConnType}
			return
		}
		responderDone <- responderResult{responderConn, transport.executeHandshake(responderConn, context.Background())}
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	initiator, dialErr := gontcp2.DialNTCP2WithHandshakeContext(dialCtx, "tcp", tcpLn.Addr().String(), p.initiatorConfig)

	var res responderResult
	select {
	case res = <-responderDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for responder handshake (initiator error: %v)", dialErr)
	}

	// Report both sides together: when one fails the other's error is the cause.
	if dialErr != nil || res.err != nil {
		if initiator != nil {
			initiator.Close()
		}
		if res.conn != nil {
			res.conn.Close()
		}
		require.FailNowf(t, "NTCP2 handshake failed",
			"initiator dial: %v\nresponder executeHandshake: %v", dialErr, res.err)
	}
	defer initiator.Close()
	defer res.conn.Close()

	// Reaching the data phase proves the established flag was set and both sides
	// derived matching keys — neither holds under the generic Noise handshake.
	payload := []byte("ntcp2-wire-handshake")
	_, err = initiator.Write(payload)
	require.NoError(t, err, "initiator data-phase write")

	buf := make([]byte, 1024)
	require.NoError(t, res.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := res.conn.Read(buf)
	require.NoError(t, err, "responder data-phase read must succeed once established")
	assert.Equal(t, payload, buf[:n], "responder must decrypt the initiator's message")

	assert.NotEmpty(t, res.conn.PeerRouterInfoBytes(),
		"NTCP2 wire handshake must capture the peer's message 3 RouterInfo")
}
