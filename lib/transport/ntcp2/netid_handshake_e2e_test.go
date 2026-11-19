// Regression test for the transport-handshake network ID (netId).
//
// netdb.net_id was plumbed into the published RouterInfo and inbound NetDB
// validation, but NOT into the go-noise transport config, so a router on a
// non-mainline network (netId != 2) still wrote the mainline default of 2 into
// the NTCP2 message-1 options block. i2pd (and go-noise) then reject every
// session with "message 1 network ID 2 does not match local network ID 5",
// leaving no established transport sessions on any testnet.
//
// These tests build two transports the way lib/router does (NewNTCP2Transport
// from a signed RouterInfo whose netId option carries the configured network)
// and assert:
//   - matching non-default netId on both ends establishes a session (the fix);
//   - a mismatched netId is rejected on the wire (proves the field actually
//     carries the configured value, and that cross-network rejection works).

package ntcp2

import (
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/require"
)

// newNetIDIntegrationTransport builds a bound NTCP2 transport whose identity
// RouterInfo advertises the given netId, mirroring newFallbackIntegrationTransport
// but parameterizing the netId so the handshake networkID is derived from it.
func newNetIDIntegrationTransport(t *testing.T, listenerAddress string, staticPriv []byte, netID string) *NTCP2Transport {
	t.Helper()

	_, port, err := net.SplitHostPort(listenerAddress)
	require.NoError(t, err)

	curvePriv, err := i2pcurve25519.NewCurve25519PrivateKey(staticPriv)
	require.NoError(t, err)
	curvePub, err := curvePriv.Public()
	require.NoError(t, err)

	addrCfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "NTCP2",
		Options: map[string]string{
			"host": "localhost",
			"port": port,
			"s":    i2pbase64.I2PEncoding.EncodeToString(curvePub.Bytes()),
			// i= (obfuscation IV) is injected into the dial-target copy by
			// publishLiveNTCP2Address once the transport is bound.
			"v": "2",
		},
	}
	identity := *testutil.CreateSignedTestRouterInfo(t, map[string]string{"netId": netID}, addrCfg)

	keystore := &fallbackIntegrationKeystore{privateKey: append([]byte(nil), staticPriv...)}
	cfg, err := NewConfig(listenerAddress)
	require.NoError(t, err)

	tr, err := NewNTCP2Transport(identity, cfg, keystore)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	return tr
}

// newNetIDPeerPair builds two transports on loopback, both advertising netID.
func newNetIDPeerPair(t *testing.T, netID string) ntcp2PeerPair {
	t.Helper()

	privA := make([]byte, 32)
	privB := make([]byte, 32)
	for i := range privA {
		privA[i] = byte(i + 1)
		privB[i] = byte(i + 101)
	}

	a := newNetIDIntegrationTransport(t, "127.0.0.1:0", privA, netID)
	b := newNetIDIntegrationTransport(t, "127.0.0.1:0", privB, netID)

	return ntcp2PeerPair{
		a:   a,
		b:   b,
		aRI: publishLiveNTCP2Address(t, a),
		bRI: publishLiveNTCP2Address(t, b),
	}
}

// TestNTCP2HandshakeEstablishesOnNonDefaultNetID is the core regression: two
// routers on netId 5 must establish a session. Before the fix, both wrote
// networkID 2 into msg1 while each expected 5, so every session was rejected and
// no transport session ever came up on a testnet.
func TestNTCP2HandshakeEstablishesOnNonDefaultNetID(t *testing.T) {
	p := newNetIDPeerPair(t, "5")
	dialOneWay(t, p.a, p.b, p.bRI)
}

// TestNTCP2HandshakeRejectsNetIDMismatch proves the wire field actually carries
// the configured netId: a dialer on netId 5 reaching a responder still on the
// mainline default (2) must be rejected with a network-ID mismatch, exactly the
// i2pd behaviour the fix is meant to avoid on a matching network.
func TestNTCP2HandshakeRejectsNetIDMismatch(t *testing.T) {
	privA := make([]byte, 32)
	privB := make([]byte, 32)
	for i := range privA {
		privA[i] = byte(i + 1)
		privB[i] = byte(i + 101)
	}

	// Dialer advertises netId 5; responder stays on the default (2).
	dialer := newNetIDIntegrationTransport(t, "127.0.0.1:0", privA, "5")
	responder := newNetIDIntegrationTransport(t, "127.0.0.1:0", privB, "2")
	target := publishLiveNTCP2Address(t, responder)

	acceptErr := make(chan error, 1)
	go func() {
		_, err := responder.Accept()
		acceptErr <- err
	}()

	// The responder rejects msg1 on a network-ID mismatch and closes the
	// connection, so the dialer's error is a reset rather than the mismatch text
	// (which is logged on the responder). The decisive signal is that neither end
	// establishes a session — the same pair with matching netId does (test above).
	_, err := dialer.GetSession(target)
	require.Error(t, err, "a netId mismatch must fail the handshake")

	require.Eventually(t, func() bool {
		return responder.GetSessionCount() == 0 && dialer.GetSessionCount() == 0
	}, 3*time.Second, 50*time.Millisecond,
		"a netId mismatch must establish no session on either end")
}

// TestNTCP2InboundRequiresConfiguredNetID guards the responder (inbound) config
// site: a responder advertising netId 5 must REQUIRE 5 in msg1, so a dialer on
// the mainline default (2) is rejected. Before the fix the responder left its
// expected networkID at the default 2, so it would have accepted the netId-2
// dialer and mixed networks.
func TestNTCP2InboundRequiresConfiguredNetID(t *testing.T) {
	privA := make([]byte, 32)
	privB := make([]byte, 32)
	for i := range privA {
		privA[i] = byte(i + 1)
		privB[i] = byte(i + 101)
	}

	// Dialer on the default (2); responder on netId 5 now requires 5.
	dialer := newNetIDIntegrationTransport(t, "127.0.0.1:0", privA, "2")
	responder := newNetIDIntegrationTransport(t, "127.0.0.1:0", privB, "5")
	target := publishLiveNTCP2Address(t, responder)

	go func() {
		_, _ = responder.Accept()
	}()

	_, err := dialer.GetSession(target)
	require.Error(t, err, "a responder on netId 5 must reject a netId-2 initiator")

	require.Eventually(t, func() bool {
		return responder.GetSessionCount() == 0 && dialer.GetSessionCount() == 0
	}, 3*time.Second, 50*time.Millisecond,
		"a netId mismatch must establish no session on either end")
}
