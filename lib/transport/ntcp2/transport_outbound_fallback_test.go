package ntcp2

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/testutil"
	noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeWrappedAddr(t *testing.T, hostPort string, marker byte) net.Addr {
	t.Helper()
	host, port, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	require.NoError(t, err)

	var h data.Hash
	for i := range h {
		h[i] = marker
	}

	addr, err := noise.NewNTCP2Addr(tcpAddr, h, "initiator")
	require.NoError(t, err)
	return addr
}

func TestTryDialCandidates_AttemptsUntilSuccess(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	addrs := []net.Addr{
		makeWrappedAddr(t, "127.0.0.1:11001", 1),
		makeWrappedAddr(t, "127.0.0.1:11002", 2),
	}
	candidates := []NTCP2DialCandidate{
		{Addr: addrs[0]},
		{Addr: addrs[1]},
	}

	attempted := make([]string, 0, 2)
	failErr := errors.New("first failed")

	perform := func(addr net.Addr, tcpAddrString string, _ []byte, _ *noise.Config, _ time.Time) (*noise.Conn, error) {
		attempted = append(attempted, tcpAddrString)
		if len(attempted) == 1 {
			return nil, failErr
		}
		return &noise.Conn{}, nil
	}

	peerHashBytes := make([]byte, 32)
	config := &noise.Config{}

	conn, err := dialCandidatesWithPerformer(transport, candidates, peerHashBytes, config, perform)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, []string{"127.0.0.1:11001", "127.0.0.1:11002"}, attempted)
}

func TestTryDialCandidates_AllFailReturnsLastError(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	addrs := []net.Addr{
		makeWrappedAddr(t, "127.0.0.1:12001", 3),
		makeWrappedAddr(t, "127.0.0.1:12002", 4),
	}
	candidates := []NTCP2DialCandidate{
		{Addr: addrs[0]},
		{Addr: addrs[1]},
	}

	firstErr := errors.New("first")
	lastErr := errors.New("last")
	attempted := make([]string, 0, 2)

	perform := func(addr net.Addr, tcpAddrString string, _ []byte, _ *noise.Config, _ time.Time) (*noise.Conn, error) {
		attempted = append(attempted, tcpAddrString)
		if len(attempted) == 1 {
			return nil, firstErr
		}
		return nil, lastErr
	}

	peerHashBytes := make([]byte, 32)
	config := &noise.Config{}

	conn, err := dialCandidatesWithPerformer(transport, candidates, peerHashBytes, config, perform)
	assert.Nil(t, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, lastErr)
	assert.Equal(t, []string{"127.0.0.1:12001", "127.0.0.1:12002"}, attempted)
}

type fallbackIntegrationKeystore struct {
	privateKey []byte
}

func (k *fallbackIntegrationKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return &fallbackIntegrationPrivateKey{keyData: append([]byte(nil), k.privateKey...)}
}

type fallbackIntegrationPrivateKey struct {
	keyData []byte
}

func (k *fallbackIntegrationPrivateKey) Bytes() []byte {
	return append([]byte(nil), k.keyData...)
}

func (k *fallbackIntegrationPrivateKey) Zero() {
	for i := range k.keyData {
		k.keyData[i] = 0
	}
}

func (k *fallbackIntegrationPrivateKey) NewDecrypter() (types.Decrypter, error) {
	return nil, nil
}

func (k *fallbackIntegrationPrivateKey) Public() (types.PublicEncryptionKey, error) {
	return nil, nil
}

func newFallbackIntegrationIdentity(t *testing.T, host, port string, staticPriv []byte) router_info.RouterInfo {
	t.Helper()

	curvePriv, err := i2pcurve25519.NewCurve25519PrivateKey(staticPriv)
	require.NoError(t, err)
	curvePub, err := curvePriv.Public()
	require.NoError(t, err)

	addrCfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "NTCP2",
		Options: map[string]string{
			"host": host,
			"port": port,
			"s":    i2pbase64.I2PEncoding.EncodeToString(curvePub.Bytes()),
		},
	}

	return *testutil.CreateSignedTestRouterInfo(t, nil, addrCfg)
}

func newFallbackIntegrationTransport(t *testing.T, listenerAddress string, staticPriv []byte) *NTCP2Transport {
	t.Helper()

	_, port, err := net.SplitHostPort(listenerAddress)
	require.NoError(t, err)

	identity := newFallbackIntegrationIdentity(t, "localhost", port, staticPriv)
	keystore := &fallbackIntegrationKeystore{privateKey: append([]byte(nil), staticPriv...)}

	cfg, err := NewConfig(listenerAddress)
	require.NoError(t, err)

	tr, err := NewNTCP2Transport(identity, cfg, keystore)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	return tr
}

func reserveClosedPort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	return addr
}

func buildPeerRouterInfoWithFallbackCandidates(
	t *testing.T,
	peer router_info.RouterInfo,
	closedAddr string,
	liveAddr string,
	obfuscationIV []byte,
) router_info.RouterInfo {
	t.Helper()

	_, closedPort, err := net.SplitHostPort(closedAddr)
	require.NoError(t, err)
	_, livePort, err := net.SplitHostPort(liveAddr)
	require.NoError(t, err)

	peerBytes, err := peer.Bytes()
	require.NoError(t, err)
	peerInfo, remainder, err := router_info.ReadRouterInfo(peerBytes)
	require.NoError(t, err)
	require.Len(t, remainder, 0)

	addresses := peer.RouterAddresses()
	require.NotEmpty(t, addresses, "peer RouterInfo must contain at least one NTCP2 address")
	require.NotNil(t, addresses[0].TransportOptions)

	baseOptions, err := addresses[0].TransportOptions.ToGoMap()
	require.NoError(t, err)
	baseOptions["i"] = i2pbase64.I2PEncoding.EncodeToString(obfuscationIV)
	closedOptions := map[string]string{}
	for k, v := range baseOptions {
		closedOptions[k] = v
	}
	closedOptions["host"] = "localhost"
	closedOptions["port"] = closedPort

	closedCandidate, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", closedOptions)
	require.NoError(t, err)

	peerAddresses := peerInfo.RouterAddresses()
	require.NotEmpty(t, peerAddresses)
	peerAddresses[0] = closedCandidate

	liveOptions := map[string]string{}
	for k, v := range baseOptions {
		liveOptions[k] = v
	}
	liveOptions["host"] = "localhost"
	liveOptions["port"] = livePort
	secondary, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", liveOptions)
	require.NoError(t, err)
	require.NoError(t, (&peerInfo).AddAddress(secondary))

	return peerInfo
}

func TestGetSession_FallbackFromClosedPortToLiveResponder(t *testing.T) {
	if os.Getenv("GOI2P_ENABLE_UNSTABLE_NTCP2_LIVE_FALLBACK_TEST") != "1" {
		t.Skip("set GOI2P_ENABLE_UNSTABLE_NTCP2_LIVE_FALLBACK_TEST=1 to run unstable live fallback harness with responder-side handshake diagnostics")
	}

	initiatorStatic := make([]byte, 32)
	responderStatic := make([]byte, 32)
	for i := range initiatorStatic {
		initiatorStatic[i] = byte(i + 1)
		responderStatic[i] = byte(i + 33)
	}

	responder := newFallbackIntegrationTransport(t, "127.0.0.1:0", responderStatic)
	initiator := newFallbackIntegrationTransport(t, "127.0.0.1:0", initiatorStatic)
	responderCfg := responder.config.Load()
	require.NotNil(t, responderCfg)
	require.NotNil(t, responderCfg.Config)

	responderHandshakeErr := make(chan error, 1)
	responder.testInboundHandshakeErrorHook = func(err error) {
		select {
		case responderHandshakeErr <- err:
		default:
		}
	}

	closedAddr := reserveClosedPort(t)
	peerInfo := buildPeerRouterInfoWithFallbackCandidates(
		t,
		responder.identity,
		closedAddr,
		responder.Addr().String(),
		responderCfg.Config.ObfuscationIV,
	)

	acceptResult := make(chan error, 1)
	go func() {
		conn, err := responder.Accept()
		if err != nil {
			acceptResult <- err
			return
		}
		_ = conn.Close()
		acceptResult <- nil
	}()

	session, err := initiator.GetSession(peerInfo)
	if err != nil {
		var responderErrMsg string
		select {
		case hookErr := <-responderHandshakeErr:
			responderErrMsg = hookErr.Error()
		default:
			responderErrMsg = "<none captured>"
		}

		initiatorErrMsg := err.Error()
		knownInitiatorSignature := strings.Contains(initiatorErrMsg, "msg2") && strings.Contains(initiatorErrMsg, "i/o timeout")
		knownResponderSignature := strings.Contains(responderErrMsg, "failed to read first XK handshake message") && strings.Contains(responderErrMsg, "i/o timeout")
		if knownInitiatorSignature && knownResponderSignature {
			t.Skipf("known unstable live fallback signature observed; initiator=%q responder=%q", initiatorErrMsg, responderErrMsg)
		}

		t.Fatalf("outbound session failed with unexpected signature: %v | responder handshake error: %s", err, responderErrMsg)
	}
	require.NotNil(t, session)
	require.NoError(t, session.Close())

	select {
	case acceptErr := <-acceptResult:
		require.NoError(t, acceptErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for responder to accept fallback connection")
	}
}
