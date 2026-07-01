package ntcp2

import (
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPeerConnNotifier struct {
	attempts   int
	successes  int
	failures   int
	permanent  int
	lastReason string
}

type testRouterInfoRefresher struct {
	count int
	hash  data.Hash
}

func (r *testRouterInfoRefresher) RequestRouterInfoRefresh(hash data.Hash) {
	r.count++
	r.hash = hash
}

func (n *testPeerConnNotifier) RecordAttempt(_ data.Hash) {
	n.attempts++
}

func (n *testPeerConnNotifier) RecordSuccess(_ data.Hash, _ int64) {
	n.successes++
}

func (n *testPeerConnNotifier) RecordFailure(_ data.Hash, reason string) {
	n.failures++
	n.lastReason = reason
}

func (n *testPeerConnNotifier) RecordPermanentFailure(_ data.Hash, reason string) {
	n.permanent++
	n.lastReason = reason
}

type handoffTimeoutConn struct {
	*acceptMockConn
	closed chan struct{}
}

func newHandoffTimeoutConn(remoteAddr string) *handoffTimeoutConn {
	return &handoffTimeoutConn{
		acceptMockConn: newAcceptMockConn(remoteAddr),
		closed:         make(chan struct{}),
	}
}

func (c *handoffTimeoutConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return c.acceptMockConn.Close()
}

func makeRouterInfoWithNTCP2StaticKey(t *testing.T, staticKey []byte) router_info.RouterInfo {
	t.Helper()
	addrCfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "NTCP2",
		Options: map[string]string{
			"s": i2pbase64.I2PEncoding.EncodeToString(staticKey),
		},
	}
	return *testutil.CreateSignedTestRouterInfo(t, nil, addrCfg)
}

func TestUpdateLocalRouterInfo_DoesNotReplaceIdentityOnStaticKeyMismatch(t *testing.T) {
	transport := createTransportPB2(t)
	defer transport.Close()

	beforeIdentity := transport.identity

	mismatchedKey := make([]byte, 32)
	for i := range mismatchedKey {
		mismatchedKey[i] = byte(200 + i)
	}

	oldCfg := transport.config.Load()
	require.NotNil(t, oldCfg)
	newCfg := *oldCfg
	newCfg.Config.StaticKey = make([]byte, 32)
	for i := range newCfg.Config.StaticKey {
		newCfg.Config.StaticKey[i] = byte(i)
	}
	transport.config.Store(&newCfg)

	transport.UpdateLocalRouterInfo(makeRouterInfoWithNTCP2StaticKey(t, mismatchedKey))

	assert.Equal(t, beforeIdentity, transport.identity, "mismatched RouterInfo must not replace the live identity")
}

func TestHandleDialFailure_ClassifierUsesPermanentFailureForInvalidNTCP2Data(t *testing.T) {
	transport, _ := newMinimalTransport()
	defer transport.Close()

	notifier := &testPeerConnNotifier{}
	transport.SetPeerConnNotifier(notifier)

	var routerHash data.Hash
	for i := range routerHash {
		routerHash[i] = byte(i + 1)
	}

	transport.handleDialFailure(routerHash, routerHash, ErrInvalidRouterInfo)
	transport.handleDialFailure(routerHash, routerHash, ErrNTCP2NotSupported)
	transport.handleDialFailure(routerHash, routerHash, assert.AnError)

	assert.Equal(t, 2, notifier.permanent, "structural NTCP2 failures should be permanent")
	assert.Equal(t, 1, notifier.failures, "non-structural failures should remain transient")
}

func TestHandleDialFailure_RequestsRouterInfoRefreshOnHandshakeRejectPatterns(t *testing.T) {
	transport, _ := newMinimalTransport()
	defer transport.Close()

	refresher := &testRouterInfoRefresher{}
	transport.SetRouterInfoRefresher(refresher)

	var routerHash data.Hash
	for i := range routerHash {
		routerHash[i] = byte(i + 11)
	}

	transport.handleDialFailure(routerHash, routerHash, oops.Errorf("EOF"))
	assert.Equal(t, 1, refresher.count, "EOF handshake rejections should trigger RouterInfo refresh")
	assert.Equal(t, routerHash, refresher.hash)

	transport.handleDialFailure(routerHash, routerHash, oops.Errorf("read: connection reset by peer"))
	assert.Equal(t, 2, refresher.count, "connection reset should trigger RouterInfo refresh")

	transport.handleDialFailure(routerHash, routerHash, oops.Errorf("context canceled"))
	assert.Equal(t, 2, refresher.count, "cancellation should not trigger RouterInfo refresh")
}

func TestInboundHandshakeWorker_UsesConfiguredPendingQueueTimeout(t *testing.T) {
	transport := newTestTransport(newMockListener(), 1)
	transport.pendingConns = make(chan net.Conn, 1)
	transport.pendingConns <- newAcceptMockConn("10.0.0.9:9000")
	transport.testBypassHandshakeTypeCheck = true

	cfg := transport.config.Load()
	require.NotNil(t, cfg)
	newCfg := *cfg
	newCfg.PendingConnQueueTimeout = 25 * time.Millisecond
	transport.config.Store(&newCfg)

	conn := newHandoffTimeoutConn("10.0.0.10:9001")
	done := make(chan struct{})
	go func() {
		transport.inboundHandshakeWorker(conn)
		close(done)
	}()

	select {
	case <-conn.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("expected inbound handoff timeout to close the connection")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected inboundHandshakeWorker to exit after queue timeout")
	}

	assert.Equal(t, int32(0), transport.GetSessionCount(), "timed-out handoff should release the reserved session slot")
	assert.Equal(t, uint64(1), transport.metrics.queueSendTimeouts.Load(), "timeout metric should increment")
	assert.Equal(t, 1, len(transport.pendingConns), "pre-existing pending connection should remain queued")
}
