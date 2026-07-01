package ntcp2

import (
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
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
