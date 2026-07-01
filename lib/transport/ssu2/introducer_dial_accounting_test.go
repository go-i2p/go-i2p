package ssu2

import (
	"errors"
	"sync"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPeerConnNotifier struct {
	mu               sync.Mutex
	attempts         int
	successes        int
	failures         int
	permanentFailure int
	lastFailure      string
}

func (n *testPeerConnNotifier) RecordAttempt(_ data.Hash) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.attempts++
}

func (n *testPeerConnNotifier) RecordSuccess(_ data.Hash, _ int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.successes++
}

func (n *testPeerConnNotifier) RecordFailure(_ data.Hash, reason string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failures++
	n.lastFailure = reason
}

func (n *testPeerConnNotifier) RecordPermanentFailure(_ data.Hash, reason string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.permanentFailure++
	n.lastFailure = reason
}

func testTransportForIntroducerDialAccounting() *SSU2Transport {
	l := logger.WithField("component", "ssu2_test")
	tr := &SSU2Transport{
		logger:          l,
		sessionRegistry: transport.NewSessionRegistry(l),
	}
	tr.config.Store(&Config{ListenerAddress: ":0"})
	tr.natManagersHealthy.Store(true)
	return tr
}

func TestDialViaIntroducer_RecordsAttemptAndFailure_WhenRouterLookupMissing(t *testing.T) {
	tr := testTransportForIntroducerDialAccounting()
	n := &testPeerConnNotifier{}
	tr.SetPeerConnNotifier(n)

	_, err := tr.dialViaIntroducer(router_info.RouterInfo{}, data.Hash{})
	require.Error(t, err)

	assert.Equal(t, 1, n.attempts)
	assert.Equal(t, 0, n.successes)
	assert.Equal(t, 1, n.failures)
	assert.Equal(t, 0, n.permanentFailure)
	assert.Contains(t, n.lastFailure, "RouterLookupFunc not configured")
}

func TestDialViaIntroducer_RecordsAttemptAndFailure_WhenNoIntroducers(t *testing.T) {
	tr := testTransportForIntroducerDialAccounting()
	tr.config.Store(&Config{
		ListenerAddress: ":0",
		RouterLookupFunc: func(hash data.Hash) (router_info.RouterInfo, error) {
			return router_info.RouterInfo{}, nil
		},
	})
	tr.natManagersHealthy.Store(true)

	n := &testPeerConnNotifier{}
	tr.SetPeerConnNotifier(n)

	_, err := tr.dialViaIntroducer(router_info.RouterInfo{}, data.Hash{})
	require.Error(t, err)

	assert.Equal(t, 1, n.attempts)
	assert.Equal(t, 0, n.successes)
	assert.Equal(t, 1, n.failures)
	assert.Equal(t, 0, n.permanentFailure)
	assert.Contains(t, n.lastFailure, "no valid introducers found")
}

func TestGetSession_UnreachablePeerReturnsInvalidRouterInfo(t *testing.T) {
	tr := testTransportForIntroducerDialAccounting()
	n := &testPeerConnNotifier{}
	tr.SetPeerConnNotifier(n)

	ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)

	_, err := tr.GetSession(*ri)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRouterInfo), "unreachable SSU2 peer should surface ErrInvalidRouterInfo")

	assert.Equal(t, 1, n.attempts)
	assert.Equal(t, 0, n.successes)
	assert.Equal(t, 0, n.failures)
	assert.Equal(t, 1, n.permanentFailure)
	assert.Contains(t, n.lastFailure, "no_reachable_ssu2_address")
}

func TestCollectIntroducers_KeepsDistinctRelayTagsForSameRouterHash(t *testing.T) {
	tr := testTransportForIntroducerDialAccounting()

	hashBytes := make([]byte, 32)
	for i := range hashBytes {
		hashBytes[i] = byte(i + 1)
	}
	hashB64 := i2pbase64.EncodeToString(hashBytes)

	addrCfg := testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "SSU2",
		Options: map[string]string{
			router_address.INTRODUCER_HASH_PREFIX + "0": hashB64,
			router_address.INTRODUCER_TAG_PREFIX + "0":  "1111",
			router_address.INTRODUCER_HASH_PREFIX + "1": hashB64,
			router_address.INTRODUCER_TAG_PREFIX + "1":  "2222",
		},
	}
	ri := testutil.CreateSignedTestRouterInfo(t, nil, &addrCfg)

	intros := tr.collectIntroducers(*ri)
	require.Len(t, intros, 2)
	assert.Equal(t, uint32(1111), intros[0].RelayTag)
	assert.Equal(t, uint32(2222), intros[1].RelayTag)
}

var _ transport.PeerConnNotifier = (*testPeerConnNotifier)(nil)
