package ssu2

import (
	"sync"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
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
	tr := &SSU2Transport{logger: logger.WithField("component", "ssu2_test")}
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

var _ transport.PeerConnNotifier = (*testPeerConnNotifier)(nil)
