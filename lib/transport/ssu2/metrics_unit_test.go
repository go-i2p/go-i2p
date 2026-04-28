package ssu2

// metrics_unit_test.go covers the reachability counter helpers.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetReachabilityCounters_ZeroOnNew verifies all counters start at zero
// for a freshly-constructed transport.
func TestGetReachabilityCounters_ZeroOnNew(t *testing.T) {
	tr := makeMinimalTransport()
	snap := tr.GetReachabilityCounters()
	assert.Equal(t, uint64(0), snap.NATMappingSuccess)
	assert.Equal(t, uint64(0), snap.NATMappingFailure)
	assert.Equal(t, uint64(0), snap.PeerTestConfirmed)
	assert.Equal(t, uint64(0), snap.PublishedAddrChanged)
}

// TestGetReachabilityCounters_NATMappingSuccess verifies that incrementing
// the success counter is reflected in the snapshot.
func TestGetReachabilityCounters_NATMappingSuccess(t *testing.T) {
	tr := makeMinimalTransport()
	tr.reachMetrics.natMappingSuccess.Add(3)
	snap := tr.GetReachabilityCounters()
	assert.Equal(t, uint64(3), snap.NATMappingSuccess)
	assert.Equal(t, uint64(0), snap.NATMappingFailure)
}

// TestGetReachabilityCounters_NATMappingFailure verifies the failure counter.
func TestGetReachabilityCounters_NATMappingFailure(t *testing.T) {
	tr := makeMinimalTransport()
	tr.reachMetrics.natMappingFailure.Add(5)
	snap := tr.GetReachabilityCounters()
	assert.Equal(t, uint64(0), snap.NATMappingSuccess)
	assert.Equal(t, uint64(5), snap.NATMappingFailure)
}

// TestGetReachabilityCounters_PeerTestConfirmed verifies the PeerTest counter.
func TestGetReachabilityCounters_PeerTestConfirmed(t *testing.T) {
	tr := makeMinimalTransport()
	tr.reachMetrics.peerTestConfirmed.Add(2)
	snap := tr.GetReachabilityCounters()
	assert.Equal(t, uint64(2), snap.PeerTestConfirmed)
}

// TestGetReachabilityCounters_PublishedAddrChanged verifies the publish counter.
func TestGetReachabilityCounters_PublishedAddrChanged(t *testing.T) {
	tr := makeMinimalTransport()
	tr.reachMetrics.publishedAddrChanged.Add(1)
	snap := tr.GetReachabilityCounters()
	assert.Equal(t, uint64(1), snap.PublishedAddrChanged)
}

// TestGetReachabilityCounters_Snapshot verifies that the snapshot is a copy,
// not a live reference — subsequent increments do not change the snapshot.
func TestGetReachabilityCounters_Snapshot(t *testing.T) {
	tr := makeMinimalTransport()
	tr.reachMetrics.natMappingSuccess.Add(1)
	snap := tr.GetReachabilityCounters()
	tr.reachMetrics.natMappingSuccess.Add(99)
	assert.Equal(t, uint64(1), snap.NATMappingSuccess, "snapshot should not reflect later increments")
}
