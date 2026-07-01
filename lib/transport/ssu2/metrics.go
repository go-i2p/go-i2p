package ssu2

import "sync/atomic"

// reachabilityMetrics holds atomic counters for reachability-related events.
// All fields are accessed atomically; do not copy this struct.
type reachabilityMetrics struct {
	natMappingSuccess       atomic.Uint64
	natMappingFailure       atomic.Uint64
	peerTestConfirmed       atomic.Uint64
	publishedAddrChanged    atomic.Uint64
	staleSessionsReconciled atomic.Uint64 // A-3: how many Close() operations found non-zero stale sessions
	replayChecksDeferred    atomic.Uint64 // deferred anti-replay checks due to unavailable SessionRequest replay token
}

// ReachabilitySnapshot is a point-in-time copy of all reachability counters.
type ReachabilitySnapshot struct {
	// NATMappingSuccess is the number of successful NAT-PMP/UPnP port mappings.
	NATMappingSuccess uint64
	// NATMappingFailure is the number of failed NAT-PMP/UPnP port map attempts.
	NATMappingFailure uint64
	// PeerTestConfirmed is the number of times an external address was
	// confirmed by the PeerTest majority-vote logic.
	PeerTestConfirmed uint64
	// PublishedAddrChanged is the number of times the RouterInfo was
	// republished because the confirmed external address changed.
	PublishedAddrChanged uint64
	// StaleSessionsReconciled is the number of times Close() found non-zero
	// stale sessions during final reconciliation. This should always be 0
	// when session accounting is correct (A-3 fix). Non-zero indicates
	// accounting drift bugs (typically from A-1, A-2, X-2, X-3 issues).
	StaleSessionsReconciled uint64
	// ReplayChecksDeferred is the number of inbound SSU2 connections where
	// anti-replay validation was deferred because SessionRequest replay
	// material was not yet available.
	ReplayChecksDeferred uint64

	// SessionPeerTerminations counts OnTermination callbacks received from peers.
	SessionPeerTerminations uint64

	// SessionReadTimeoutRetries counts receive-loop read timeouts that were
	// treated as retryable (non-fatal) in SSU2 sessions.
	SessionReadTimeoutRetries uint64

	// SessionRecvBackpressureDrops counts inbound messages dropped due to full
	// receive channel backpressure in SSU2Session.
	SessionRecvBackpressureDrops uint64
}

// GetReachabilityCounters returns a point-in-time snapshot of all
// reachability-related counters for monitoring and diagnostics.
func (t *SSU2Transport) GetReachabilityCounters() ReachabilitySnapshot {
	return ReachabilitySnapshot{
		NATMappingSuccess:            t.reachMetrics.natMappingSuccess.Load(),
		NATMappingFailure:            t.reachMetrics.natMappingFailure.Load(),
		PeerTestConfirmed:            t.reachMetrics.peerTestConfirmed.Load(),
		PublishedAddrChanged:         t.reachMetrics.publishedAddrChanged.Load(),
		StaleSessionsReconciled:      t.reachMetrics.staleSessionsReconciled.Load(),
		ReplayChecksDeferred:         t.reachMetrics.replayChecksDeferred.Load(),
		SessionPeerTerminations:      globalSSU2SessionChurn.sessionPeerTerminations.Load(),
		SessionReadTimeoutRetries:    globalSSU2SessionChurn.sessionReadTimeoutRetries.Load(),
		SessionRecvBackpressureDrops: globalSSU2SessionChurn.sessionRecvBackpressureDrops.Load(),
	}
}

type ssu2SessionChurnMetrics struct {
	sessionPeerTerminations      atomic.Uint64
	sessionReadTimeoutRetries    atomic.Uint64
	sessionRecvBackpressureDrops atomic.Uint64
}

func recordSSU2PeerTermination() {
	globalSSU2SessionChurn.sessionPeerTerminations.Add(1)
}

func recordSSU2ReadTimeoutRetry() {
	globalSSU2SessionChurn.sessionReadTimeoutRetries.Add(1)
}

func recordSSU2RecvBackpressureDrop() {
	globalSSU2SessionChurn.sessionRecvBackpressureDrops.Add(1)
}

var globalSSU2SessionChurn ssu2SessionChurnMetrics
