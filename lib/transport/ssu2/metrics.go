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

	// Inbound pre-authentication handshake path (finding 005).
	handshakeRefusedGlobal      atomic.Uint64 // inbound connections closed for exceeding the transport-wide handshake budget
	handshakeRefusedSource      atomic.Uint64 // inbound connections closed for exceeding the per-source handshake budget
	inboundHandshakeFailures    atomic.Uint64 // responder handshakes that failed or timed out
	handshakeWatchdogsFired     atomic.Uint64 // failed handshakes whose go-noise destroy wait was cut short by the worker watchdog
	inboundHandshakeSuccess     atomic.Uint64 // responder handshakes completed and delivered to Accept()
	queueSendTimeouts           atomic.Uint64 // handshakes that timed out sending to the pendingConns queue
	maxPendingConnsQueueDepth   atomic.Uint64 // maximum observed depth of the pendingConns queue
	pendingConnsQueueFullEvents atomic.Uint64 // times a send was attempted with the queue full
}

// ReachabilitySnapshot is a point-in-time copy of all reachability counters.
// It is returned by GetReachabilityCounters for monitoring and diagnostics,
// letting operators see how NAT traversal and peer testing are performing.
// See also [SSU2Transport].
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

	// HandshakeRefusedGlobal counts inbound connections closed because the
	// transport-wide pre-authentication handshake budget was already spent.
	// Non-zero means something is flooding the router; the connections were
	// shed without paying for a handshake.
	HandshakeRefusedGlobal uint64

	// HandshakeRefusedSource counts inbound connections closed because one
	// source IP already held its share of the handshake budget.
	HandshakeRefusedSource uint64

	// InboundHandshakeFailures counts responder handshakes that failed or
	// timed out. A peer that sends a SessionRequest and never completes the
	// exchange shows up here.
	InboundHandshakeFailures uint64

	// InboundHandshakeSuccess counts responder handshakes completed and
	// delivered to Accept(). Zero with non-zero failures means inbound SSU2 is
	// not working at all.
	InboundHandshakeSuccess uint64

	// HandshakeWatchdogsFired counts failed handshakes where the worker had to
	// cancel go-noise's Termination destroy wait so the connection's handshake
	// slot came back promptly instead of 11 s later. Non-zero is normal under
	// probing; a value that keeps climbing while InboundHandshakeSuccess stays
	// zero means peers are sending SessionRequests they never finish.
	HandshakeWatchdogsFired uint64

	// QueueSendTimeouts counts inbound handshakes that timed out trying to
	// hand their connection to the pending queue. High values mean the Accept()
	// consumer is slow or stopped.
	QueueSendTimeouts uint64

	// MaxPendingConnsQueueDepth is the maximum observed depth of the inbound
	// pending queue, used for capacity planning.
	MaxPendingConnsQueueDepth uint64

	// PendingConnsQueueFullEvents counts inbound handshakes that attempted to
	// deliver to a full pending queue.
	PendingConnsQueueFullEvents uint64

	// InflightHandshakes is how many inbound responder handshakes are running
	// right now.
	InflightHandshakes int64

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
		HandshakeRefusedGlobal:       t.reachMetrics.handshakeRefusedGlobal.Load(),
		HandshakeRefusedSource:       t.reachMetrics.handshakeRefusedSource.Load(),
		InboundHandshakeFailures:     t.reachMetrics.inboundHandshakeFailures.Load(),
		InboundHandshakeSuccess:      t.reachMetrics.inboundHandshakeSuccess.Load(),
		HandshakeWatchdogsFired:      t.reachMetrics.handshakeWatchdogsFired.Load(),
		QueueSendTimeouts:            t.reachMetrics.queueSendTimeouts.Load(),
		MaxPendingConnsQueueDepth:    t.reachMetrics.maxPendingConnsQueueDepth.Load(),
		PendingConnsQueueFullEvents:  t.reachMetrics.pendingConnsQueueFullEvents.Load(),
		InflightHandshakes:           t.admission.current(),
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
