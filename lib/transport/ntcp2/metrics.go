package ntcp2

import "sync/atomic"

// transportMetrics holds atomic counters for transport health and lifecycle events.
// All fields are accessed atomically; do not copy this struct.
type transportMetrics struct {
	staleSessionsReconciled     atomic.Uint64 // A-3: how many Close() operations found non-zero stale sessions
	queueSendTimeouts           atomic.Uint64 // TE-2: how many inbound handshakes timed out sending to pendingConns queue
	maxPendingConnsQueueDepth   atomic.Uint64 // TE-2: maximum observed depth of pendingConns queue (for capacity planning)
	pendingConnsQueueFullEvents atomic.Uint64 // TE-2: how many times send attempted with full queue

	// Session-level churn counters (process-wide aggregate across all NTCP2Session
	// instances, including those created outside NTCP2Transport).
	sessionEOFCloses        atomic.Uint64
	sessionTimeoutOrReset   atomic.Uint64
	sessionRecvBackpressure atomic.Uint64
}

// TransportMetricsSnapshot is a point-in-time copy of all transport metric counters.
type TransportMetricsSnapshot struct {
	// StaleSessionsReconciled is the number of times Close() found non-zero
	// stale sessions during final reconciliation. This should always be 0
	// when session accounting is correct (A-3 fix). Non-zero indicates
	// accounting drift bugs (typically from A-1, A-2, X-2, X-3 issues).
	StaleSessionsReconciled uint64

	// QueueSendTimeouts is the number of inbound handshakes that timed out
	// trying to send their connection to the pendingConns queue (TE-2 metric).
	// High values indicate Accept() consumer is slow or blocked.
	QueueSendTimeouts uint64

	// MaxPendingConnsQueueDepth is the maximum observed length of the
	// pendingConns channel (0-64). Used for capacity planning and detecting
	// sustained queue pressure under load.
	MaxPendingConnsQueueDepth uint64

	// PendingConnsQueueFullEvents is the number of times an inbound handshake
	// attempted to send to a full queue (len=64). High values indicate queue
	// capacity should be increased or Accept() throughput optimized.
	PendingConnsQueueFullEvents uint64

	// SessionEOFCloses counts receive-loop terminations due to EOF.
	SessionEOFCloses uint64

	// SessionTimeoutOrReset counts receive-loop terminations due to read timeout
	// or connection reset by peer.
	SessionTimeoutOrReset uint64

	// SessionRecvBackpressure counts dropped inbound messages due to full
	// receive channel backpressure in NTCP2Session.
	SessionRecvBackpressure uint64
}

// GetTransportMetrics returns a point-in-time snapshot of all
// transport metric counters for monitoring and diagnostics.
func (t *NTCP2Transport) GetTransportMetrics() TransportMetricsSnapshot {
	return TransportMetricsSnapshot{
		StaleSessionsReconciled:     t.metrics.staleSessionsReconciled.Load(),
		QueueSendTimeouts:           t.metrics.queueSendTimeouts.Load(),
		MaxPendingConnsQueueDepth:   t.metrics.maxPendingConnsQueueDepth.Load(),
		PendingConnsQueueFullEvents: t.metrics.pendingConnsQueueFullEvents.Load(),
		SessionEOFCloses:            globalNTCP2SessionChurn.sessionEOFCloses.Load(),
		SessionTimeoutOrReset:       globalNTCP2SessionChurn.sessionTimeoutOrReset.Load(),
		SessionRecvBackpressure:     globalNTCP2SessionChurn.sessionRecvBackpressure.Load(),
	}
}

func recordSessionEOFClose() {
	globalNTCP2SessionChurn.sessionEOFCloses.Add(1)
}

func recordSessionTimeoutOrReset() {
	globalNTCP2SessionChurn.sessionTimeoutOrReset.Add(1)
}

func recordSessionRecvBackpressure() {
	globalNTCP2SessionChurn.sessionRecvBackpressure.Add(1)
}

var globalNTCP2SessionChurn transportMetrics
