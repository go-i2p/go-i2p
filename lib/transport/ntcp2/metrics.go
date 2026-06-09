package ntcp2

import "sync/atomic"

// transportMetrics holds atomic counters for transport health and lifecycle events.
// All fields are accessed atomically; do not copy this struct.
type transportMetrics struct {
	staleSessionsReconciled atomic.Uint64 // A-3: how many Close() operations found non-zero stale sessions
}

// TransportMetricsSnapshot is a point-in-time copy of all transport metric counters.
type TransportMetricsSnapshot struct {
	// StaleSessionsReconciled is the number of times Close() found non-zero
	// stale sessions during final reconciliation. This should always be 0
	// when session accounting is correct (A-3 fix). Non-zero indicates
	// accounting drift bugs (typically from A-1, A-2, X-2, X-3 issues).
	StaleSessionsReconciled uint64
}

// GetTransportMetrics returns a point-in-time snapshot of all
// transport metric counters for monitoring and diagnostics.
func (t *NTCP2Transport) GetTransportMetrics() TransportMetricsSnapshot {
	return TransportMetricsSnapshot{
		StaleSessionsReconciled: t.metrics.staleSessionsReconciled.Load(),
	}
}
