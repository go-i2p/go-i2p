package netdb

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Peer reliability threshold constants
// ──────────────────────────────────────────────────────────────────────────────

// LowSuccessRateThreshold is the success rate below which a peer is
// considered stale. Used by PeerTracker.IsLikelyStale.
const LowSuccessRateThreshold = 0.25

// HighSuccessRateThreshold is the success rate above which a peer is
// considered reliable. Used by PeerTracker.GetReliablePeers.
const HighSuccessRateThreshold = 0.75

// MinAttemptsForStats is the minimum number of connection attempts
// before a peer's success rate is considered statistically meaningful.
const MinAttemptsForStats = 5

// ConsecutiveFailThreshold is the number of consecutive failures that
// triggers automatic staleness classification.
const ConsecutiveFailThreshold = 3

// EMAAlpha is the exponential moving average smoothing factor used
// for response time tracking. A value of 0.2 gives new samples 20%
// weight, providing a stable average that smoothly adapts to changing
// network conditions without being overly reactive to outliers.
const EMAAlpha = 0.2

// StalenessCheckWindow is the lookback window for the "recent failures
// without recent success" staleness check in PeerTracker.
const StalenessCheckWindow = 1 * time.Hour
