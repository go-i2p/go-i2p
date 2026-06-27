package netdb

import "time"

// Peer profile persistence configuration.

// PeerProfileFileName is the filename used to persist peer tracking
// statistics to disk. The file is stored in the NetDB directory.
const PeerProfileFileName = "peer_profiles.json"

// DefaultPeerProfileExpiration is how long a peer profile entry survives
// without any new activity before it is discarded on load. Matches i2pd's
// PEER_PROFILE_EXPIRATION_TIMEOUT (36 hours).
const DefaultPeerProfileExpiration = 36 * time.Hour

// DefaultPeerProfilePersistInterval is how often the PeerTracker saves
// its in-memory statistics to disk during normal operation.
const DefaultPeerProfilePersistInterval = 5 * time.Minute

// Peer reliability threshold constants.

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
