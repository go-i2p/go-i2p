// Package config provides configuration structures and defaults for go-i2p.
package config

import "time"

// CongestionDefaults contains default values for congestion advertisement (Prop 162).
// These settings control when the router advertises D/E/G congestion flags in its
// RouterInfo caps, and how to derate congested peers during tunnel building.
//
// The congestion cap system provides three levels:
//   - D (Medium): Router is experiencing elevated load but still functional
//   - E (High): Router is near capacity, rejecting most tunnel requests
//   - G (Critical): Router is rejecting ALL tunnel requests (temporary or permanent)
//
// Spec: https://geti2p.net/spec/proposals/162-congestion-caps
type CongestionDefaults struct {
	// === Flag Advertisement Thresholds ===
	// These thresholds determine when to advertise D/E/G flags based on
	// the ratio of current participating tunnels to max participating tunnels.
	// Values should maintain: DFlagThreshold < EFlagThreshold < GFlagThreshold

	// DFlagThreshold is the participating tunnel ratio to advertise D flag.
	// When current/max ratio exceeds this, advertise medium congestion.
	// Default: 0.70 (70% of max participating tunnels)
	DFlagThreshold float64

	// EFlagThreshold is the participating tunnel ratio to advertise E flag.
	// When current/max ratio exceeds this, advertise high congestion.
	// Default: 0.85 (85% of max participating tunnels)
	EFlagThreshold float64

	// GFlagThreshold is the participating tunnel ratio to advertise G flag.
	// When current/max ratio exceeds this, advertise critical congestion.
	// Default: 1.00 (100% = at max participating tunnels)
	GFlagThreshold float64

	// === Hysteresis Thresholds ===
	// These prevent flag flapping by requiring the ratio to drop below a
	// clear threshold before removing a flag. This prevents oscillation
	// when load hovers around a boundary.
	// Values should maintain: ClearDFlag < DFlag, ClearEFlag < EFlag, ClearGFlag < GFlag

	// ClearDFlagThreshold is the ratio to clear D flag and return to normal.
	// Default: 0.60 (60% of max)
	ClearDFlagThreshold float64

	// ClearEFlagThreshold is the ratio to clear E flag (downgrade to D or clear).
	// Default: 0.75 (75% of max)
	ClearEFlagThreshold float64

	// ClearGFlagThreshold is the ratio to clear G flag (downgrade to E).
	// Default: 0.95 (95% of max)
	ClearGFlagThreshold float64

	// === Averaging Window ===

	// AveragingWindow is the duration over which to average congestion metrics.
	// Per spec, congestion state should be based on an average over several minutes,
	// not instantaneous measurement, to prevent rapid flag changes.
	// Default: 5 minutes (per spec recommendation)
	AveragingWindow time.Duration

	// === RouterInfo Age Threshold ===

	// EFlagAgeThreshold is when E flag is treated as D due to stale RouterInfo.
	// If a remote peer's RouterInfo is older than this and has E flag,
	// treat it as D flag instead (assume congestion may have cleared).
	// Default: 15 minutes (per spec)
	EFlagAgeThreshold time.Duration

	// === Peer Selection Derating ===
	// When building tunnels, peers with congestion flags have their apparent
	// capacity reduced by these multipliers. This makes them less likely to
	// be selected, but doesn't exclude them entirely (except G flag).

	// DFlagCapacityMultiplier is the capacity multiplier for D-flagged peers.
	// A value of 0.5 means D-flagged peers appear to have 50% of normal capacity.
	// Default: 0.5
	DFlagCapacityMultiplier float64

	// EFlagCapacityMultiplier is the capacity multiplier for E-flagged peers.
	// A value of 0.1 means E-flagged peers appear to have 10% of normal capacity.
	// Default: 0.1 (severely degraded)
	EFlagCapacityMultiplier float64

	// StaleEFlagCapacityMultiplier is the multiplier for E-flagged peers with old RouterInfo.
	// When RouterInfo is older than EFlagAgeThreshold, use this instead of EFlagCapacityMultiplier.
	// Per spec, stale E flags should be treated as D flags.
	// Default: 0.5 (same as D flag)
	StaleEFlagCapacityMultiplier float64
}

// CongestionFlag represents a congestion level flag.
type CongestionFlag string

const (
	// CongestionFlagNone indicates no congestion (normal operation).
	CongestionFlagNone CongestionFlag = ""

	// CongestionFlagD indicates medium congestion or low-performance router.
	// Tunnel creators should downgrade/limit apparent tunnel capacity in profile.
	CongestionFlagD CongestionFlag = "D"

	// CongestionFlagE indicates high congestion, near or at some limit.
	// Tunnel creators should severely downgrade capacity if RI < 15 min old,
	// or treat as D if RI > 15 min old.
	CongestionFlagE CongestionFlag = "E"

	// CongestionFlagG indicates rejecting ALL tunnels (temporary or permanent).
	// Tunnel creators should NOT build tunnels through this router.
	CongestionFlagG CongestionFlag = "G"
)

// CongestionLevel returns the numeric level for the flag (0=none, 1=D, 2=E, 3=G).
func (f CongestionFlag) CongestionLevel() int {
	switch f {
	case CongestionFlagD:
		return 1
	case CongestionFlagE:
		return 2
	case CongestionFlagG:
		return 3
	default:
		return 0
	}
}

// String returns the string representation of the congestion flag.
func (f CongestionFlag) String() string {
	return string(f)
}

// buildCongestionDefaults creates default congestion configuration values.
// These values are based on the PROP_162 specification recommendations.
func buildCongestionDefaults() CongestionDefaults {
	return CongestionDefaults{
		// Flag advertisement thresholds
		DFlagThreshold: 0.70,
		EFlagThreshold: 0.85,
		GFlagThreshold: 1.00,

		// Hysteresis thresholds (10-15% below advertisement thresholds)
		ClearDFlagThreshold: 0.60,
		ClearEFlagThreshold: 0.75,
		ClearGFlagThreshold: 0.95,

		// Averaging window per spec recommendation
		AveragingWindow: 5 * time.Minute,

		// RouterInfo age threshold per spec
		EFlagAgeThreshold: 15 * time.Minute,

		// Peer selection derating multipliers
		DFlagCapacityMultiplier:      0.5,
		EFlagCapacityMultiplier:      0.1,
		StaleEFlagCapacityMultiplier: 0.5,
	}
}

// ParseCongestionFlag parses a caps string and extracts the congestion flag if present.
// Returns CongestionFlagNone if no congestion flag is found.
// Checks for D, E, G flags in priority order (G > E > D).
func ParseCongestionFlag(caps string) CongestionFlag {
	if containsFlag(caps, 'G') {
		return CongestionFlagG
	}
	if containsFlag(caps, 'E') {
		return CongestionFlagE
	}
	if containsFlag(caps, 'D') {
		return CongestionFlagD
	}
	return CongestionFlagNone
}

// containsFlag checks if a caps string contains the specified flag character.
func containsFlag(caps string, flag rune) bool {
	for _, r := range caps {
		if r == flag {
			return true
		}
	}
	return false
}
