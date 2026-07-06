package router

import (
	"strings"

	"github.com/go-i2p/go-i2p/lib/config"
)

var tierRanks = map[string]int{
	"K": 0,
	"L": 1,
	"M": 2,
	"N": 3,
	"O": 4,
	"P": 5,
	"X": 6,
}

func normalizeConfiguredTier(tier string) string {
	tier = strings.ToUpper(strings.TrimSpace(tier))
	if _, ok := tierRanks[tier]; ok {
		return tier
	}
	return ""
}

// resolveRouterBandwidthTier returns the RouterInfo bandwidth capability letter
// (K/L/M/N/O/P/X) for this router.
//
// Precedence:
// 1. Use explicitly configured router.bandwidth_tier when valid.
// 2. Otherwise derive from configured bandwidth and session limits.
func resolveRouterBandwidthTier(cfg *config.RouterConfig) string {
	if cfg == nil {
		return ""
	}
	if explicit := normalizeConfiguredTier(cfg.BandwidthTier); explicit != "" {
		return explicit
	}

	tier := deriveTierFromBandwidth(cfg.MaxBandwidth)
	return promoteTierBySessionLimit(tier, effectiveSessionLimit(cfg))
}

func deriveTierFromBandwidth(maxBandwidthBytesPerSec uint64) string {
	const (
		kb = uint64(1024)
	)

	// Unlimited bandwidth is handled as high-capacity and then refined by
	// session-limit promotion logic.
	if maxBandwidthBytesPerSec == 0 {
		return "O"
	}

	switch {
	case maxBandwidthBytesPerSec < 12*kb:
		return "K"
	case maxBandwidthBytesPerSec < 48*kb:
		return "L"
	case maxBandwidthBytesPerSec < 64*kb:
		return "M"
	case maxBandwidthBytesPerSec < 128*kb:
		return "N"
	case maxBandwidthBytesPerSec < 256*kb:
		return "O"
	case maxBandwidthBytesPerSec < 2048*kb:
		return "P"
	default:
		return "X"
	}
}

func effectiveSessionLimit(cfg *config.RouterConfig) int {
	if cfg == nil {
		return 0
	}

	minPositive := 0
	consider := func(v int) {
		if v <= 0 {
			return
		}
		if minPositive == 0 || v < minPositive {
			minPositive = v
		}
	}

	consider(cfg.MaxConnections)
	if cfg.Transport != nil {
		consider(cfg.Transport.NTCP2MaxConnections)
	}

	return minPositive
}

func promoteTierBySessionLimit(base string, limit int) string {
	if limit <= 0 {
		return base
	}

	target := ""
	switch {
	case limit >= 4096:
		target = "X"
	case limit >= 1024:
		target = "P"
	case limit >= 512:
		target = "O"
	}

	if target == "" {
		return base
	}
	if tierRanks[target] > tierRanks[base] {
		return target
	}
	return base
}
