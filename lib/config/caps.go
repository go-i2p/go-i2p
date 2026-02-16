package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-i2p/logger"
)

// BandwidthClass represents a single-letter bandwidth capability flag
// per the I2P common-structures specification.
//
// The bandwidth class is determined by the router's shared bandwidth limit
// and advertised in the RouterInfo caps string.
//
// Spec: https://geti2p.net/spec/common-structures#router-info
type BandwidthClass string

const (
	// BandwidthClassK indicates under 12 KB/s shared bandwidth.
	BandwidthClassK BandwidthClass = "K"

	// BandwidthClassL indicates 12–48 KB/s shared bandwidth.
	BandwidthClassL BandwidthClass = "L"

	// BandwidthClassM indicates 48–64 KB/s shared bandwidth.
	BandwidthClassM BandwidthClass = "M"

	// BandwidthClassN indicates 64–128 KB/s shared bandwidth.
	BandwidthClassN BandwidthClass = "N"

	// BandwidthClassO indicates 128–256 KB/s shared bandwidth.
	BandwidthClassO BandwidthClass = "O"

	// BandwidthClassP indicates 256–2000 KB/s shared bandwidth.
	BandwidthClassP BandwidthClass = "P"

	// BandwidthClassX indicates over 2000 KB/s shared bandwidth.
	BandwidthClassX BandwidthClass = "X"
)

// BandwidthClassFromRate returns the I2P bandwidth class letter for the
// given shared bandwidth in bytes per second.
//
// Per the I2P spec (common-structures.rst):
//
//   - K: < 12 KBps (< 12288 bytes/s)
//   - L: 12–48 KBps
//   - M: 48–64 KBps
//   - N: 64–128 KBps
//   - O: 128–256 KBps
//   - P: 256–2000 KBps
//   - X: >= 2000 KBps (>= 2048000 bytes/s)
func BandwidthClassFromRate(bytesPerSec uint64) BandwidthClass {
	kbps := bytesPerSec / 1024
	switch {
	case kbps >= 2000:
		return BandwidthClassX
	case kbps >= 256:
		return BandwidthClassP
	case kbps >= 128:
		return BandwidthClassO
	case kbps >= 64:
		return BandwidthClassN
	case kbps >= 48:
		return BandwidthClassM
	case kbps >= 12:
		return BandwidthClassL
	default:
		return BandwidthClassK
	}
}

// String returns the single-letter representation of the bandwidth class.
func (b BandwidthClass) String() string {
	return string(b)
}

// validCapsFlags is the set of all valid single-letter capability flags
// that may appear in a RouterInfo caps string.
//
// Spec references:
//   - common-structures.rst: K/L/M/N/O/P/X (bandwidth), R/U (reachability), f (floodfill), H (hidden)
//   - Proposal 162: D/E/G (congestion)
var validCapsFlags = map[rune]string{
	// Bandwidth class flags (exactly one required)
	'K': "bandwidth: under 12 KB/s",
	'L': "bandwidth: 12-48 KB/s",
	'M': "bandwidth: 48-64 KB/s",
	'N': "bandwidth: 64-128 KB/s",
	'O': "bandwidth: 128-256 KB/s",
	'P': "bandwidth: 256-2000 KB/s",
	'X': "bandwidth: over 2000 KB/s",

	// Reachability flags (exactly one required)
	'R': "reachable",
	'U': "unreachable",

	// Optional flags
	'f': "floodfill",
	'H': "hidden",

	// Congestion flags per Proposal 162 (at most one)
	'D': "congestion: medium",
	'E': "congestion: high",
	'G': "congestion: rejecting all tunnels",
}

// bandwidthFlags is the set of bandwidth class flag characters.
var bandwidthFlags = map[rune]bool{
	'K': true, 'L': true, 'M': true, 'N': true,
	'O': true, 'P': true, 'X': true,
}

// congestionFlags is the set of congestion flag characters per Proposal 162.
var congestionFlags = map[rune]bool{
	'D': true, 'E': true, 'G': true,
}

// reachabilityFlags is the set of reachability flag characters.
var reachabilityFlags = map[rune]bool{
	'R': true, 'U': true,
}

// ValidateCapsString checks that a caps string contains only valid single-letter
// capability flags per the I2P spec. It verifies:
//   - All characters are recognized capability flags
//   - Exactly one bandwidth class letter (K/L/M/N/O/P/X)
//   - Exactly one reachability flag (R or U)
//   - At most one congestion flag (D/E/G per Proposal 162)
//   - No duplicate flags
func ValidateCapsString(caps string) error {
	if caps == "" {
		return newValidationError("caps string must not be empty")
	}

	seen := make(map[rune]bool)
	bwCount := 0
	reachCount := 0
	congCount := 0

	for _, r := range caps {
		// Check for duplicates
		if seen[r] {
			return newValidationError(fmt.Sprintf("duplicate caps flag: %c", r))
		}
		seen[r] = true

		// Check if recognized
		if _, ok := validCapsFlags[r]; !ok {
			return newValidationError(fmt.Sprintf("unrecognized caps flag: %c", r))
		}

		// Count by category
		if bandwidthFlags[r] {
			bwCount++
		}
		if reachabilityFlags[r] {
			reachCount++
		}
		if congestionFlags[r] {
			congCount++
		}
	}

	if bwCount != 1 {
		return newValidationError(fmt.Sprintf(
			"caps string must contain exactly one bandwidth class letter (K/L/M/N/O/P/X), found %d", bwCount))
	}
	if reachCount != 1 {
		return newValidationError(fmt.Sprintf(
			"caps string must contain exactly one reachability flag (R/U), found %d", reachCount))
	}
	if congCount > 1 {
		return newValidationError(fmt.Sprintf(
			"caps string must contain at most one congestion flag (D/E/G), found %d", congCount))
	}

	return nil
}

// BuildCapsString constructs a valid RouterInfo caps string from the given
// parameters. The flags are assembled in canonical order:
//
//	bandwidth + reachability + [floodfill] + [hidden] + [congestion]
//
// This ensures all caps strings produced by this router follow a consistent
// ordering for easy comparison, even though the I2P spec does not mandate
// flag ordering.
func BuildCapsString(bandwidth BandwidthClass, reachable bool, floodfill bool, hidden bool, congestion CongestionFlag) string {
	var b strings.Builder

	// Bandwidth class (required)
	b.WriteString(string(bandwidth))

	// Reachability (required)
	if reachable {
		b.WriteRune('R')
	} else {
		b.WriteRune('U')
	}

	// Floodfill (optional)
	if floodfill {
		b.WriteRune('f')
	}

	// Hidden (optional)
	if hidden {
		b.WriteRune('H')
	}

	// Congestion per Proposal 162 (optional)
	if congestion != CongestionFlagNone {
		b.WriteString(congestion.String())
	}

	log.WithFields(logger.Fields{
		"at":   "BuildCapsString",
		"caps": b.String(),
	}).Debug("built RouterInfo caps string")

	return b.String()
}

// SpecRouterInfoOptionKeys is the set of option keys recognized by the I2P
// specification for RouterInfo. Any key NOT in this set may cause the
// RouterInfo to be rejected or ignored by other routers.
//
// Spec: https://geti2p.net/spec/common-structures#routerinfo
var SpecRouterInfoOptionKeys = map[string]string{
	"router.version":       "Router software version (e.g. 0.9.64)",
	"caps":                 "Capability flags string",
	"netId":                "Network ID (2 = production I2P network)",
	"coreVersion":          "Core library version",
	"stat_uptime":          "Router uptime statistics",
	"netdb.knownRouters":   "Number of known routers in local NetDB",
	"netdb.knownLeaseSets": "Number of known LeaseSets in local NetDB",
}

// ValidateRouterInfoOptionKeys checks that the given option keys map contains
// only spec-recognized keys. Returns an error listing any unrecognized keys.
//
// This helps prevent accidental inclusion of proprietary or debug keys that
// could cause the RouterInfo to be rejected by other routers on the network.
func ValidateRouterInfoOptionKeys(options map[string]string) error {
	var unknownKeys []string
	for key := range options {
		if _, ok := SpecRouterInfoOptionKeys[key]; !ok {
			unknownKeys = append(unknownKeys, key)
		}
	}

	if len(unknownKeys) > 0 {
		sort.Strings(unknownKeys)
		return newValidationError(fmt.Sprintf(
			"unrecognized RouterInfo option keys: %s", strings.Join(unknownKeys, ", ")))
	}

	log.WithFields(logger.Fields{
		"at":        "ValidateRouterInfoOptionKeys",
		"key_count": len(options),
	}).Debug("all RouterInfo option keys are spec-recognized")

	return nil
}

// ValidateCongestionFlag checks that a CongestionFlag value is one of the
// recognized values: "" (none), "D", "E", or "G".
func ValidateCongestionFlag(flag CongestionFlag) error {
	switch flag {
	case CongestionFlagNone, CongestionFlagD, CongestionFlagE, CongestionFlagG:
		return nil
	default:
		return newValidationError(fmt.Sprintf(
			"invalid congestion flag: %q (must be empty, D, E, or G)", flag))
	}
}
