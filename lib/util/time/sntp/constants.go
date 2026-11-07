package sntp

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Sleep and backoff durations
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: router_timestamper.go
const (
	// SyncLostSleep is how long the timestamper waits between attempts once
	// it has given up on the current server set, after maxConsecutiveFails
	// consecutive failures. Long enough to avoid hammering a network that is
	// down, short enough that recovery is noticed the same day.
	SyncLostSleep = 30 * time.Minute

	// RetrySleep is how long the timestamper waits after a single failed
	// time query.
	RetrySleep = 30 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Server selection
// ──────────────────────────────────────────────────────────────────────────────

// defaultIPv6Preference is the probability that the timestamper prefers an
// IPv6 transport for a default-pool query when the caller has not expressed a
// preference. It is a fraction, not a percentage.
// Moved from: router_timestamper.go
const defaultIPv6Preference = 0.75

// ──────────────────────────────────────────────────────────────────────────────
// NTP response validation
// ──────────────────────────────────────────────────────────────────────────────

// MaxStratum is the highest valid NTP stratum. Stratum 0 is reserved for the
// "kiss of death" and unset responses, so usable servers answer 1 through 15.
// Spec: RFC 5905 section 4
// Moved from: verification.go
const MaxStratum = 15

// WellSyncedOffset is the clock offset under which a sample is treated as
// evidence the local clock is already well synchronised. It is far tighter
// than the ±60 minute skew the I2P protocol tolerates, so it only affects the
// reported sync status, never whether a sample is accepted.
// Moved from: router_timestamper.go
const WellSyncedOffset = 500 * time.Millisecond

// ──────────────────────────────────────────────────────────────────────────────
// Timezone data
// ──────────────────────────────────────────────────────────────────────────────

// timezoneCountryMapCapacity is the initial capacity of the timezone-to-country
// map, sized to the number of entries in the embedded zone_to_country.txt so
// the map is not repeatedly grown while loading it.
// Moved from: timezone_country.go
const timezoneCountryMapCapacity = 420
