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

// ──────────────────────────────────────────────────────────────────────────────
// Concurrent server selection
// ──────────────────────────────────────────────────────────────────────────────

// maxConcurrentServers caps how many NTP servers the timestamper queries at once.
// The point of querying several is to catch a single server that lies about the
// time, and four is well past the point where more agreement adds confidence —
// beyond that it only multiplies outbound traffic to third-party time servers.
// A caller who asks for more is clamped down rather than rejected, since the
// request is harmless and the ceiling is a safety limit, not a contract.
//
// Moved from: router_timestamper.go
const maxConcurrentServers = 4

// ──────────────────────────────────────────────────────────────────────────────
// Timezone data file layout
// ──────────────────────────────────────────────────────────────────────────────

// Both embedded data files are two-column comma-separated records: a timezone or
// country name and its value. A line that does not split into that pair is not a
// record at all, so it is skipped rather than half-parsed.
//
// Moved from: timezone_country.go, zones.go
const timezoneRecordFieldCount = 2
