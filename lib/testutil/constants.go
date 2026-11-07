package testutil

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// RouterInfo fixture defaults
// ──────────────────────────────────────────────────────────────────────────────

// fixtureRouterVersion is the router.version option written into generated
// RouterInfos. Real RouterInfos always carry it, and network validation
// expects a value in the modern dotted-quad form.
// Moved from: routerinfo.go
const fixtureRouterVersion = "0.9.64"

// fixtureNetID is the netId option for generated RouterInfos: "2" is the
// production I2P network, the same value the NetDB requires of an accepted
// peer (see netdb.expectedNetID).
// Moved from: routerinfo.go
const fixtureNetID = "2"

// fixtureRouterAddressCost is the default NTCP2 router-address cost field.
// Lower is preferred when a peer selects transports; the I2P convention for a
// directly reachable address is a single-digit cost.
// Moved from: routerinfo.go
const fixtureRouterAddressCost = 3

// fixtureRouterAddressLifetime is how far ahead a generated router address is
// dated to expire. Long enough that a fixture does not go stale partway through
// a test run, including under the race detector.
// Moved from: routerinfo.go
const fixtureRouterAddressLifetime = 24 * time.Hour
