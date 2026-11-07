package i2pcontrol

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// I2PControl network status codes
// ──────────────────────────────────────────────────────────────────────────────

// The integer the router reports as i2p.router.status and
// i2p.router.net.status. The router produces these codes and this package names
// them for the RPC reply, so they are defined once here and aliased by the
// router rather than kept as matching literals in two places.
//
// The codes come from the Java router's NetworkStatus enum, which I2PControl
// mirrors; the reference set runs 0 through 14.
//
// Moved from: handlers.go
const (
	// NetworkStatusOK means the router is running and directly reachable with a
	// confirmed external address.
	NetworkStatusOK = 0

	// NetworkStatusTesting means the router has not yet connected to any peers.
	NetworkStatusTesting = 1

	// NetworkStatusFirewalled means inbound is blocked: no confirmed external
	// address, or reachability only through introducers behind a restricted or
	// port-restricted NAT.
	NetworkStatusFirewalled = 2

	// NetworkStatusHidden means the router is in hidden mode by configuration.
	NetworkStatusHidden = 3

	// NetworkStatusWarnFirewalledAndFast means a firewalled router is also
	// advertising a high bandwidth class, which the network treats as a
	// misconfiguration.
	NetworkStatusWarnFirewalledAndFast = 4

	// NetworkStatusWarnFirewalledAndFloodfill means a floodfill is firewalled and
	// so cannot serve lookups to peers that cannot reach it.
	NetworkStatusWarnFirewalledAndFloodfill = 5

	// NetworkStatusWarnFirewalledWithInboundTCP means NTCP inbound succeeded while
	// the router still reports itself firewalled.
	NetworkStatusWarnFirewalledWithInboundTCP = 6

	// NetworkStatusWarnFirewalledWithUDPDisabled means the router is firewalled on
	// TCP with SSU disabled, leaving it no transport that could traverse NAT.
	NetworkStatusWarnFirewalledWithUDPDisabled = 7

	// NetworkStatusErrorI2CP means the I2CP server is not running, so local
	// clients cannot connect.
	NetworkStatusErrorI2CP = 8

	// NetworkStatusErrorClockSkew means the local clock differs from the network's
	// by more than the tolerance, which breaks message expiration.
	NetworkStatusErrorClockSkew = 9

	// NetworkStatusErrorPrivateTCPAddress means the router advertised a
	// non-routable address as its public TCP endpoint.
	NetworkStatusErrorPrivateTCPAddress = 10

	// NetworkStatusErrorSymmetricNAT means the router is reachable only via
	// introducers because the NAT is symmetric.
	NetworkStatusErrorSymmetricNAT = 11

	// NetworkStatusErrorUDPPortInUse means the SSU port is already bound by
	// another process.
	NetworkStatusErrorUDPPortInUse = 12

	// NetworkStatusErrorNoActivePeers means the router has no peers at all and the
	// operator should check connectivity and firewall configuration.
	NetworkStatusErrorNoActivePeers = 13

	// NetworkStatusErrorUDPDisabledAndTCPUnset means neither transport is usable,
	// so the router cannot peer with anything.
	NetworkStatusErrorUDPDisabledAndTCPUnset = 14
)

// networkStatusNames maps each status code to the name the
// i2p.router.status RouterInfo field reports. Indexed by the code, so adding a
// code without a name is a compile-time-visible gap rather than a silent
// fallthrough to "UNKNOWN".
var networkStatusNames = [...]string{
	NetworkStatusOK:                            "OK",
	NetworkStatusTesting:                       "TESTING",
	NetworkStatusFirewalled:                    "FIREWALLED",
	NetworkStatusHidden:                        "HIDDEN",
	NetworkStatusWarnFirewalledAndFast:         "WARN_FIREWALLED_AND_FAST",
	NetworkStatusWarnFirewalledAndFloodfill:    "WARN_FIREWALLED_AND_FLOODFILL",
	NetworkStatusWarnFirewalledWithInboundTCP:  "WARN_FIREWALLED_WITH_INBOUND_TCP",
	NetworkStatusWarnFirewalledWithUDPDisabled: "WARN_FIREWALLED_WITH_UDP_DISABLED",
	NetworkStatusErrorI2CP:                     "ERROR_I2CP",
	NetworkStatusErrorClockSkew:                "ERROR_CLOCK_SKEW",
	NetworkStatusErrorPrivateTCPAddress:        "ERROR_PRIVATE_TCP_ADDRESS",
	NetworkStatusErrorSymmetricNAT:             "ERROR_SYMMETRIC_NAT",
	NetworkStatusErrorUDPPortInUse:             "ERROR_UDP_PORT_IN_USE",
	NetworkStatusErrorNoActivePeers:            "ERROR_NO_ACTIVE_PEERS_CHECK_CONNECTION_AND_FIREWALL",
	NetworkStatusErrorUDPDisabledAndTCPUnset:   "ERROR_UDP_DISABLED_AND_TCP_UNSET",
}

// ──────────────────────────────────────────────────────────────────────────────
// Server timeouts
// ──────────────────────────────────────────────────────────────────────────────

// I2PControl is a local administrative protocol with short request/response
// exchanges, so the deadlines are tight: a client that neither sends nor reads
// promptly is not doing useful work and should not hold a goroutine.
//
// Moved from: server.go
const (
	// serverReadTimeout bounds reading one request body.
	serverReadTimeout = 15 * time.Second

	// serverWriteTimeout bounds writing one response.
	serverWriteTimeout = 15 * time.Second

	// serverIdleTimeout is how long a keep-alive connection may sit between
	// requests before the server closes it.
	serverIdleTimeout = 60 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Hostname and port parsing limits
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: handlers.go, stats.go
const (
	// maxHostnameLength is the longest hostname accepted from a peer address. A
	// DNS label is 63 bytes and a full name 253, so anything longer is not a
	// hostname but a buffer stuffed with junk.
	maxHostnameLength = 253

	// maxPortNumber is the upper bound of a TCP/UDP port: ports are 16-bit.
	maxPortNumber = 65535

	// minBandwidthWindowSamples is how many samples a bandwidth window must hold
	// before its average is reported. A single sample is a spike, not a rate.
	minBandwidthWindowSamples = 2
)
