package i2pcontrol

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/i2pcontrol/netstatus"
)

// ──────────────────────────────────────────────────────────────────────────────
// I2PControl network status codes
// ──────────────────────────────────────────────────────────────────────────────

// The integer the router reports as i2p.router.status and
// i2p.router.net.status. The codes are owned by lib/i2pcontrol/netstatus, a leaf
// package, because the components that produce them sit at different depths in
// the dependency order — lib/transport/ssu2 and lib/tui both report a code but
// cannot import this package. These aliases keep the names available to
// i2pcontrol's own callers while the values stay defined once.
//
// Spec: https://github.com/i2p/i2p.i2p/blob/master/install/docs/http-api/i2pcontrol/index.md
const (
	// NetworkStatusOK means the router is running and directly reachable with a
	// confirmed external address.
	NetworkStatusOK = netstatus.OK

	// NetworkStatusTesting means the router has not yet connected to any peers.
	NetworkStatusTesting = netstatus.Testing

	// NetworkStatusFirewalled means inbound is blocked: no confirmed external
	// address, or reachability only through introducers behind a restricted or
	// port-restricted NAT.
	NetworkStatusFirewalled = netstatus.Firewalled

	// NetworkStatusHidden means the router is in hidden mode by configuration.
	NetworkStatusHidden = netstatus.Hidden

	// NetworkStatusWarnFirewalledAndFast means a firewalled router is also
	// advertising a high bandwidth class, which the network treats as a
	// misconfiguration.
	NetworkStatusWarnFirewalledAndFast = netstatus.WarnFirewalledAndFast

	// NetworkStatusWarnFirewalledAndFloodfill means a floodfill is firewalled and
	// so cannot serve lookups to peers that cannot reach it.
	NetworkStatusWarnFirewalledAndFloodfill = netstatus.WarnFirewalledAndFloodfill

	// NetworkStatusWarnFirewalledWithInboundTCP means NTCP inbound succeeded while
	// the router still reports itself firewalled.
	NetworkStatusWarnFirewalledWithInboundTCP = netstatus.WarnFirewalledWithInboundTCP

	// NetworkStatusWarnFirewalledWithUDPDisabled means the router is firewalled on
	// TCP with SSU disabled, leaving it no transport that could traverse NAT.
	NetworkStatusWarnFirewalledWithUDPDisabled = netstatus.WarnFirewalledWithUDPDisabled

	// NetworkStatusErrorI2CP means the I2CP server is not running, so local
	// clients cannot connect.
	NetworkStatusErrorI2CP = netstatus.ErrorI2CP

	// NetworkStatusErrorClockSkew means the local clock differs from the network's
	// by more than the tolerance, which breaks message expiration.
	NetworkStatusErrorClockSkew = netstatus.ErrorClockSkew

	// NetworkStatusErrorPrivateTCPAddress means the router advertised a
	// non-routable address as its public TCP endpoint.
	NetworkStatusErrorPrivateTCPAddress = netstatus.ErrorPrivateTCPAddress

	// NetworkStatusErrorSymmetricNAT means the router is reachable only via
	// introducers because the NAT is symmetric.
	NetworkStatusErrorSymmetricNAT = netstatus.ErrorSymmetricNAT

	// NetworkStatusErrorUDPPortInUse means the SSU port is already bound by
	// another process.
	NetworkStatusErrorUDPPortInUse = netstatus.ErrorUDPPortInUse

	// NetworkStatusErrorNoActivePeers means the router has no peers at all and the
	// operator should check connectivity and firewall configuration.
	NetworkStatusErrorNoActivePeers = netstatus.ErrorNoActivePeers

	// NetworkStatusErrorUDPDisabledAndTCPUnset means neither transport is usable,
	// so the router cannot peer with anything.
	NetworkStatusErrorUDPDisabledAndTCPUnset = netstatus.ErrorUDPDisabledAndTCPUnset
)

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
