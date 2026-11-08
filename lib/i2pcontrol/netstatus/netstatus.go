package netstatus

// I2PControl network status codes.
//
// A router reports one of these integers as i2p.router.status and
// i2p.router.net.status. The codes come from the Java router's NetworkStatus
// enum, which I2PControl mirrors; the reference set runs 0 through 14.
//
// Spec: https://github.com/i2p/i2p.i2p/blob/master/install/docs/http-api/i2pcontrol/index.md
//
// Consolidated from matching literals previously kept in lib/i2pcontrol,
// lib/router, lib/transport/ssu2 and lib/tui.
const (
	// OK means the router is running and directly reachable with a confirmed
	// external address.
	OK = 0

	// Testing means the router has not yet connected to any peers.
	Testing = 1

	// Firewalled means inbound is blocked: no confirmed external address, or
	// reachability only through introducers behind a restricted or port-restricted
	// NAT.
	Firewalled = 2

	// Hidden means the router is in hidden mode by configuration.
	Hidden = 3

	// WarnFirewalledAndFast means a firewalled router is also advertising a high
	// bandwidth class, which the network treats as a misconfiguration.
	WarnFirewalledAndFast = 4

	// WarnFirewalledAndFloodfill means a floodfill is firewalled and so cannot
	// serve lookups to peers that cannot reach it.
	WarnFirewalledAndFloodfill = 5

	// WarnFirewalledWithInboundTCP means NTCP inbound succeeded while the router
	// still reports itself firewalled.
	WarnFirewalledWithInboundTCP = 6

	// WarnFirewalledWithUDPDisabled means the router is firewalled on TCP with SSU
	// disabled, leaving it no transport that could traverse NAT.
	WarnFirewalledWithUDPDisabled = 7

	// ErrorI2CP means the I2CP server is not running, so local clients cannot
	// connect.
	ErrorI2CP = 8

	// ErrorClockSkew means the local clock differs from the network's by more than
	// the tolerance, which breaks message expiration.
	ErrorClockSkew = 9

	// ErrorPrivateTCPAddress means the router advertised a non-routable address as
	// its public TCP endpoint.
	ErrorPrivateTCPAddress = 10

	// ErrorSymmetricNAT means the router is reachable only via introducers because
	// the NAT is symmetric.
	ErrorSymmetricNAT = 11

	// ErrorUDPPortInUse means the SSU port is already bound by another process.
	ErrorUDPPortInUse = 12

	// ErrorNoActivePeers means the router has no peers at all and the operator
	// should check connectivity and firewall configuration.
	ErrorNoActivePeers = 13

	// ErrorUDPDisabledAndTCPUnset means neither transport is usable, so the router
	// cannot peer with anything.
	ErrorUDPDisabledAndTCPUnset = 14

	// MaxCode is the highest defined status code. The reference set ends at 14;
	// anything above it is not a code this router knows.
	MaxCode = ErrorUDPDisabledAndTCPUnset
)

// names maps each status code to the name the i2p.router.status field reports.
// Indexed by the code and sized by MaxCode, so adding a code without a name
// leaves an empty entry that Name reports as Unknown rather than silently
// returning the wrong string, and a code declared above MaxCode fails to
// compile.
var names = [...]string{
	OK:                            "OK",
	Testing:                       "TESTING",
	Firewalled:                    "FIREWALLED",
	Hidden:                        "HIDDEN",
	WarnFirewalledAndFast:         "WARN_FIREWALLED_AND_FAST",
	WarnFirewalledAndFloodfill:    "WARN_FIREWALLED_AND_FLOODFILL",
	WarnFirewalledWithInboundTCP:  "WARN_FIREWALLED_WITH_INBOUND_TCP",
	WarnFirewalledWithUDPDisabled: "WARN_FIREWALLED_WITH_UDP_DISABLED",
	ErrorI2CP:                     "ERROR_I2CP",
	ErrorClockSkew:                "ERROR_CLOCK_SKEW",
	ErrorPrivateTCPAddress:        "ERROR_PRIVATE_TCP_ADDRESS",
	ErrorSymmetricNAT:             "ERROR_SYMMETRIC_NAT",
	ErrorUDPPortInUse:             "ERROR_UDP_PORT_IN_USE",
	ErrorNoActivePeers:            "ERROR_NO_ACTIVE_PEERS_CHECK_CONNECTION_AND_FIREWALL",
	ErrorUDPDisabledAndTCPUnset:   "ERROR_UDP_DISABLED_AND_TCP_UNSET",
}

// Unknown is what Name returns for a code outside the defined range, or for a
// code declared without a name.
const Unknown = "UNKNOWN"

// Table-size assertion, following the compile-time checks in lib/i2np. If a code
// is added to the const block and entered in names without MaxCode being
// advanced — or MaxCode is advanced past the table — the package stops building
// instead of silently reporting a valid code as UNKNOWN.
const (
	_ = uint(len(names) - MaxCode - 1)
	_ = uint(MaxCode - len(names) + 1)
)

// Name returns the human-readable status name for a code, as it appears in the
// i2p.router.status RouterInfo field. Every firewalled variant gets its own
// string rather than one coarse label, so a client can tell them apart.
func Name(code int) string {
	if code < 0 || code > MaxCode {
		return Unknown
	}
	if name := names[code]; name != "" {
		return name
	}
	return Unknown
}
