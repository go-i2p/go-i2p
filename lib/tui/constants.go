package tui

import "github.com/go-i2p/go-i2p/lib/i2pcontrol/netstatus"

// ──────────────────────────────────────────────────────────────────────────────
// ANSI 256-colour palette entries
// ──────────────────────────────────────────────────────────────────────────────

// These are xterm 256-colour indices passed to lipgloss.Color, not RGB values.
// They are collected here so the panel styling and the reachability status
// colours can be reviewed together for contrast.
// Moved from: tui.go
const (
	// colorAccent is the orange used for panel borders and titles.
	colorAccent = "214"
	// colorLabel is the light grey used for panel field labels.
	colorLabel = "252"
	// colorValue is the green used for panel field values.
	colorValue = "120"
	// colorMuted is the grey used for unknown or unclassifiable states, and as
	// the fallback when a state has no entry in reachabilityColors.
	colorMuted = "240"
	// colorFirewalled is the yellow used for the firewalled state.
	colorFirewalled = "220"
	// colorInboundBlocked is the amber used for the inbound-blocked state.
	colorInboundBlocked = "208"
	// colorIPv4 is the green used for the directly-reachable IPv4 state.
	colorIPv4 = "82"
	// colorIPv6 is the cyan used for the directly-reachable IPv6 state.
	colorIPv6 = "39"
)

// ──────────────────────────────────────────────────────────────────────────────
// I2PControl network status codes
// ──────────────────────────────────────────────────────────────────────────────

// The TUI reads i2p.router.net.status over the I2PControl JSON-RPC interface, so
// it must translate the numeric wire codes. They are owned by
// lib/i2pcontrol/netstatus, the leaf package both the producer and the consumers
// can reach: lib/tui sits below lib/i2pcontrol in the dependency order, so
// importing that package directly would invert it, but the leaf is importable
// from here. The values are aliased rather than restated, so a display label can
// never disagree with the code the router sent.
//
// Spec: https://github.com/i2p/i2p.i2p/blob/master/install/docs/http-api/i2pcontrol/index.md
// Moved from: tui.go
const (
	// netStatusOK means the router is directly reachable.
	netStatusOK = netstatus.OK
	// netStatusTesting means the router has not yet connected to any peers.
	netStatusTesting = netstatus.Testing
	// netStatusFirewalled is the base firewalled code.
	netStatusFirewalled = netstatus.Firewalled
	// netStatusHidden means the router is in hidden mode with no published address.
	netStatusHidden = netstatus.Hidden
	// netStatusFirewalledAndFast is a firewalled router configured as a fast peer.
	netStatusFirewalledAndFast = netstatus.WarnFirewalledAndFast
	// netStatusFirewalledAndFloodfill is a firewalled floodfill, which cannot
	// receive the queries it is meant to answer.
	netStatusFirewalledAndFloodfill = netstatus.WarnFirewalledAndFloodfill
	// netStatusFirewalledWithInboundTCP is a firewalled router that nonetheless
	// accepts inbound TCP.
	netStatusFirewalledWithInboundTCP = netstatus.WarnFirewalledWithInboundTCP
	// netStatusFirewalledWithUDPDisabled is a firewalled router whose UDP is off.
	netStatusFirewalledWithUDPDisabled = netstatus.WarnFirewalledWithUDPDisabled
	// netStatusErrorSymmetricNAT is the symmetric-NAT error, which blocks
	// unsolicited inbound connections like the other firewalled variants.
	netStatusErrorSymmetricNAT = netstatus.ErrorSymmetricNAT
)
