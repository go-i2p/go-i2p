// Package ssu2 implements the SSU2 (Secure Semireliable UDP 2) transport
// protocol for I2P router-to-router communication.
//
// # What is SSU2?
//
// SSU2 is a UDP-based transport. Like NTCP2, it gives two routers a private,
// encrypted channel, but it rides on UDP instead of TCP. That makes it lower
// latency, and it adds NAT traversal so that routers behind firewalls can
// still reach each other.
//
// SSU2 uses the Noise protocol framework (the XK pattern) for key agreement,
// providing forward secrecy and identity hiding.
//
// # Features
//
//   - UDP-based transport with lower latency than NTCP2.
//   - Session handshake using the Noise XK pattern.
//   - Peer testing for NAT detection.
//   - Introducer support for NAT traversal.
//   - Connection migration for roaming clients.
//   - Congestion control and reliable delivery.
//
// # I2P specification
//
// SSU2 is defined in the I2P specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst
//
// # Configuration
//
// The router configuration supports SSU2 settings:
//
//	transport:
//	  ssu2_enabled: true
//	  ssu2_port: 9002  # use a random port when 0
//
// # Experimental status
//
// This transport is described as experimental in the README and in the
// --transport.ssu2-enabled help text, and it is enabled by default. The label
// means something specific: the implementation covers the specification's SSU2
// surface and is exercised by this package's tests, but it has never completed a
// handshake with a Java I2P or i2pd peer on the real network. The live-network
// suite asserts bootstrap, RouterInfo and LeaseSet paths; none of them asserts
// SSU2 (see docs/interop-matrix.md). NTCP2 is proven against both reference
// implementations.
//
// docs/ssu2-experimental.md lists the full set of gaps — including the
// initiator-side handshake replay cache that ssu2.rst:1576-1581 requires and
// that go-noise creates only for responders — and the checklist that must be
// satisfied before the designation can be removed.
//
// # Implementation notes
//
// This package wraps the go-noise/ssu2 library (which provides the Noise state
// machine and UDP protocol primitives) behind the transport.Transport and
// transport.TransportSession interfaces used by the go-i2p router.
//
// ## NAT traversal
//
// As of 2026-06, NAT traversal logic (UPnP/NAT-PMP, loopback detection,
// SO_REUSEADDR socket options, and TOCTOU retry handling) has been extracted
// to the shared lib/nat package. listenWithOSPort is a thin wrapper around
// nat.ProbeAndBindWithNATTraversal, and the explicit-port path in
// bindPacketConnWithFallback wraps nat.BindWithNATTraversal.
//
// bindPacketConnWithFallback also provides the plain-socket fallback: a NAT
// port mapping improves reachability but is never a precondition for
// listening, so a mapping failure falls back to bindPlainUDPConn rather than
// failing transport construction. This mirrors ntcp2.bindListenerWithFallback
// and matters because port 0 is the default configuration — without the
// fallback a router on a host with no UPnP/NAT-PMP silently loses SSU2.
//
// Identity updates do not touch the socket either. SetIdentity publishes a new
// config to the live listener via its UpdateIdentity method rather than
// recreating it: a responder's identity is consumed per session, so the socket
// is irrelevant, and rebinding could not work anyway because the old socket
// must stay open for the swap to be atomic. The NAT managers are left running,
// since they reference the listener only through path.ListenerRef (GetAddr).
//
// Future enhancements to NAT handling should be implemented in lib/nat, not
// here. This ensures consistent behavior across all transports (NTCP2, SSU2,
// and any future transport implementations).
//
// See lib/nat/doc.go for details on the NAT traversal implementation.
package ssu2
