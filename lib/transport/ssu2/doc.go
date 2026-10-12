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
// to the shared lib/nat package. The listenWithOSPort and
// listenWithNATTraversal functions in this package are now thin wrappers
// around nat.ProbeAndBindWithNATTraversal and nat.BindWithNATTraversal
// respectively.
//
// Future enhancements to NAT handling should be implemented in lib/nat, not
// here. This ensures consistent behavior across all transports (NTCP2, SSU2,
// and any future transport implementations).
//
// See lib/nat/doc.go for details on the NAT traversal implementation.
package ssu2
