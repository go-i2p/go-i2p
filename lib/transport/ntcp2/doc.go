// Package ntcp2 implements the NTCP2 transport protocol for the I2P network.
//
// # What is NTCP2?
//
// NTCP2 is a TCP-based transport. It gives two routers a private, encrypted
// channel over a normal TCP connection. Because it rides on TCP, it is
// reliable and works through most networks, which makes it the default
// transport.
//
// NTCP2 uses the Noise protocol framework (the XK pattern) for key agreement.
// This provides:
//   - Forward secrecy: past sessions stay secret even if a key is later leaked.
//   - Identity hiding: a router's identity is not revealed to a passive
//     observer of the connection.
//
// The concrete Noise pattern is Noise_XK_25519_ChaChaPoly_SHA256: X25519 key
// exchange with ChaCha20-Poly1305 encryption.
//
// # I2P specification
//
// NTCP2 is defined in the I2P specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst
//
// # Implementation notes
//
// ## NAT traversal
//
// As of 2026-06, NAT traversal logic (UPnP/NAT-PMP, loopback detection,
// SO_REUSEADDR socket options, and TOCTOU retry handling) has been extracted
// to the shared lib/nat package. The bindOSAssignedPort and
// bindWithNATTraversal functions in this package are now thin wrappers around
// nat.ProbeAndBindWithNATTraversal and nat.BindWithNATTraversal respectively.
//
// Future enhancements to NAT handling should be implemented in lib/nat, not
// here. This ensures consistent behavior across all transports (NTCP2, SSU2,
// and any future transport implementations).
//
// See lib/nat/doc.go for details on the NAT traversal implementation.
package ntcp2
