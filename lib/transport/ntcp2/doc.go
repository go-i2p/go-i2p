// Package ntcp2 implements the NTCP2 transport protocol for the I2P network.
// NTCP2 is a TCP-based transport that uses the Noise protocol framework (XK pattern)
// for authenticated key agreement, providing forward secrecy and identity hiding.
//
// # Implementation Notes
//
// ## NAT Traversal
//
// As of 2026-06, NAT traversal logic (UPnP/NAT-PMP, loopback detection,
// SO_REUSEADDR socket options, and TOCTOU retry handling) has been extracted
// to the shared lib/nat package. The bindOSAssignedPort and bindWithNATTraversal
// functions in this package are now thin wrappers around nat.ProbeAndBindWithNATTraversal
// and nat.BindWithNATTraversal respectively.
//
// Future enhancements to NAT handling should be implemented in lib/nat, not here.
// This ensures consistent behavior across all transports (NTCP2, SSU2, and any
// future transport implementations).
//
// See lib/nat/doc.go for details on the NAT traversal implementation.
package ntcp2
