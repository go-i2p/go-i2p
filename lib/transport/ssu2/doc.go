// Package ssu2 implements the SSU2 (Secure Semireliable UDP 2) transport
// protocol for I2P router-to-router communication.
//
// SSU2 is a UDP-based transport that uses the Noise protocol framework (XK pattern)
// for authenticated key agreement, providing forward secrecy, identity hiding,
// and NAT traversal capabilities.
//
// This package wraps the go-noise/ssu2 library (which provides the Noise state
// machine and UDP protocol primitives) behind the transport.Transport and
// transport.TransportSession interfaces used by the go-i2p router.
//
// # Features
//
//   - UDP-based transport with lower latency than NTCP2
//   - Session handshake using Noise XK pattern
//   - Peer testing for NAT detection
//   - Introducer support for NAT traversal
//   - Connection migration for roaming clients
//   - Congestion control and reliable delivery
//
// # I2P Specification
//
// SSU2 is defined in the I2P specification at:
// https://geti2p.net/spec/ssu2
//
// # Configuration
//
// The router configuration supports SSU2 settings:
//
//	transport:
//	  ssu2_enabled: true
//	  ssu2_port: 9002  // Random port when 0
package ssu2
