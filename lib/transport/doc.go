// Package transport implements I2P transport layer protocols for router-to-router communication.
//
// # Overview
//
// The transport layer handles encrypted, authenticated connections between I2P routers.
// Supported transports:
//   - NTCP2: TCP-based transport with Noise protocol encryption
//   - SSU2: UDP-based transport (planned)
//
// # TransportMuxer
//
// The TransportMuxer multiplexes multiple transports into a single Transport interface:
//   - Combines multiple transports in priority order
//   - Accepts connections from all registered transports concurrently
//   - Dials peers using the first compatible transport
//   - Enforces connection limits across all transports
//
// # NTCP2 Transport
//
// NTCP2 uses Noise_XK_25519_ChaChaPoly_SHA256:
//   - X25519 key exchange
//   - ChaCha20-Poly1305 AEAD encryption
//   - Session state management
//   - I2NP message framing
//
// See lib/transport/ntcp2 for implementation details.
//
// # Thread Safety
//
// TransportMuxer is safe for concurrent access:
//   - Connection counting uses atomic operations
//   - Each transport manages its own connections
//   - Accept listens on all transports concurrently
//
// # Usage Example
//
//	// Create individual transports
//	ntcp2Transport := ntcp2.NewTransport(config)
//
//	// Multiplex transports together
//	tmux := transport.Mux(ntcp2Transport)
//	// Or with a connection limit:
//	tmux := transport.MuxWithLimit(1024, ntcp2Transport)
//
//	// Set identity for all transports
//	tmux.SetIdentity(ourRouterInfo)
//
//	// Accept connections from any transport
//	conn, err := tmux.Accept()
//
//	// Dial a peer
//	conn, err := tmux.Dial(peerRouterInfo)
//
// # Connection Management
//
// Connections are automatically managed:
//   - Connection limits enforced via MaxConnections
//   - Session counting with atomic operations
//   - ReleaseSession() frees capacity when connections close
package transport
