// Package transport implements the I2P transport layer: the encrypted,
// authenticated connections between routers.
//
// # What is the transport layer?
//
// I2NP messages (see lib/i2np) need a way to get from one router to another.
// The transport layer provides that channel. It sets up an encrypted,
// authenticated connection so that routers can be sure of each other's
// identity and that their messages have not been tampered with.
//
// Two transports are supported:
//   - NTCP2: a TCP-based transport. Reliable, and works through most networks.
//   - SSU2: a UDP-based transport. Lower latency, with NAT traversal and
//     introducer support for peers behind firewalls.
//
// Both use the Noise protocol framework for key agreement, which gives forward
// secrecy (past sessions stay secret even if a key is later compromised) and
// identity hiding.
//
// # TransportMuxer
//
// A TransportMuxer combines several transports behind a single Transport
// interface:
//   - It accepts connections from all registered transports at once.
//   - It dials a peer using the first compatible transport.
//   - It enforces a connection limit across all transports.
//
// # NTCP2
//
// NTCP2 uses the Noise_XK_25519_ChaChaPoly_SHA256 pattern: X25519 key
// exchange with ChaCha20-Poly1305 encryption. See lib/transport/ntcp2 for
// details and the NTCP2 specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst
//
// # SSU2
//
// SSU2 is the UDP equivalent, with NAT traversal and introducer support. See
// lib/transport/ssu2 for details and the SSU2 specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst
//
// # Thread safety
//
// TransportMuxer is safe for concurrent use. Connection counting uses atomic
// operations, each transport manages its own connections, and Accept listens
// on all transports at once.
//
// # Usage example
//
//	// Create individual transports.
//	ntcp2Transport := ntcp2.NewTransport(config)
//
//	// Multiplex transports together.
//	tmux := transport.Mux(ntcp2Transport)
//	// Or with a connection limit:
//	tmux := transport.MuxWithLimit(1024, ntcp2Transport)
//
//	// Optionally rotate the identity presented to peers. Transports are
//	// already constructed with an identity, so this is only needed if the
//	// RouterInfo changes at runtime; it updates in place and never rebinds.
//	tmux.SetIdentity(ourRouterInfo)
//
//	// Accept connections from any transport.
//	conn, err := tmux.Accept()
//
//	// Dial a peer.
//	conn, err = tmux.Dial(peerRouterInfo)
//
// # Connection management
//
// Connections are managed automatically:
//   - Connection limits are enforced via MaxConnections.
//   - Session counting uses atomic operations.
//   - ReleaseSession() frees capacity when a connection closes.
package transport
