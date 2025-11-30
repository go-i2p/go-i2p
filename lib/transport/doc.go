// Package transport implements I2P transport layer protocols for router-to-router communication.
//
// # Overview
//
// The transport layer handles encrypted, authenticated connections between I2P routers.
// Supported transports:
//   - NTCP2: TCP-based transport with Noise protocol encryption
//   - SSU2: UDP-based transport (planned)
//
// # Transport Manager
//
// The TransportManager coordinates all transports:
//   - Maintains connection pool
//   - Routes I2NP messages to appropriate transports
//   - Handles connection lifecycle
//   - Monitors transport health
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
// TransportManager is safe for concurrent access:
//   - Connection map protected by mutex
//   - Each transport manages its own connections
//   - Message sending is thread-safe
//
// # Usage Example
//
//	// Create transport manager
//	tm := transport.NewTransportManager(ourRouterInfo, netdb)
//
//	// Register NTCP2 transport
//	ntcp2 := ntcp2.NewTransport(config)
//	tm.RegisterTransport(ntcp2)
//
//	// Send message to peer
//	peerHash, err := peerRouterInfo.IdentHash()
//	if err != nil {
//	    log.Printf("Failed to get peer hash: %v", err)
//	    return
//	}
//	if err := tm.SendMessage(peerHash, i2npMsg); err != nil {
//	    log.Printf("Failed to send message: %v", err)
//	}
//
//	// Stop all transports
//	tm.Shutdown()
//
// # Connection Management
//
// Connections are automatically managed:
//   - Idle connections closed after timeout
//   - Failed connections retried with backoff
//   - Connection limits enforced per transport
package transport
