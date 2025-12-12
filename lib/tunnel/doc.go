// Package tunnel implements I2P tunnel creation, management, and message routing.
//
// # Overview
//
// Tunnels are the core anonymity mechanism in I2P. This package handles:
//   - Tunnel building with encrypted build records
//   - Tunnel pool management (inbound and outbound)
//   - Message routing through tunnel hops
//   - Layered encryption/decryption at each hop
//   - Fragment handling for large messages
//
// # Tunnel Architecture
//
// Tunnels are unidirectional paths through the I2P network:
//   - Outbound tunnels: Local → Hop1 → Hop2 → ... → Endpoint
//   - Inbound tunnels: Gateway → Hop1 → Hop2 → ... → Local
//
// Each tunnel has multiple hops (typically 3) for anonymity.
//
// # Tunnel Roles
//
// Routers can perform three roles in tunnel operation:
//
//   - Gateway: Receives messages from the network and forwards them into
//     the tunnel with the first layer of encryption.
//
//   - Participant: Acts as an intermediate hop, removing one layer of
//     encryption and forwarding to the next hop. The Participant.Process()
//     method handles decryption and extraction of next hop information.
//
//   - Endpoint: Receives messages from the tunnel, removes the final
//     encryption layer, and delivers to the destination or local router.
//
// # Thread Safety
//
// TunnelPool is safe for concurrent access:
//   - Tunnel list protected by mutex
//   - Builder operations are atomic
//   - Pool management runs in background goroutine
//
// # Usage Example
//
//	// Create tunnel pool
//	pool := tunnel.NewTunnelPool(config, netdb, transport)
//
//	// Build outbound tunnel
//	outTunnel, err := pool.BuildOutboundTunnel(3) // 3 hops
//	if err != nil {
//	    log.Printf("Failed to build tunnel: %v", err)
//	}
//
//	// Route message through tunnel
//	if err := outTunnel.SendMessage(msg); err != nil {
//	    log.Printf("Failed to send: %v", err)
//	}
//
// # Cryptography
//
// Each tunnel hop uses:
//   - AES256 for layer encryption
//   - HMAC-SHA256 for integrity
//   - ElGamal or ECIES for build record encryption
//
// See github.com/go-i2p/crypto for cryptographic primitives.
package tunnel
