// Package tunnel implements I2P tunnel creation, management, and message routing.
//
// # What is a tunnel?
//
// A tunnel is a private path through the I2P network. Instead of sending a
// message straight to its destination, a router wraps the message in layers of
// encryption and hands it to a chain of routers, called hops. Each hop peels
// off one layer and passes the rest along, so no single hop can see both the
// sender and the receiver.
//
// Tunnels are unidirectional:
//   - Outbound tunnel: Local → Hop1 → Hop2 → ... → Endpoint
//   - Inbound tunnel: Gateway → Hop1 → Hop2 → ... → Local
//
// Most tunnels use three hops.
//
// # Tunnel roles
//
// A router can play one of three roles in a tunnel:
//
//   - Gateway: the entry point. It receives a message from the network and
//     forwards it into the tunnel with the first layer of encryption.
//
//   - Participant: a middle hop. It removes one layer of encryption and
//     forwards the rest to the next hop. The Participant.Process() method
//     handles the decryption and finds the next hop.
//
//   - Endpoint: the exit. It removes the final layer of encryption and
//     delivers the message to its destination or to the local router.
//
// # How messages flow
//
// A message is split into fixed-size tunnel messages (about 1 KB each) so that
// all messages look the same size on the wire. This makes it harder for an
// observer to guess what is being sent from its length. The first fragment
// carries delivery instructions; follow-on fragments carry the rest of the
// data. See the tunnel message specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/tunnel-message.rst
//
// # Building tunnels
//
// Tunnels are built with encrypted build records. Each hop's record is
// encrypted to that hop alone, so a router only learns its own neighbors and
// never the full path. Tunnel creation uses ECIES (Elliptic Curve Integrated
// Encryption Scheme) with X25519. See the tunnel creation specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/tunnel-creation-ecies.rst
//
// # Tunnel pool
//
// A TunnelPool keeps a set of ready-to-use tunnels and rebuilds them as they
// expire. It is safe for concurrent use: the tunnel list is protected by a
// mutex, builder operations are atomic, and maintenance runs in a background
// goroutine.
//
// # Usage example
//
//	// Create a tunnel pool with a peer selector.
//	pool := tunnel.NewTunnelPool(peerSelector)
//
//	// Start maintenance (builds tunnels automatically).
//	if err := pool.StartMaintenance(); err != nil {
//	    log.Printf("Failed to start maintenance: %v", err)
//	}
//
//	// Select an active tunnel for sending.
//	outTunnel := pool.SelectTunnel()
//	if outTunnel == nil {
//	    log.Printf("No active tunnels available")
//	}
//
//	// For message routing, use Gateway.Send() with an I2NP message.
//	// gateway := tunnel.NewGateway(tunnelID, nextHopID, encryption)
//	// encryptedMsg, err := gateway.Send(i2npMessageBytes)
//
// # Cryptography
//
// Each tunnel hop uses:
//   - ChaCha20-Poly1305 for layer encryption.
//   - ECIES-X25519 for build record encryption.
//
// See github.com/go-i2p/crypto for the cryptographic primitives.
package tunnel
