// Package i2np implements the I2P Network Protocol (I2NP) for router-to-router communication.
//
// # Message Types
//
// I2NP defines message types for:
//   - Network database operations (DatabaseStore, DatabaseLookup)
//   - Tunnel building (ShortTunnelBuild, VariableTunnelBuild)
//   - Data delivery (TunnelData, Data, DeliveryStatus)
//   - Garlic encryption (end-to-end encrypted message bundles)
//
// # Message Structure
//
// All I2NP messages consist of:
//   - Header: type, ID, expiration, size, checksum
//   - Payload: type-specific data
//
// # Cryptography
//
// I2NP uses modern cryptography:
//   - ECIES-X25519-AEAD-Ratchet for garlic encryption
//   - ChaCha20-Poly1305 for tunnel build records
//   - ElGamal/AES (legacy, compatibility only)
//
// See github.com/go-i2p/crypto for cryptographic primitives.
//
// # Usage Example
//
//	// Create DatabaseStore message
//	ds, err := i2np.NewDatabaseStoreMessage(hash, data, i2np.ROUTER_INFO_TYPE)
//	if err != nil {
//	    log.Printf("Failed to create message: %v", err)
//	}
//
//	// Send via transport
//	if err := transport.SendMessage(peerHash, ds); err != nil {
//	    log.Printf("Failed to send: %v", err)
//	}
//
// # Database Operations
//
// DatabaseStore supports RouterInfo, LeaseSet, and LeaseSet2:
//   - Type field bits 3-0 specify entry type
//   - Validation ensures hash matches content
//   - Replies are sent via DeliveryStatus messages
//
// DatabaseLookup queries the network database:
//   - Supports iterative and recursive lookups
//   - Returns DatabaseStore or DatabaseSearchReply
//   - Floodfill routers handle lookup requests
//
// # Tunnel Building
//
// Tunnel build messages are encrypted per-hop:
//   - Build request records encrypted to each hop
//   - Build reply records return encrypted status
//   - Short format for 1-8 hop tunnels
//   - Variable format for longer tunnels (deprecated)
//
// See lib/tunnel for tunnel management and building.
package i2np
