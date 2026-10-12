// Package i2np implements the I2P Network Protocol (I2NP), the set of messages
// that I2P routers exchange with each other.
//
// # What is I2NP?
//
// I2P is a private overlay network. A "router" is any machine that helps move
// traffic through that network. Routers do not talk to each other directly;
// they exchange small, well-defined messages. I2NP is the format of those
// messages.
//
// Think of I2NP as a shared vocabulary. Every router speaks it, so any router
// can ask another for data, request a tunnel, or deliver a message, and the
// other side always knows how to read the request.
//
// This package only implements the current, modern message types. Legacy
// ElGamal-based tunnel building is not supported.
//
// # Anatomy of a message
//
// Every I2NP message has a header followed by a type-specific payload.
//
// The standard header is 16 bytes:
//
//	field        size   meaning
//	---------    ----   -------------------------------------------------
//	type         1      which message this is (see below)
//	msg_id       4      a random ID used to match replies to requests
//	expiration   8      a timestamp; the message is dropped after this time
//	size         2      length of the payload in bytes
//	checksum     1      one byte of SHA-256 over the payload, for error checks
//
// When a message travels over NTCP2 or SSU2, the transport already provides
// length and integrity checks, so the size and checksum fields are omitted and
// the header shrinks. See the I2NP specification for the exact rules:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
//
// # Message families
//
// I2NP messages fall into four groups.
//
// Network database. Routers share two kinds of records: a RouterInfo (how to
// reach a router) and a LeaseSet (how to reach a service). These messages
// store and look up those records:
//   - DatabaseStore: publish a record to the network.
//   - DatabaseLookup: ask the network for a record.
//   - DatabaseSearchReply: point a lookup at the routers that may hold it.
//   - DeliveryStatus: confirm that a stored record was received.
//
// Tunnel building. Tunnels are the private paths that carry real traffic.
// These messages set them up, with each hop encrypted separately so that no
// single router can see the whole path:
//   - ShortTunnelBuild: build a tunnel of 1 to 8 hops (the current format).
//   - VariableTunnelBuild: an older, longer format (kept for compatibility).
//
// Data delivery. Once a tunnel exists, traffic flows through it:
//   - TunnelData: one fixed-size chunk of data moving through a tunnel.
//   - TunnelGateway: a full I2NP message handed to the first hop of a tunnel.
//   - Data: a length-prefixed payload, used only inside Garlic messages.
//
// Garlic. "Garlic" is I2P's end-to-end encryption. A Garlic message bundles
// several encrypted layers into one packet so that a message can travel
// through multiple tunnels without revealing its contents or its route.
//
// # Cryptography
//
// I2NP relies on modern cryptography from github.com/go-i2p/crypto:
//   - ECIES-X25519-AEAD-Ratchet for Garlic messages.
//   - ChaCha20-Poly1305 for encrypting tunnel build records.
//
// # Usage example
//
//	// Build a DatabaseStore message for a RouterInfo.
//	ds := i2np.NewDatabaseStore(hash, data, i2np.DatabaseStoreTypeRouterInfo)
//
//	// Serialize it for transmission.
//	payload, err := ds.MarshalBinary()
//	if err != nil {
//	    log.Printf("Failed to serialize message: %v", err)
//	}
//
// # See also
//
//   - lib/tunnel for building and managing tunnels.
//   - lib/netdb for storing and looking up RouterInfo and LeaseSet records.
//   - I2NP specification: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
package i2np
