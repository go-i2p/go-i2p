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
// # Tunnel build message coverage (known gap)
//
// This package implements the short-record tunnel build pair only:
// ShortTunnelBuild (type 25) and OutboundTunnelBuildReply (type 26), which
// carry 218-byte ECIES-X25519 records and require every hop to be an
// ECIES-X25519 router at version 0.9.51 or newer
// (tunnel-creation-ecies.rst:538-539).
//
// The four 528-byte-record build messages are NOT handled: TunnelBuild (21),
// TunnelBuildReply (22), VariableTunnelBuild (23) and VariableTunnelBuildReply
// (24). All four are recognised by the message dispatch and dropped there with
// a debug-level log; none is parsed, so no record of a build or reply in the
// long format is ever read. (The types are declared in constants.go precisely
// so that they are dropped as the defined messages they are rather than
// reported as "unknown message type".)
//
// This is a deliberate scope decision, not a specification allowance, and it
// should not be read as "these messages are deprecated". Two caveats matter to
// anyone assessing interop:
//
//   - The specification's message-type table (i2np.rst:691-692) labels 21/22
//     "deprecated", but the normative Notes for those same messages say they
//     "may still be used for very long tunnels, and has not been deprecated.
//     Routers must implement." (i2np.rst:1581-1583, :1607-1609).
//   - The 528-byte records that 21-24 carry are what a tunnel needs whenever
//     any hop is an ElGamal router: i2np.rst:268 describes the ElGamal record
//     as "only used in the current network when a tunnel contains an ElGamal
//     router", and tunnel-creation-ecies.rst:543 scopes the 218-byte records to
//     types 25/26 "compared to 528 bytes for all other build messages". Because
//     this package also has no ElGamal record crypto, a tunnel that includes an
//     ElGamal router cannot be built or accepted here.
//
// The registry's fourth column is the "Since" column, not a deprecation column
// — i2np.rst:693 reads "VariableTunnelBuild_ 23 0.7.12" — so a version number
// in that column means "introduced in", not "obsolete".
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
//   - ShortTunnelBuild: build a tunnel of 1 to 8 hops, and its
//     OutboundTunnelBuildReply. This is the only build pair implemented — see
//     "Tunnel build message coverage (known gap)" above for the messages that
//     are not, and why the short-record pair cannot replace them when a hop is
//     an ElGamal router.
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
