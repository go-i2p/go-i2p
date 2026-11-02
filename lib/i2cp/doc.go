// Package i2cp implements the I2P Client Protocol (I2CP) server.
//
// # What is I2CP?
//
// I2CP is the interface that lets ordinary applications talk to the I2P
// network. Instead of speaking I2P's wire protocols directly, an application
// connects to a local I2CP server and uses a simple request/response protocol
// to:
//
//   - Create sessions with a destination keypair (its I2P identity).
//   - Send and receive messages through tunnels.
//   - Publish a LeaseSet so others can reach it.
//
// The server listens on localhost:7654 by default (configurable via
// --i2cp.address). Protocol version: I2CP v0.9.67.
//
// I2CP is defined in the I2P specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2cp.rst
//
// # Main components
//
//   - Server: handles TCP and Unix socket connections.
//   - Session: manages a client session and its tunnel pool.
//   - MessageRouter: routes messages through the tunnel system.
//   - Publisher: publishes LeaseSets to the NetDB.
//
// # Encrypted LeaseSets
//
// A destination can publish an EncryptedLeaseSet (type 5) so that a floodfill
// learns only a per-day blinded identity, never the destination itself. See
// github.com/go-i2p/common/encrypted_leaseset for the wire format and the
// blinding math.
//
// Publishing: set the i2cp.encryptLeaseSet session option (or
// SessionConfig.UseEncryptedLeaseSet) and the session builds the record with
// CreateEncryptedLeaseSet. The session derives the day's blinded destination
// (A') and the matching blinded private scalar (a'), signs the outer record
// with a' using RedDSA (signature type 11), and publishes A' as the blinded key
// -- never the destination's own signing or encryption key, which would defeat
// the anonymity the record exists to provide.
//
// Per-client authorization restricts decryption to a list of authorized
// clients. The publisher calls Session.SetEncryptedLeaseSetClientAuth with a
// ClientAuthConfig (nil clears it, leaving the record open to any holder of the
// blinding secret). Two schemes are supported: DH (auth type 1), where each
// client supplies an X25519 public key and the authCookie is sealed per client
// with an ephemeral X25519 exchange; and PSK (auth type 2), where each client
// shares a 32-byte pre-shared key. Client keys arrive out of band (the spec
// provides no I2CP wire options for them), so they are configured
// programmatically rather than through session options.
//
// Resolving: a client sends the peer's blinding parameters with a BlindingInfo
// (type 42) message, which the server records as advice keyed by the blinded
// destination. When routing a message to a blinded destination the server looks
// up that advice and resolves through the NetDB with the appropriate credential
// (see netdb.DestinationResolver.ResolveDestinationWithCredential). The local
// client's DH private keys are held by Session.StorePrivateKeys; the PSK and
// lookup password travel in the BlindingInfo advice itself.
//
// # Known limitations
//
// EncryptedLeaseSet DHT key: records are stored under SHA-256 of the blinded
// public key, but the spec (proposal 123, "Encrypted LeaseSet" lookup) calls for
// SHA-256 over the signature type and the blinded public key together. go-i2p is
// self-consistent, so publish/lookup round-trips within this network, but the
// records will not line up with a spec-following Java or i2pd floodfill.
//
// HostReply result codes: a failed blinded lookup is reported as timeout (2) or
// generic failure (3). The spec (i2cp.rst, HostReply) reserves those for
// "lookup password required" (2), "private key required" (3), "both required"
// (4), and "decryption failure" (5); a b33 client relies on those codes to
// learn that it must supply a secret or a client key.
//
// Message reliability: the i2cp.messageReliability option is parsed and
// stored, but all reliability modes (BestEffort, Guaranteed, None) are
// currently treated as BestEffort. Guaranteed-delivery acknowledgment
// tracking is not implemented. Applications that need guaranteed delivery
// must add their own acknowledgment layer (for example, via the go-streaming
// library).
package i2cp
