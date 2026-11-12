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
// # Read timeouts
//
// Two independent timeouts govern reading from an I2CP connection, and they
// bound different things. Conflating them caused issue #54, where an idle
// client was disconnected exactly 30 s after the GetDate/SetDate exchange.
//
//   - MessageReadTimeout (30 s) bounds only the bytes of a single message, and
//     only once that message's header has been read. It exists to stop
//     slow-send attacks: a peer that declares a large payload and then
//     drip-feeds it. It is refreshed on each body read, so a stalled transfer
//     mid-message is still cut off. It is a local default, not a value stated
//     by the I2CP spec -- the spec fixes the header framing (length(4) +
//     type(1)) but prescribes no read deadline. The 65535-byte payload cap
//     beside it is likewise an i2pd interop limit, not a spec value.
//
//   - ServerConfig.ReadTimeout bounds the idle gap between messages, i.e. the
//     wait for the next header. I2CP clients are expected to hold a long-lived
//     connection and may be idle on it for a long time -- an application
//     commonly connects at startup and creates its first session much later,
//     which is the ordinary SAM-bridge topology. So the default is 0, meaning
//     no idle timeout is enforced and an idle client is never disconnected for
//     inactivity.
//
// To enable idle enforcement, set ServerConfig.ReadTimeout to a value a
// legitimate client cannot reach while idle between messages -- 5 minutes is a
// reasonable choice. Do not set it low: the previous 60 s default killed normal
// long-lived client connections.
//
// A timeout while waiting for a header is not an error: the connection stays
// open, the deadline is re-armed, and nothing is logged at warn level per
// occurrence. A timeout during body/flag/payload continuation is fatal, so
// malformed or truncated input never becomes survivable. Both cases are
// distinguished with errors.Is(err, os.ErrDeadlineExceeded) and
// net.Error.Timeout(), never by comparing error strings.
//
// Only the read goroutine sets read deadlines, once per iteration, so
// SetReadDeadline never races a concurrent writer on the same connection. The
// read path also takes a context.Context, so shutdown cancels a blocked header
// read instead of waiting out a deadline.
//
// # Known limitations
//
// HostLookup does not return blinded (EncryptedLeaseSet) destinations. A
// blinded record is stored under SHA-256(sig type || blinded public key),
// which cannot be derived from the 32-byte hash a type 0/2 lookup carries --
// it needs the unblinded destination and the blinding secret. Blinded peers
// are reached through the send path (see "Encrypted LeaseSets" above), which
// has both; a client that wants a blinded destination's leases should send to
// it rather than look it up.
//
// Message reliability: the i2cp.messageReliability option is parsed and
// stored, but all reliability modes (BestEffort, Guaranteed, None) are
// currently treated as BestEffort. Guaranteed-delivery acknowledgment
// tracking is not implemented. Applications that need guaranteed delivery
// must add their own acknowledgment layer (for example, via the go-streaming
// library).
package i2cp
