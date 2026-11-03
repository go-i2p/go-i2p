// BlindingInfo (type 42) advice is the spec's mechanism for a client to give the
// router the blinding secret and per-client private key it needs to resolve and
// decrypt a blinded peer: "If the blinded destination requires a secret or
// per-client authentication, the client must send a Blinding Info message"
// (i2cp.rst §BlindingInfoMessage). A b33 address only flags that they are
// required and carries neither.
//
// Before this wiring, the router parsed and stored advice but no resolution path
// ever consulted it, so sending to a blinded destination could not work at all.
package i2cp

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adviceSession creates a server with one live session and returns both.
func adviceSession(t *testing.T) (*Server, *Session) {
	t.Helper()
	server := newTestI2CPServer(t, "")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { server.manager.DestroySession(session.ID()) })
	return server, session
}

// sendAdvice delivers a BlindingInfo message through the real handler.
func sendAdvice(t *testing.T, server *Server, session *Session, payload []byte) {
	t.Helper()
	msg := &Message{Type: MessageTypeBlindingInfo, SessionID: session.ID(), Payload: payload}
	var sp *Session = session
	_, err := server.handleBlindingInfo(msg, &sp)
	require.NoError(t, err, "BlindingInfo must be accepted")
}

// buildBlindingInfoDestPayload assembles a type-2 (Destination endpoint) advice.
func buildBlindingInfoDestPayload(t *testing.T, sessionID uint16, flags byte, dest *destination.Destination, privKey []byte, password string) []byte {
	t.Helper()
	destBytes, err := dest.Bytes()
	require.NoError(t, err)

	data := make([]byte, 10)
	data[2] = flags
	data[3] = BlindingEndpointDestination
	binaryPutU16(data[0:2], sessionID)
	binaryPutU16(data[4:6], 11) // blinded sig type RedDSA
	binaryPutU32(data[6:10], uint32(time.Now().Unix()+3600))
	data = append(data, destBytes...)
	if flags&blindingFlagPerClient != 0 {
		data = append(data, privKey...)
	}
	if flags&blindingFlagSecret != 0 {
		data = append(data, byte(len(password)))
		data = append(data, password...)
	}
	return data
}

// buildBlindingInfoSigKeyPayload assembles a type-3 (sig type + signing public
// key) advice, the form a "b33" address maps to: the address carries the
// destination's UNBLINDED public key.
func buildBlindingInfoSigKeyPayload(t *testing.T, sessionID uint16, flags byte, pubKey, privKey []byte, password string) []byte {
	t.Helper()

	data := make([]byte, 10)
	data[2] = flags
	data[3] = BlindingEndpointSigTypeKey
	binaryPutU16(data[0:2], sessionID)
	binaryPutU16(data[4:6], 11)
	binaryPutU32(data[6:10], uint32(time.Now().Unix()+3600))
	// Endpoint: 2-byte sig type + signing public key.
	st := make([]byte, 2)
	binaryPutU16(st, 7) // Ed25519
	data = append(data, st...)
	data = append(data, pubKey...)
	if flags&blindingFlagPerClient != 0 {
		data = append(data, privKey...)
	}
	if flags&blindingFlagSecret != 0 {
		data = append(data, byte(len(password)))
		data = append(data, password...)
	}
	return data
}

// TestBlindingAdviceMatchesDestinationEndpoint verifies advice sent with a full
// Destination endpoint is found when sending to that destination. This is the
// case where the client knows the peer's destination but not its leases.
func TestBlindingAdviceMatchesDestinationEndpoint(t *testing.T) {
	server, session := adviceSession(t)

	dest, err := createTestDestination()
	require.NoError(t, err)

	privKey := newTestKeyBytes(t)
	sendAdvice(t, server, session,
		buildBlindingInfoDestPayload(t, session.ID(), blindingFlagPerClient, dest, privKey, ""))

	found, ok := server.blindingAdviceForDestination(dest)
	require.True(t, ok, "advice must be found for the destination it names")
	assert.Equal(t, privKey, found.PrivateKey)
	assert.True(t, found.IsPerClient())
}

// TestBlindingAdviceMatchesSigTypeKeyEndpoint covers the b33 form: the address
// gives the unblinded signing public key, and a send carries the destination, so
// the two have to be matched on that key.
func TestBlindingAdviceMatchesSigTypeKeyEndpoint(t *testing.T) {
	server, session := adviceSession(t)

	dest, err := createTestDestination()
	require.NoError(t, err)
	spk, err := dest.SigningPublicKey()
	require.NoError(t, err)

	privKey := newTestKeyBytes(t)
	sendAdvice(t, server, session,
		buildBlindingInfoSigKeyPayload(t, session.ID(), blindingFlagPerClient, spk.Bytes(), privKey, ""))

	found, ok := server.blindingAdviceForDestination(dest)
	require.True(t, ok, "advice keyed by the unblinded public key must match the destination")
	assert.Equal(t, privKey, found.PrivateKey)

	// A different destination must not match.
	other, err := createTestDestination()
	require.NoError(t, err)
	_, ok = server.blindingAdviceForDestination(other)
	assert.False(t, ok, "advice must not match an unrelated destination")
}

// TestBlindingAdviceMatchesHashEndpoint covers a client that advised using the
// destination hash directly.
func TestBlindingAdviceMatchesHashEndpoint(t *testing.T) {
	server, session := adviceSession(t)

	dest, err := createTestDestination()
	require.NoError(t, err)
	h, err := dest.Hash()
	require.NoError(t, err)

	sendAdvice(t, server, session,
		buildBlindingInfoHashPayload(session.ID(), blindingFlagPerClient, h[:], newTestKeyBytes(t), ""))

	found, ok := server.blindingAdviceForDestination(dest)
	require.True(t, ok, "advice with a destination-hash endpoint must match")
	assert.True(t, found.IsPerClient())
}

// TestBlindingAdviceExpiredIgnored pins that stale key material is not trusted.
// Expiration was previously only logged; now that advice is what unlocks
// decryption of a peer's leases, an expired entry must be skipped.
func TestBlindingAdviceExpiredIgnored(t *testing.T) {
	server, session := adviceSession(t)

	dest, err := createTestDestination()
	require.NoError(t, err)
	h, err := dest.Hash()
	require.NoError(t, err)

	payload := make([]byte, 10)
	payload[2] = blindingFlagPerClient
	payload[3] = BlindingEndpointHash
	binaryPutU16(payload[0:2], session.ID())
	binaryPutU16(payload[4:6], 11)
	// Expiration in the past.
	binaryPutU32(payload[6:10], uint32(time.Now().Unix()-60))
	payload = append(payload, h[:]...)
	payload = append(payload, newTestKeyBytes(t)...)

	sendAdvice(t, server, session, payload)

	_, ok := server.blindingAdviceForDestination(dest)
	assert.False(t, ok, "expired advice must not be used")

	// Still retrievable by raw hash lookup, which is the accessor clients of the
	// API may use directly; the send path applies the expiry rule.
	_, ok = server.BlindingAdviceFor(hashKey(h[:]))
	assert.True(t, ok, "the entry is still stored; matching is what excludes it")
}

// TestClientCredentialFromAdviceSchemes checks the flag bits 3-1 scheme field is
// mapped to the right credential type, and that a scheme the spec does not define
// is refused rather than guessed at.
func TestClientCredentialFromAdviceSchemes(t *testing.T) {
	key := newTestKeyBytes(t)

	dh := &BlindingInfoPayload{Flags: blindingFlagPerClient, PrivateKey: key}
	require.NotNil(t, clientCredentialFromAdvice(dh))
	assert.Equal(t, encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		clientCredentialFromAdvice(dh).AuthType)
	assert.Equal(t, key, clientCredentialFromAdvice(dh).DHPrivateKey)

	psk := &BlindingInfoPayload{
		Flags:      blindingFlagPerClient | (blindingAuthSchemePSK << 1),
		PrivateKey: key,
	}
	require.NotNil(t, clientCredentialFromAdvice(psk))
	assert.Equal(t, encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
		clientCredentialFromAdvice(psk).AuthType)
	assert.Equal(t, key, clientCredentialFromAdvice(psk).PSK)

	// Not per-client: open record, no credential.
	assert.Nil(t, clientCredentialFromAdvice(&BlindingInfoPayload{PrivateKey: key}))

	// Per-client but no key supplied: nothing to build a credential from.
	assert.Nil(t, clientCredentialFromAdvice(&BlindingInfoPayload{Flags: blindingFlagPerClient}))

	// Undefined scheme (bits 3-1 = 010).
	assert.Nil(t, clientCredentialFromAdvice(&BlindingInfoPayload{
		Flags:      blindingFlagPerClient | (2 << 1),
		PrivateKey: key,
	}), "undefined auth scheme must not be guessed")
}

// TestResolveDestinationKeyForPeerPerClientEndToEnd is the full router path:
// a session publishes a per-client EncryptedLeaseSet, a second session advises
// the router with its DH private key, and the router resolves the peer's X25519
// key for sending. Without the advice wiring this cannot work, because a blinded
// record is not reachable from the destination hash alone.
func TestResolveDestinationKeyForPeerPerClientEndToEnd(t *testing.T) {
	server, sender := adviceSession(t)

	publisher := newEncryptedLeaseSetSession(t)

	clientPub, clientPriv := newAuthorizedClient(t)
	elsBytes := publishPerClientEncLS(t, publisher, [][]byte{clientPub})

	key, err := publicationKeyForTest(t, elsBytes)
	require.NoError(t, err)
	server.SetDestinationResolver(netdb.NewDestinationResolver(newENCLSNetDB(key, elsBytes)))

	dest := publisher.destination
	destHash := mustDestHash(t, dest)
	spk, err := dest.SigningPublicKey()
	require.NoError(t, err)

	// No advice recorded yet: the router cannot find the blinded record, since
	// it is stored under the blinded DHT key rather than the destination hash.
	_, err = server.resolveDestinationKeyForPeer(dest, destHash)
	require.Error(t, err, "without advice the blinded peer is unresolvable")

	// Advice with the key but NOT the secret still fails, for the same reason.
	sendAdvice(t, server, sender,
		buildBlindingInfoSigKeyPayload(t, sender.ID(),
			blindingFlagPerClient, spk.Bytes(), clientPriv, ""))
	_, err = server.resolveDestinationKeyForPeer(dest, destHash)
	require.Error(t, err, "advice without the blinding secret must not resolve")

	// The sending client advises the router of the blinded peer, its per-client
	// key, and the blinding secret. The secret is required, not incidental:
	// GENERATE_ALPHA mixes it in, so a reader without it derives a different
	// blinded key and looks up a hash the record was never stored under.
	sendAdvice(t, server, sender,
		buildBlindingInfoSigKeyPayload(t, sender.ID(),
			blindingFlagPerClient|blindingFlagSecret, spk.Bytes(), clientPriv,
			string(publisher.config.BlindingSecret)))

	got, err := server.resolveDestinationKeyForPeer(dest, destHash)
	require.NoError(t, err, "with advice the blinded peer must resolve")

	want, err := publisher.keys.EncryptionPublicKey()
	require.NoError(t, err)
	assert.Equal(t, want.Bytes(), got[:],
		"resolved key must be the publisher's X25519 encryption key")
}

// TestResolveDestinationKeyForPeerCleartextUnaffected asserts destinations with
// a cleartext LeaseSet still resolve exactly as before, so the blinded path is
// strictly additive.
func TestResolveDestinationKeyForPeerCleartextUnaffected(t *testing.T) {
	server, _ := adviceSession(t)

	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	destHash, err := leaseSetPublicationKey(LeaseSetStoreTypeLeaseSet2, ls2Bytes)
	require.NoError(t, err)

	server.SetDestinationResolver(netdb.NewDestinationResolver(
		newENCLSNetDB(destHash, ls2Bytes),
	))

	// The cleartext path is reached through ResolveDestination, which reads the
	// LeaseSet2 buckets; the fake only answers EncLS lookups, so use a resolver
	// stub that mimics a cleartext-only resolver.
	stub := &cleartextOnlyResolver{key: [32]byte{1, 2, 3}}
	server.SetDestinationResolver(stub)

	got, err := server.resolveDestinationKeyForPeer(session.destination, destHash)
	require.NoError(t, err)
	assert.Equal(t, [32]byte{1, 2, 3}, got, "cleartext resolver must still be used")
}

// cleartextOnlyResolver implements only ResolveDestination, the shape existing
// resolvers and test stubs have. The server must use it without requiring the
// blinded capability.
type cleartextOnlyResolver struct{ key [32]byte }

func (r *cleartextOnlyResolver) ResolveDestination(common.Hash) ([32]byte, error) {
	return r.key, nil
}

// helpers

func binaryPutU16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func binaryPutU32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func mustDestHash(t *testing.T, dest *destination.Destination) common.Hash {
	t.Helper()
	h, err := dest.Hash()
	require.NoError(t, err)
	return h
}
