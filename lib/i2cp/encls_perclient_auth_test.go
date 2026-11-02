// Per-client authorization for EncryptedLeaseSet (spec §"Per-client authorization").
//
// By default an EncryptedLeaseSet is readable by anybody who knows the
// destination: the blinded record is public and only the inner LeaseSet2 is
// encrypted, under a subcredential derived from the destination's signing public
// key. Per-client authorization goes further: a per-publication authCookie is
// encrypted to each authorized client (DH to cpk_i, or PSK), and the Layer 2 key
// is derived from that cookie, so only an authorized client can read the leases.
//
// These tests drive the real router code on both sides - a session publishing
// with a client list, and the netdb resolver reading it back - rather than
// calling common directly, because the gap being closed was in the wiring:
// common already implemented the scheme, and nothing on either side used it.
package i2cp

import (
	"crypto/rand"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/require"
)

// newAuthorizedClient returns a fresh X25519 key pair standing in for a client
// the destination has authorized: cpk_i to the publisher, csk_i to the reader.
func newAuthorizedClient(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pubKey, privKey, err := curve25519.GenerateKeyPair()
	require.NoError(t, err)
	return pubKey.Bytes(), privKey.Bytes()
}

// newTestKeyBytes returns 32 random bytes, usable as a key that was never
// authorized.
func newTestKeyBytes(t *testing.T) []byte {
	t.Helper()
	var b [32]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return b[:]
}

// dhCredential builds a DH client credential from csk_i.
func dhCredential(priv []byte) *encrypted_leaseset.ClientCredential {
	return &encrypted_leaseset.ClientCredential{
		AuthType:     encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHPrivateKey: priv,
	}
}

// publicationKeyForTest derives the NetDB key an EncryptedLeaseSet is stored
// under, using the same production helper the publish path uses.
func publicationKeyForTest(t *testing.T, elsBytes []byte) (common.Hash, error) {
	t.Helper()
	return leaseSetPublicationKey(LeaseSetStoreTypeEncryptedLeaseSet, elsBytes)
}

// newENCLSNetDB builds a fake netdb holding one EncryptedLeaseSet under key.
func newENCLSNetDB(key common.Hash, data []byte) *enclsFakeNetDB {
	return &enclsFakeNetDB{byHash: map[common.Hash][]byte{key: data}}
}

// newDestinationResolverForTest wraps the netdb resolver constructor.
func newDestinationResolverForTest(fake *enclsFakeNetDB) *netdb.DestinationResolver {
	return netdb.NewDestinationResolver(fake)
}

// publishPerClientEncLS configures session with per-client DH authorization for
// the given client public keys and returns the serialized EncryptedLeaseSet the
// router would publish.
func publishPerClientEncLS(t *testing.T, session *Session, clientPubKeys [][]byte) []byte {
	t.Helper()

	require.NoError(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType:           encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: clientPubKeys,
	}))

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err, "publish with per-client auth")
	return elsBytes
}

// TestEncryptedLeaseSetClientAuthRoundTrip is the core capability test: with
// per-client DH authorization, an authorized client resolves the destination and
// recovers the X25519 key, and an unauthorized client cannot.
func TestEncryptedLeaseSetClientAuthRoundTrip(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	clientPub, clientPriv := newAuthorizedClient(t)
	otherPub, otherPriv := newAuthorizedClient(t)

	elsBytes := publishPerClientEncLS(t, session, [][]byte{clientPub, otherPub})

	key, err := publicationKeyForTest(t, elsBytes)
	require.NoError(t, err)
	fake := newENCLSNetDB(key, elsBytes)
	resolver := newDestinationResolverForTest(fake)

	dest := *session.destination
	want, err := session.keys.EncryptionPublicKey()
	require.NoError(t, err)

	// An authorized client decrypts and resolves.
	authorized, err := resolver.ResolveEncryptedDestinationWithCredential(
		dest, session.blindingSecret, dhCredential(clientPriv))
	require.NoError(t, err, "authorized client must resolve")
	require.Equal(t, want.Bytes(), authorized[:],
		"authorized client must recover the session's X25519 key")

	// A client that was not given the cookie cannot, even though it can see the
	// blinded record and derive the subcredential.
	unauthorized, err := resolver.ResolveEncryptedDestinationWithCredential(
		dest, session.blindingSecret, dhCredential(newTestKeyBytes(t)))
	require.Error(t, err, "unauthorized client must not resolve")
	require.Equal(t, [32]byte{}, unauthorized)

	// No credential at all also fails: the record is per-client, not open.
	_, err = resolver.ResolveEncryptedDestinationWithCredential(dest, session.blindingSecret, nil)
	require.Error(t, err, "missing credential must not resolve a per-client record")

	// Sanity: otherPub is genuinely authorized too, so the failure above is
	// about authorization and not about the credential form.
	alsoOK, err := resolver.ResolveEncryptedDestinationWithCredential(
		dest, session.blindingSecret, dhCredential(otherPriv))
	require.NoError(t, err, "second authorized client must resolve")
	require.Equal(t, want.Bytes(), alsoOK[:])
}

// TestEncryptedLeaseSetClientAuthPSKRoundTrip covers the PSK scheme.
func TestEncryptedLeaseSetClientAuthPSKRoundTrip(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	psk := newTestKeyBytes(t)
	require.NoError(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType:      encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
		PSKClientKeys: [][]byte{psk},
	}))

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err)

	key, err := publicationKeyForTest(t, elsBytes)
	require.NoError(t, err)
	resolver := newDestinationResolverForTest(newENCLSNetDB(key, elsBytes))
	dest := *session.destination

	got, err := resolver.ResolveEncryptedDestinationWithCredential(
		dest, session.blindingSecret,
		&encrypted_leaseset.ClientCredential{
			AuthType: encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
			PSK:      psk,
		})
	require.NoError(t, err, "PSK client must resolve")

	want, err := session.keys.EncryptionPublicKey()
	require.NoError(t, err)
	require.Equal(t, want.Bytes(), got[:])

	// Wrong PSK fails.
	_, err = resolver.ResolveEncryptedDestinationWithCredential(
		dest, session.blindingSecret,
		&encrypted_leaseset.ClientCredential{
			AuthType: encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
			PSK:      newTestKeyBytes(t),
		})
	require.Error(t, err, "wrong PSK must not resolve")
}

// TestEncryptedLeaseSetClientAuthDefaultIsOpen pins that the existing behavior
// is unchanged when no client list is configured: auth type 0, readable with no
// credential. This is what keeps the feature opt-in.
func TestEncryptedLeaseSetClientAuthDefaultIsOpen(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err)

	key, err := publicationKeyForTest(t, elsBytes)
	require.NoError(t, err)
	resolver := newDestinationResolverForTest(newENCLSNetDB(key, elsBytes))
	dest := *session.destination

	got, err := resolver.ResolveEncryptedDestinationWithCredential(dest, session.blindingSecret, nil)
	require.NoError(t, err, "auth type 0 must resolve with no credential")

	want, err := session.keys.EncryptionPublicKey()
	require.NoError(t, err)
	require.Equal(t, want.Bytes(), got[:])
}

// TestEncryptedLeaseSetClientAuthRejectsBadConfig asserts a malformed client
// list is refused when it is supplied, not at regeneration time.
func TestEncryptedLeaseSetClientAuthRejectsBadConfig(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	// DH with no clients.
	require.Error(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType: encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
	}), "DH auth with no client keys must be rejected")

	// Wrong key size.
	require.Error(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType:           encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: [][]byte{{1, 2, 3}},
	}), "short client key must be rejected")

	// A rejected config must not leave a partial setting behind.
	require.Nil(t, session.EncryptedLeaseSetClientAuth())

	// Unknown auth type.
	require.Error(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType:      42,
		PSKClientKeys: [][]byte{newTestKeyBytes(t)},
	}), "unknown auth type must be rejected")
}

// TestEncryptedLeaseSetClientAuthClears verifies nil config restores auth type 0.
func TestEncryptedLeaseSetClientAuthClears(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	pub, _ := newAuthorizedClient(t)
	require.NoError(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType:           encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: [][]byte{pub},
	}))
	require.NotNil(t, session.EncryptedLeaseSetClientAuth())

	require.NoError(t, session.SetEncryptedLeaseSetClientAuth(nil))
	require.Nil(t, session.EncryptedLeaseSetClientAuth())

	// And the published record is open again.
	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err)
	key, err := publicationKeyForTest(t, elsBytes)
	require.NoError(t, err)
	resolver := newDestinationResolverForTest(newENCLSNetDB(key, elsBytes))

	_, err = resolver.ResolveEncryptedDestinationWithCredential(
		*session.destination, session.blindingSecret, nil)
	require.NoError(t, err, "cleared config must publish an open record")
}

// TestEncryptedLeaseSetClientAuthCopiesInput asserts the router copies the client
// list, so a caller mutating its own slices cannot change what is published.
func TestEncryptedLeaseSetClientAuthCopiesInput(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	pub, _ := newAuthorizedClient(t)
	// Keep the exact key the record was authorized for, to check resolution below.
	exact := make([]byte, len(pub))
	copy(exact, pub)

	list := [][]byte{pub}
	require.NoError(t, session.SetEncryptedLeaseSetClientAuth(&encrypted_leaseset.ClientAuthConfig{
		AuthType:           encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: list,
	}))

	// Clobber the caller's buffer after handing it over.
	for i := range list[0] {
		list[0][i] = 0xFF
	}

	stored := session.EncryptedLeaseSetClientAuth()
	require.NotNil(t, stored)
	require.Equal(t, exact, stored.DHClientPublicKeys[0],
		"stored client key must be a copy, not a reference to the caller's slice")
}
