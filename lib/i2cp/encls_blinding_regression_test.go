// 003 regression tests: an EncryptedLeaseSet published by a go-i2p session must
// be keyed and signed with the *blinded* destination, never the unblinded one.
//
// Encrypted LeaseSets (netdb type 5) exist so a floodfill learns only a blinded
// identity. Three properties hold that anonymity up, and they are what these
// tests pin down:
//
//  1. The cleartext blinded_public_key field carries the blinded *signing* key
//     A' (type 11 RedDSA). If it carries the destination's X25519 encryption
//     key instead, the record identifies the destination outright.
//  2. The outer signature verifies under A' and does NOT verify under the
//     unblinded destination signing key A. A signature that verifies under A is
//     a linkability oracle: any netdb reader can test candidate destinations
//     against a published EncryptedLeaseSet.
//  3. The NetDB publication key equals the blinded lookup hash a resolver
//     computes from the destination, so the record is actually findable.
//
// Spec: https://geti2p.net/spec/encryptedleaseset sections "Blinding
// Calculations" and "Signing" ("for signing of the encrypted leaseset, we use
// Red25519 based on RedDSA to sign and verify with blinded keys").
package i2cp

import (
	"errors"
	"testing"
	"time"

	rootcommon "github.com/go-i2p/common"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/kdf"
	cryptoRed25519 "github.com/go-i2p/crypto/red25519"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/require"
)

// encLSWireBlindedKeyOffset is where the 32-byte blinded_public_key field starts
// in a serialized EncryptedLeaseSet: after the 2-byte big-endian sig_type.
const encLSWireBlindedKeyOffset = 2

// encLSWireSignatureSize is the trailing signature length (Ed25519 and RedDSA
// are both 64 bytes on the wire).
const encLSWireSignatureSize = 64

// enclsTestPublished returns a published timestamp for tests that drive the
// EncryptedLeaseSet helpers one at a time. CreateEncryptedLeaseSet takes a
// single time.Now() and threads it through the inner LeaseSet2, the inner
// encryption, and the EncryptedLeaseSet, because a reader derives the inner
// layer keys from the structure's published field; tests that call the helpers
// directly must pass the same value to each.
func enclsTestPublished() uint32 {
	return uint32(time.Now().Unix())
}

// newEncryptedLeaseSetSession builds a session configured for encrypted
// LeaseSets with one live inbound tunnel, so CreateEncryptedLeaseSet has a real
// lease to publish.
func newEncryptedLeaseSetSession(t *testing.T) *Session {
	t.Helper()

	keyStore, config := setupEncryptedLeaseSetConfig(t)
	config.LeaseSetExpiration = 600

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
		clientNetDB: netdb.NewClientNetDB(nil),
		createdAt:   time.Now(),
		active:      true,
		stopCh:      make(chan struct{}),
	}
	// One TunnelReady lease, so lease construction succeeds.
	setupSessionInboundPool(t, session)
	return session
}

// TestEncryptedLeaseSetPublishesBlindedSigningKey pins property 1: the
// blinded_public_key field must be the blinded destination's signing key.
//
// The router filled this field with blindedDestination.PublicKey(), which
// returns the *receiving* (X25519 encryption) key. KeysAndCert carries that key
// straight through from the unblinded destination when the blinded destination
// is assembled, so the published structure leaked the destination's real
// encryption key and was keyed in the NetDB under a hash no blinded lookup can
// reproduce.
func TestEncryptedLeaseSetPublishesBlindedSigningKey(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	require.NoError(t, session.updateBlindedDestination(), "derive the blinded destination")

	blindedSigning, err := session.blindedDestination.SigningPublicKey()
	require.NoError(t, err)
	destEncryption, err := session.keys.EncryptionPublicKey()
	require.NoError(t, err)

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err, "build the EncryptedLeaseSet the router would publish")

	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	require.NoError(t, err, "the published bytes must parse")

	// The wire field and the parsed accessor must agree.
	require.Equal(t, elsBytes[encLSWireBlindedKeyOffset:encLSWireBlindedKeyOffset+32],
		els.BlindedPublicKey(), "blinded key field must be read from the right wire offset")

	require.Equal(t, blindedSigning.Bytes(), els.BlindedPublicKey(),
		"blinded_public_key must be the blinded destination's SIGNING key")

	require.NotEqual(t, destEncryption.Bytes(), els.BlindedPublicKey(),
		"blinded_public_key must NOT be the destination's X25519 encryption key")

	// A blinded key is declared RedDSA (11), never the destination's Ed25519 (7).
	require.Equal(t, uint16(key_certificate.KEYCERT_SIGN_REDDSA_ED25519), els.SigType(),
		"spec: the blinded signing key type is always 11")
}

// TestEncryptedLeaseSetSignedWithBlindedKey pins property 2: the outer signature
// verifies under A' and is unlinkable from the unblinded destination key A.
func TestEncryptedLeaseSetSignedWithBlindedKey(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	destSigning, err := session.destination.SigningPublicKey()
	require.NoError(t, err)

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err)

	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	require.NoError(t, err)

	// A spec-following floodfill verifies the record under its own blinded key
	// before storing it.
	require.NoError(t, els.Verify(),
		"EncryptedLeaseSet must verify under its own blinded key")

	// Reconstruct the signed data exactly as common does: 0x05 || content-minus-signature.
	dataForSigning := append([]byte{encrypted_leaseset.ENCRYPTED_LEASESET_DBSTORE_TYPE},
		elsBytes[:len(elsBytes)-encLSWireSignatureSize]...)

	blindedAsKey, err := key_certificate.ConstructSigningPublicKeyByType(
		els.BlindedPublicKey(), int(els.SigType()),
	)
	require.NoError(t, err)

	// Positive control first, so the negative check below is meaningful and not
	// an artifact of key type or serialization offset.
	require.NoError(t,
		rootcommon.VerifySignatureData(dataForSigning, els.Signature().Bytes(),
			int(els.SigType()), blindedAsKey, "EncryptedLeaseSet"),
		"outer signature must verify under the blinded key")

	// The same signature must NOT verify under the unblinded destination key.
	// If it does, the record is linkable to the destination by anyone who can
	// read the netdb, and the feature's purpose is defeated. Checked at the
	// record's own sig type so this tests key identity, not key type.
	unblindedAsSameType, err := key_certificate.ConstructSigningPublicKeyByType(
		destSigning.Bytes(), int(els.SigType()),
	)
	require.NoError(t, err)
	require.Error(t,
		rootcommon.VerifySignatureData(dataForSigning, els.Signature().Bytes(),
			int(els.SigType()), unblindedAsSameType, "EncryptedLeaseSet"),
		"outer signature must NOT verify under the unblinded destination key (linkability)")
}

// enclsFakeNetDB stores EncryptedLeaseSets by hash so the router's own resolver
// can look one up. Only the EncryptedLeaseSet accessor is backed; the others
// report not-found, which is what forces resolution through the blinded record.
type enclsFakeNetDB struct {
	byHash map[common.Hash][]byte
}

func (f *enclsFakeNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	return nil, errENCLSNotFound
}

func (f *enclsFakeNetDB) GetLeaseSet2Bytes(hash common.Hash) ([]byte, error) {
	return nil, errENCLSNotFound
}

func (f *enclsFakeNetDB) GetMetaLeaseSetBytes(hash common.Hash) ([]byte, error) {
	return nil, errENCLSNotFound
}

func (f *enclsFakeNetDB) GetEncryptedLeaseSetBytes(hash common.Hash) ([]byte, error) {
	if data, ok := f.byHash[hash]; ok {
		return data, nil
	}
	return nil, errENCLSNotFound
}

var errENCLSNotFound = errors.New("encls: not found")

// TestEncryptedLeaseSetResolvesEndToEnd is the functional proof of the fix: a
// destination publishes an EncryptedLeaseSet, a reader holding only the
// destination resolves it, and gets back the session's X25519 key.
//
// Before the fix this failed twice over. The blinded_public_key field held the
// destination's X25519 key, so the record was stored under a hash no blinded
// lookup reproduces (lookup: not found). And even if a reader found it, the
// subcredential is derived from the blinded *signing* key, so a reader computing
// it from the real blinded key could not decrypt what the writer had encrypted
// under a subcredential built from the encryption key.
func TestEncryptedLeaseSetResolvesEndToEnd(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err)

	// Publish the way the maintenance loop does: derive the key from the
	// structure and store it.
	key, err := leaseSetPublicationKey(LeaseSetStoreTypeEncryptedLeaseSet, elsBytes)
	require.NoError(t, err)

	fake := &enclsFakeNetDB{byHash: map[common.Hash][]byte{key: elsBytes}}
	resolver := netdb.NewDestinationResolver(fake)

	dest := *session.destination
	got, err := resolver.ResolveEncryptedDestination(dest, session.blindingSecret)
	require.NoError(t, err, "a reader must resolve the published EncryptedLeaseSet")

	want, err := session.keys.EncryptionPublicKey()
	require.NoError(t, err)
	require.Equal(t, want.Bytes(), got[:],
		"resolution must return the session's X25519 encryption key from the inner LeaseSet2")

	// Spec: "After decryption, several checks should be made, including that the
	// inner timestamp and expiration match those at the top level." A single
	// time.Now() threaded through the flow is what guarantees this; three
	// separate calls can straddle a second boundary and produce a record whose
	// inner keys were derived under a different published value than the one a
	// reader recovers, i.e. permanently undecryptable.
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	require.NoError(t, err)
	inner, err := els.DecryptInnerData(subcredentialFor(t, session, &els))
	require.NoError(t, err)
	require.Equal(t, els.Published(), inner.Published(),
		"inner LeaseSet2 published must match the EncryptedLeaseSet published")
}

// subcredentialFor derives the reader-side subcredential for els, the same way
// lib/netdb does, so a test can decrypt the inner LeaseSet2 directly.
func subcredentialFor(t *testing.T, session *Session, els *encrypted_leaseset.EncryptedLeaseSet) [32]byte {
	t.Helper()
	destSigning, err := session.destination.SigningPublicKey()
	require.NoError(t, err)
	return encrypted_leaseset.DeriveSubcredential(
		destSigning.Bytes(),
		uint16(session.destination.KeyCertificate.SigningPublicKeyType()),
		els.BlindedPublicKey(),
		els.SigType(),
	)
}

// TestEncryptedLeaseSetPublicationKeyMatchesBlindedLookup pins property 3: the
// NetDB key the router publishes under must equal the blinded lookup hash a
// resolver derives from the destination, or the record is unreachable.
func TestEncryptedLeaseSetPublicationKeyMatchesBlindedLookup(t *testing.T) {
	session := newEncryptedLeaseSetSession(t)

	require.NoError(t, session.updateBlindedDestination())

	elsBytes, err := session.CreateEncryptedLeaseSet()
	require.NoError(t, err)

	pubKey, err := leaseSetPublicationKey(LeaseSetStoreTypeEncryptedLeaseSet, elsBytes)
	require.NoError(t, err)

	// Reproduce the resolver's lookup independently: derive alpha for today,
	// blind the destination's private scalar, and hash the resulting public key
	// with the spec DHT rule. lib/netdb deriveBlindedLookupHash applies the same
	// rule via encrypted_leaseset.BlindedDHTKey.
	destSigning, err := session.destination.SigningPublicKey()
	require.NoError(t, err)
	alpha, err := kdf.DeriveBlindingFactorI2P(
		destSigning.Bytes(),
		string(session.blindingSecret),
		uint16(session.destination.KeyCertificate.SigningPublicKeyType()),
		session.lastBlindingDate,
	)
	require.NoError(t, err)

	stdlibKey, err := session.stdlibSigningKey()
	require.NoError(t, err)
	redPriv, err := cryptoRed25519.ConvertEd25519PrivateKey(stdlibKey)
	require.NoError(t, err)
	blindedPriv, err := cryptoRed25519.BlindPrivateKey(redPriv, cryptoRed25519.BlindingFactor(alpha))
	require.NoError(t, err)
	expectedLookup, err := blindedPriv.Public()
	require.NoError(t, err)

	// A blinded key is always RedDSA (type 11); assert the session agrees rather
	// than trusting it, since the DHT key covers the sig type.
	require.Equal(t, uint16(key_certificate.KEYCERT_SIGN_REDDSA_ED25519),
		uint16(session.blindedDestination.KeyCertificate.SigningPublicKeyType()))

	expectedKey := encrypted_leaseset.BlindedDHTKey(
		uint16(key_certificate.KEYCERT_SIGN_REDDSA_ED25519), expectedLookup.Bytes(),
	)

	require.Equal(t, expectedKey, pubKey,
		"publication key must be SHA-256(sig type || blinded signing key), the spec DHT rule")
}
