// Tests for destination lease resolution, the addressing half of the I2P-002 fix.
//
// A sender cannot address a tunnel message without the destination's inbound
// gateway and gateway tunnel ID, so every case here is about either producing a
// correct LeaseTarget or refusing to produce one. Refusing matters as much as
// resolving: the send path has no unencapsulated fallback, so a resolver that
// invented an address would send traffic into the void.

package i2cp

import (
	"errors"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	elg "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLeaseSetFetcher is a LeaseSetFetcher with canned per-generation payloads.
type stubLeaseSetFetcher struct {
	ls1     []byte
	ls1Err  error
	ls2     []byte
	ls2Err  error
	ls1Call int
	ls2Call int
}

func (f *stubLeaseSetFetcher) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	f.ls1Call++
	return f.ls1, f.ls1Err
}

func (f *stubLeaseSetFetcher) GetLeaseSet2Bytes(hash common.Hash) ([]byte, error) {
	f.ls2Call++
	return f.ls2, f.ls2Err
}

// leaseSet2WithLeases re-signs an existing LeaseSet2 with a different lease set,
// reusing its destination, keys and options so the result stays valid.
func leaseSet2WithLeases(t *testing.T, session *Session, ls2Bytes []byte, leases []lease.Lease2) []byte {
	t.Helper()

	ls2, _, err := lease_set2.ReadLeaseSet2(ls2Bytes)
	require.NoError(t, err)

	signingKey, err := session.stdlibSigningKey()
	require.NoError(t, err)

	rebuilt, err := lease_set2.NewLeaseSet2(
		ls2.Destination(),
		ls2.Published(),
		ls2.Expires(),
		ls2.Flags(),
		ls2.OfflineSignature(),
		ls2.Options(),
		ls2.EncryptionKeys(),
		leases,
		signingKey,
	)
	require.NoError(t, err)

	out, err := rebuilt.Bytes()
	require.NoError(t, err)
	return out
}

func mustLease2(t *testing.T, gateway common.Hash, tunnelID uint32, expires time.Time) lease.Lease2 {
	t.Helper()
	l, err := lease.NewLease2(gateway, tunnelID, expires)
	require.NoError(t, err)
	return *l
}

func mustLease1(t *testing.T, gateway common.Hash, tunnelID uint32, expires time.Time) lease.Lease {
	t.Helper()
	l, err := lease.NewLease(gateway, tunnelID, expires)
	require.NoError(t, err)
	return *l
}

// leaseSet1WithLeases builds a signed classic v1 LeaseSet for a fresh ElGamal
// destination. LeaseSet v1 mandates ElGamal crypto, so it cannot reuse the
// X25519 destination the LeaseSet2 fixture uses.
func leaseSet1WithLeases(t *testing.T, leases []lease.Lease) []byte {
	t.Helper()

	encPub, _, err := elg.GenerateKeyPair()
	require.NoError(t, err)

	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	sigKey, err := keyStore.SigningPublicKey()
	require.NoError(t, err)

	cert, err := key_certificate.NewKeyCertificateWithTypes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_ELG,
	)
	require.NoError(t, err)

	kac, err := keys_and_cert.NewKeysAndCert(
		cert,
		encPub,
		make([]byte, keys_and_cert.ExpectedPaddingSize(cert.CryptoSize(), cert.SigningPublicKeySize())),
		sigKey,
	)
	require.NoError(t, err)

	dest, err := destination.NewDestination(kac)
	require.NoError(t, err)

	ls, err := lease_set.NewLeaseSet(*dest, encPub, sigKey, leases, keyStore.SigningPrivateKey())
	require.NoError(t, err)

	out, err := ls.Bytes()
	require.NoError(t, err)
	return out
}

// ── resolving ───────────────────────────────────────────────────────────────

func TestLeaseResolver_LeaseSet2LiveLease(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	var gateway common.Hash
	copy(gateway[:], "resolver-gateway-hash-32-bytes!!")

	fetcher := &stubLeaseSetFetcher{
		ls2: leaseSet2WithLeases(t, session, ls2Bytes,
			[]lease.Lease2{mustLease2(t, gateway, 0x11223344, time.Now().Add(10*time.Minute))}),
	}
	r := NewLeaseResolver(fetcher)

	target, err := r.ResolveLease(createTestHash())
	require.NoError(t, err)

	assert.Equal(t, gateway, target.GatewayHash, "must report the lease's inbound gateway")
	assert.Equal(t, uint32(0x11223344), target.TunnelID, "must report the lease's gateway tunnel ID")
	assert.False(t, target.IsZero())
	assert.Equal(t, 1, fetcher.ls2Call, "LeaseSet2 is tried first")
	assert.Zero(t, fetcher.ls1Call, "a usable LeaseSet2 must not trigger a v1 lookup")
}

func TestLeaseResolver_PicksLatestExpiringLiveLease(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	var oldest, middle, newest common.Hash
	copy(oldest[:], "lease-gw-oldest-hash-32-bytes!!!")
	copy(middle[:], "lease-gw-middle-hash-32-bytes!!!")
	copy(newest[:], "lease-gw-newest-hash-32-bytes!!!")

	now := time.Unix(1_800_000_000, 0)
	fetcher := &stubLeaseSetFetcher{
		ls2: leaseSet2WithLeases(t, session, ls2Bytes, []lease.Lease2{
			mustLease2(t, oldest, 1, now.Add(-30*time.Second)), // already expired
			mustLease2(t, middle, 2, now.Add(2*time.Minute)),   // live
			mustLease2(t, newest, 3, now.Add(9*time.Minute)),   // live, latest
		}),
	}
	r := NewLeaseResolver(fetcher)
	r.now = func() time.Time { return now }

	target, err := r.ResolveLease(createTestHash())
	require.NoError(t, err)
	assert.Equal(t, newest, target.GatewayHash, "must prefer the latest-expiring live lease")
	assert.Equal(t, uint32(3), target.TunnelID)
}

func TestLeaseResolver_FallsBackToLeaseSet1(t *testing.T) {
	var gateway common.Hash
	copy(gateway[:], "v1-lease-gateway-hash-32-bytes!!")

	fetcher := &stubLeaseSetFetcher{
		ls1:    leaseSet1WithLeases(t, []lease.Lease{mustLease1(t, gateway, 0xAABB, time.Now().Add(5*time.Minute))}),
		ls2Err: errors.New("not found"),
	}
	r := NewLeaseResolver(fetcher)

	target, err := r.ResolveLease(createTestHash())
	require.NoError(t, err)
	assert.Equal(t, gateway, target.GatewayHash)
	assert.Equal(t, uint32(0xAABB), target.TunnelID)
	assert.Equal(t, 1, fetcher.ls2Call)
	assert.Equal(t, 1, fetcher.ls1Call, "must fall back to the classic LeaseSet")
}

// ── refusing ────────────────────────────────────────────────────────────────

func TestLeaseResolver_NoLeaseSetAtAll(t *testing.T) {
	fetcher := &stubLeaseSetFetcher{ls1Err: errors.New("miss"), ls2Err: errors.New("miss")}
	r := NewLeaseResolver(fetcher)

	_, err := r.ResolveLease(createTestHash())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoLease, "must report no usable lease")
}

func TestLeaseResolver_AllLeasesExpired(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	var gateway common.Hash
	copy(gateway[:], "expired-lease-gateway-hash-32b!!")

	now := time.Unix(1_800_000_000, 0)
	fetcher := &stubLeaseSetFetcher{
		ls2: leaseSet2WithLeases(t, session, ls2Bytes, []lease.Lease2{
			mustLease2(t, gateway, 1, now.Add(-time.Minute)),
			mustLease2(t, gateway, 2, now.Add(-2*time.Minute)),
		}),
	}
	r := NewLeaseResolver(fetcher)
	r.now = func() time.Time { return now }

	_, err := r.ResolveLease(createTestHash())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoLease, "expired leases must never be used for addressing")
}

func TestLeaseResolver_GarbageLeaseSetBytes(t *testing.T) {
	fetcher := &stubLeaseSetFetcher{
		ls1: []byte("this is not a lease set"),
		ls2: []byte("this is not a lease set2"),
	}
	r := NewLeaseResolver(fetcher)

	_, err := r.ResolveLease(createTestHash())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoLease, "unparseable lease sets must fail closed")
}

func TestLeaseResolver_NilFetcherNeverResolves(t *testing.T) {
	r := NewLeaseResolver(nil)
	_, err := r.ResolveLease(createTestHash())
	require.Error(t, err, "a resolver without a NetDB accessor must refuse, not guess")
}

// ── wiring into the send path ───────────────────────────────────────────────

func TestLeaseResolver_SatisfiesDestinationLeaseResolver(t *testing.T) {
	// The router wires NewLeaseResolver(r.netdb) into the message router; this
	// compile-time assertion keeps the two interfaces from drifting apart.
	var resolver DestinationLeaseResolver = NewLeaseResolver(&stubLeaseSetFetcher{})
	require.NotNil(t, resolver)
}

func TestLeaseTarget_IsZero(t *testing.T) {
	assert.True(t, LeaseTarget{}.IsZero())

	var gateway common.Hash
	gateway[0] = 1
	assert.False(t, LeaseTarget{TunnelID: 7}.IsZero())
	assert.False(t, LeaseTarget{GatewayHash: gateway}.IsZero())
}
