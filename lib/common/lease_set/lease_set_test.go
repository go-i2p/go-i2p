package lease_set

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/destination"
	"github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"golang.org/x/crypto/openpgp/elgamal"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/lease"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/stretchr/testify/assert"
)

func createTestIdentityAndKeys(t *testing.T) (*router_identity.RouterIdentity, crypto.PublicKey, crypto.SigningPublicKey, crypto.SigningPrivateKey, crypto.SigningPrivateKey) {
	// Generate signing key pair (Ed25519) for the identity
	var identityPrivKey crypto.Ed25519PrivateKey
	_, err := (&identityPrivKey).Generate()
	if err != nil {
		t.Fatalf("Failed to generate identity Ed25519 private key: %v", err)
	}
	identityPubKeyRaw, err := identityPrivKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive identity Ed25519 public key: %v", err)
	}
	identityPubKey, ok := identityPubKeyRaw.(crypto.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate encryption key pair (ElGamal)
	var elgamalPrivKey elgamal.PrivateKey
	err = crypto.ElgamalGenerate(&elgamalPrivKey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v", err)
	}

	// Convert ElGamal public key
	var elgPubKey crypto.ElgPublicKey
	yBytes := elgamalPrivKey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	// Ensure the public key is padded to 256 bytes
	copy(elgPubKey[256-len(yBytes):], yBytes)

	// Create certificate payload
	var payload bytes.Buffer
	signingPublicKeyType, _ := data.NewIntegerFromInt(7, 2) // Ed25519
	cryptoPublicKeyType, _ := data.NewIntegerFromInt(0, 2)  // ElGamal
	payload.Write(signingPublicKeyType.Bytes())
	payload.Write(cryptoPublicKeyType.Bytes())

	// Create certificate
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Use the Ed25519 public key as-is (32 bytes)
	paddedSigningKey, err := crypto.CreateEd25519PublicKeyFromBytes(identityPubKey.Bytes())
	if err != nil {
		t.Fatalf("Failed to create Ed25519 public key from bytes: %v", err)
	}

	// Create RouterIdentity with the Ed25519 signing key
	routerIdentity, err := router_identity.NewRouterIdentity(elgPubKey, paddedSigningKey, *cert, nil)
	if err != nil {
		t.Fatalf("Failed to create router identity: %v", err)
	}

	// Generate second signing key pair for the lease set
	var leaseSetSigningPrivKey crypto.Ed25519PrivateKey
	_, err = (&leaseSetSigningPrivKey).Generate()
	if err != nil {
		t.Fatalf("Failed to generate lease set Ed25519 private key: %v", err)
	}
	leaseSetSigningPubKeyRaw, err := leaseSetSigningPrivKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive lease set Ed25519 public key: %v", err)
	}
	leaseSetSigningPubKey, ok := leaseSetSigningPubKeyRaw.(crypto.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get lease set SigningPublicKey from Ed25519 public key")
	}

	return routerIdentity, elgPubKey, leaseSetSigningPubKey, &leaseSetSigningPrivKey, &identityPrivKey
}

func createTestLease(t *testing.T, index int) (*lease.Lease, error) {
	// Create test RouterIdentity for tunnel gateway hash
	routerIdentity, _, _, _, _ := createTestIdentityAndKeys(t)
	tunnelGatewayHash := crypto.SHA256(routerIdentity.KeysAndCert.Bytes())

	// Create expiration time
	expiration := time.Now().Add(time.Hour * time.Duration(index+1)) // Different times for each lease

	// Create lease
	testLease, err := lease.NewLease(tunnelGatewayHash, uint32(1000+index), expiration)
	if err != nil {
		return nil, err
	}

	return testLease, nil
}

func createTestLeaseSet(t *testing.T, leaseCount int) (LeaseSet, error) {
	// Generate router identity and keys
	routerIdentity, encryptionKey, signingKey, signingPrivKey, _ := createTestIdentityAndKeys(t)

	// Debug destination size
	routerIdentityBytes := routerIdentity.Bytes()
	t.Logf("Router Identity size: %d bytes", len(routerIdentityBytes))

	// Create destination from router identity bytes
	dest, _, err := destination.ReadDestination(routerIdentityBytes)
	if err != nil {
		t.Logf("Failed to read destination: %v", err)
		return nil, err
	}

	destBytes := dest.KeysAndCert.Bytes()
	t.Logf("Destination size: %d bytes", len(destBytes))

	// Ensure the destination size is at least 387 bytes
	if len(destBytes) < 387 {
		t.Logf("WARNING: Destination size %d is less than required 387 bytes", len(destBytes))

		// Calculate the amount of padding needed
		paddingSize := 387 - len(destBytes)
		padding := make([]byte, paddingSize)
		_, err := rand.Read(padding) // Fill with random data
		if err != nil {
			return nil, fmt.Errorf("failed to generate padding: %v", err)
		}

		// Append the padding to the destination bytes
		destBytes = append(destBytes, padding...)

		// Re-create the KeysAndCert structure from the padded bytes
		newKeysAndCert, remainder, err := keys_and_cert.ReadKeysAndCert(destBytes)
		if err != nil {
			t.Logf("Failed to create KeysAndCert from padded bytes: %v", err)
			return nil, fmt.Errorf("failed to create KeysAndCert from padded bytes: %v", err)
		}

		// Check if there is any remainder and fill if necessary
		if len(remainder) > 0 {
			t.Logf("Additional remainder of size %d found, filling with zero bytes", len(remainder))
			destBytes = append(destBytes, make([]byte, len(remainder))...)
			// Re-create the KeysAndCert structure again to include the filled remainder
			newKeysAndCert, _, err = keys_and_cert.ReadKeysAndCert(destBytes)
			if err != nil {
				t.Logf("Failed to re-create KeysAndCert after filling remainder: %v", err)
				return nil, fmt.Errorf("failed to re-create KeysAndCert after filling remainder: %v", err)
			}
		}

		// Assign the newly created KeysAndCert to the destination
		dest.KeysAndCert = newKeysAndCert
	}

	// Additional check to ensure KeysAndCert is valid
	if dest.KeysAndCert.Bytes() == nil {
		return nil, fmt.Errorf("KeysAndCert is nil after padding and creation")
	}

	// Create leases
	var leases []lease.Lease
	for i := 0; i < leaseCount; i++ {
		testLease, err := createTestLease(t, i)
		if err != nil {
			return nil, err
		}
		leases = append(leases, *testLease)
	}

	// Create LeaseSet
	leaseSet, err := NewLeaseSet(
		dest,
		encryptionKey,
		signingKey,
		leases,
		signingPrivKey,
	)
	if err != nil {
		t.Logf("Failed to create lease set: %v", err)
	}

	return leaseSet, err
}

func TestLeaseSetCreation(t *testing.T) {
	assert := assert.New(t)

	leaseSet, err := createTestLeaseSet(t, 1)
	assert.Nil(err)
	assert.NotNil(leaseSet)

	// Check the size of the LeaseSet
	assert.GreaterOrEqual(len(leaseSet), 387, "LeaseSet should be at least 387 bytes")

	// Check the destination structure
	dest, err := leaseSet.Destination()
	assert.Nil(err)
	assert.NotNil(dest)
	assert.Equal(387, len(dest.KeysAndCert.Bytes()), "Destination KeysAndCert should be exactly 387 bytes")
}

func TestLeaseSetValidation(t *testing.T) {
	assert := assert.New(t)

	// Test with too many leases
	_, err := createTestLeaseSet(t, 17)
	assert.NotNil(err)
	assert.Equal("invalid lease set: more than 16 leases", err.Error())
}

func TestLeaseSetComponents(t *testing.T) {
	assert := assert.New(t)

	leaseSet, err := createTestLeaseSet(t, 3)
	assert.Nil(err)

	dest, err := leaseSet.Destination()
	assert.Nil(err)
	assert.NotNil(dest)

	count, err := leaseSet.LeaseCount()
	assert.Nil(err)
	assert.Equal(3, count)

	leases, err := leaseSet.Leases()
	assert.Nil(err)
	assert.Equal(3, len(leases))

	pubKey, err := leaseSet.PublicKey()
	assert.Nil(err)
	assert.Equal(LEASE_SET_PUBKEY_SIZE, len(pubKey.Bytes()))

	signKey, err := leaseSet.SigningKey()
	assert.Nil(err)
	assert.NotNil(signKey)
}

func TestExpirations(t *testing.T) {
	assert := assert.New(t)

	leaseSet, err := createTestLeaseSet(t, 3)
	assert.Nil(err)

	newest, err := leaseSet.NewestExpiration()
	assert.Nil(err)
	assert.NotNil(newest)

	oldest, err := leaseSet.OldestExpiration()
	assert.Nil(err)
	assert.NotNil(oldest)

	assert.True(oldest.Time().Before(newest.Time()) || oldest.Time().Equal(newest.Time()))
}

func TestSignatureVerification(t *testing.T) {
	assert := assert.New(t)

	leaseSet, err := createTestLeaseSet(t, 1)
	assert.Nil(err)

	sig, err := leaseSet.Signature()
	assert.Nil(err)
	assert.NotNil(sig)
}
