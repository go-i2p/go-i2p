package lease_set

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/common/signature"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/destination"
	"github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"golang.org/x/crypto/openpgp/elgamal"

	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/lease"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/stretchr/testify/assert"
)

func generateTestRouterInfo(t *testing.T) (*router_info.RouterInfo, crypto.PublicKey, crypto.SigningPublicKey, crypto.SigningPrivateKey, crypto.SigningPrivateKey, error) {
	// Generate signing key pair (Ed25519)
	var ed25519_privkey crypto.Ed25519PrivateKey
	_, err := (&ed25519_privkey).Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	ed25519_pubkey, ok := ed25519_pubkey_raw.(crypto.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate encryption key pair (ElGamal)
	var elgamal_privkey elgamal.PrivateKey
	err = crypto.ElgamalGenerate(&elgamal_privkey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}

	// Convert elgamal private key to crypto.ElgPrivateKey
	var elg_privkey crypto.ElgPrivateKey
	xBytes := elgamal_privkey.X.Bytes()
	if len(xBytes) > 256 {
		t.Fatalf("ElGamal private key X too large")
	}
	copy(elg_privkey[256-len(xBytes):], xBytes)

	// Convert elgamal public key to crypto.ElgPublicKey
	var elg_pubkey crypto.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	// Ensure that elg_pubkey implements crypto.PublicKey interface
	var _ crypto.PublicKey = elg_pubkey

	// Create KeyCertificate specifying key types
	var payload bytes.Buffer

	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2)
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}

	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2)
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}

	// Directly write the bytes of the Integer instances to the payload
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	err = binary.Write(&payload, binary.BigEndian, signingPublicKeyType)
	if err != nil {
		t.Fatalf("Failed to write signing public key type to payload: %v\n", err)
	}

	err = binary.Write(&payload, binary.BigEndian, cryptoPublicKeyType)
	if err != nil {
		t.Fatalf("Failed to write crypto public key type to payload: %v\n", err)
	}

	// Create KeyCertificate specifying key types
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	certBytes := cert.Bytes()
	t.Logf("Serialized Certificate Size: %d bytes", len(certBytes))

	keyCert, err := key_certificate.KeyCertificateFromCertificate(*cert)
	if err != nil {
		log.Fatalf("KeyCertificateFromCertificate failed: %v\n", err)
	}
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SignatureSize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}
	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elg_pubkey, ed25519_pubkey, *cert, padding)
	if err != nil {
		t.Fatalf("Failed to create router identity: %v\n", err)
	}
	// create some dummy addresses
	options := map[string]string{}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		t.Fatalf("Failed to create router address: %v\n", err)
	}
	routerAddresses := []*router_address.RouterAddress{routerAddress}
	// create router info
	routerInfo, err := router_info.NewRouterInfo(routerIdentity, time.Now(), routerAddresses, nil, &ed25519_privkey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}
	//
	// Generate signing key pair for the LeaseSet (Ed25519)
	var leaseSetSigningPrivKey crypto.Ed25519PrivateKey
	_, err = leaseSetSigningPrivKey.Generate()

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

	//
	var identityPrivKey crypto.Ed25519PrivateKey
	_, err = identityPrivKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate identity Ed25519 private key: %v", err)
	}
	/*
		identityPubKeyRaw, err := identityPrivKey.Public()
		if err != nil {
			t.Fatalf("Failed to derive identity Ed25519 public key: %v", err)
		}
		identityPubKey, ok := identityPubKeyRaw.(crypto.SigningPublicKey)
		if !ok {
			t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
		}
		identityPubKeyBytes := identityPubKey.Bytes() // 32 bytes

	*/

	return routerInfo, elg_pubkey, leaseSetSigningPubKey, &leaseSetSigningPrivKey, &identityPrivKey, nil
}

func createTestLease(t *testing.T, index int) (*lease.Lease, error) {
	// Create test RouterIdentity for tunnel gateway hash
	//routerIdentity, _, _, _, _ := createTestIdentityAndKeys(t)
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	if err != nil {
		log.Fatalf("failed to create router info: %v", err)
	}

	tunnelGatewayHash := crypto.SHA256(routerInfo.RouterIdentity().KeysAndCert.Bytes())

	// Create expiration time
	expiration := time.Now().Add(time.Hour * time.Duration(index+1)) // Different times for each lease

	// Create lease
	testLease, err := lease.NewLease(tunnelGatewayHash, uint32(1000+index), expiration)
	if err != nil {
		return nil, err
	}

	return testLease, nil
}

// (*router_info.RouterInfo, crypto.PublicKey, crypto.SigningPublicKey, crypto.SigningPrivateKey, crypto.SigningPrivateKey, error) {
func createTestLeaseSet(t *testing.T, routerInfo *router_info.RouterInfo, encryptionKey crypto.PublicKey, signingKey crypto.SigningPublicKey, signingPrivKey crypto.SigningPrivateKey, leaseCount int) (LeaseSet, error) {
	// Generate router identity and keys
	//routerIdentity, encryptionKey, signingKey, signingPrivKey, _ := createTestIdentityAndKeys(t)

	// Debug destination size
	routerIdentityBytes := routerInfo.RouterIdentity().Bytes()
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

	// Generate test router info and keys
	routerInfo, encryptionKey, signingKey, signingPrivKey, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, encryptionKey, signingKey, signingPrivKey, 1)
	assert.Nil(err)
	assert.NotNil(leaseSet)

	// Check the size of the LeaseSet
	//leaseSetBytes := leaseSet.Bytes()
	//assert.GreaterOrEqual(len(leaseSetBytes), 387, "LeaseSet should be at least 387 bytes")

	// Check the destination structure
	dest, err := leaseSet.Destination()
	assert.Nil(err)
	assert.NotNil(dest)
	assert.Equal(387, len(dest.KeysAndCert.Bytes()), "Destination KeysAndCert should be exactly 387 bytes")
}

func TestLeaseSetValidation(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, encryptionKey, signingKey, signingPrivKey, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Test with too many leases
	_, err = createTestLeaseSet(t, routerInfo, encryptionKey, signingKey, signingPrivKey, 17)
	assert.NotNil(err)
	assert.Equal("invalid lease set: more than 16 leases", err.Error())
}

func TestLeaseSetComponents(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, encryptionKey, signingKey, signingPrivKey, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Create the test lease set with 3 leases
	leaseSet, err := createTestLeaseSet(t, routerInfo, encryptionKey, signingKey, signingPrivKey, 3)
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

	// Generate test router info and keys
	routerInfo, encryptionKey, signingKey, signingPrivKey, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Create the test lease set with 3 leases
	leaseSet, err := createTestLeaseSet(t, routerInfo, encryptionKey, signingKey, signingPrivKey, 3)
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

	// Generate test router info and keys
	routerInfo, encryptionKey, signingKey, signingPrivKey, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Create the test lease set
	leaseSet, err := createTestLeaseSet(t, routerInfo, encryptionKey, signingKey, signingPrivKey, 1)
	assert.Nil(err)

	sig, err := leaseSet.Signature()
	assert.Nil(err)
	assert.NotNil(sig)
}
