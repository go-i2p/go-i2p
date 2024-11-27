package router_info

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp/elgamal"

	"github.com/go-i2p/go-i2p/lib/common/router_address"
)

func generateTestRouterInfo(t *testing.T, publishedTime time.Time) (*RouterInfo, error) {
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
	routerInfo, err := NewRouterInfo(routerIdentity, publishedTime, routerAddresses, nil, &ed25519_privkey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}
	return routerInfo, nil
}

// TestRouterInfoCreation verifies that a RouterInfo object can be created without errors.
func TestRouterInfoCreation(t *testing.T) {
	assert := assert.New(t)

	// Use helper function to generate a RouterInfo
	publishedTime := time.Now()
	routerInfo, err := generateTestRouterInfo(t, publishedTime)

	assert.Nil(err, "RouterInfo creation should not return an error")
	assert.NotNil(routerInfo, "RouterInfo should not be nil")
}

// TestRouterInfoPublishedDate verifies that the published date is correctly set and retrieved.
func TestRouterInfoPublishedDate(t *testing.T) {
	assert := assert.New(t)

	publishedTime := time.Unix(86400, 0) // 1 day since epoch
	routerInfo, err := generateTestRouterInfo(t, publishedTime)

	assert.Nil(err, "RouterInfo creation should not return an error")
	assert.Equal(publishedTime.Unix(), routerInfo.Published().Time().Unix(), "Published date should match the input date")
}

// TestRouterInfoRouterIdentity verifies that the RouterIdentity is correctly set.
func TestRouterInfoRouterIdentity(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	routerIdentity := routerInfo.RouterIdentity()
	assert.NotNil(routerIdentity, "RouterIdentity should not be nil")
}

// TestRouterInfoAddresses verifies that the RouterAddresses are correctly set and retrieved.
func TestRouterInfoAddresses(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	addresses := routerInfo.RouterAddresses()
	assert.NotNil(addresses, "RouterAddresses should not be nil")
	assert.Greater(len(addresses), 0, "RouterAddresses should have at least one address")
}

// TestRouterInfoSerialization verifies that the RouterInfo can be serialized to bytes without error.
func TestRouterInfoSerialization(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	bytes, err := routerInfo.Bytes()
	assert.Nil(err, "Serialization should not return an error")
	assert.NotNil(bytes, "Serialized bytes should not be nil")
	assert.Greater(len(bytes), 0, "Serialized bytes should have a length greater than zero")
}

// TestRouterInfoSignature verifies that the signature is correctly set in the RouterInfo.
func TestRouterInfoSignature(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	signature := routerInfo.Signature()
	assert.NotNil(signature, "Signature should not be nil")
}

/* TODO: Fix this
// TestRouterInfoCapabilities verifies the RouterCapabilities method functionality.
func TestRouterInfoCapabilities(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	capabilities := routerInfo.RouterCapabilities()
	assert.NotEmpty(capabilities, "RouterCapabilities should not be empty")
}
// TODO: Fix this
// TestRouterInfoVersion verifies the RouterVersion method functionality.
func TestRouterInfoVersion(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	version := routerInfo.RouterVersion()
	assert.NotEmpty(version, "RouterVersion should not be empty")
}

*/

// TestRouterInfoGoodVersion verifies the GoodVersion method functionality.
func TestRouterInfoGoodVersion(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	isGoodVersion := routerInfo.GoodVersion()
	assert.IsType(true, isGoodVersion, "GoodVersion should return a boolean")
}

// TestRouterInfoUnCongested verifies the UnCongested method functionality.
func TestRouterInfoUnCongested(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	isUncongested := routerInfo.UnCongested()
	assert.IsType(true, isUncongested, "UnCongested should return a boolean")
}

// TestRouterInfoReachable verifies the Reachable method functionality.
func TestRouterInfoReachable(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	isReachable := routerInfo.Reachable()
	assert.IsType(true, isReachable, "Reachable should return a boolean")
}
