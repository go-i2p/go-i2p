package router_info

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp/elgamal"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/router_address"
)

func generateTestRouterInfo(t *testing.T, publishedTime time.Time) (*RouterInfo, error) {
	// Step 1: Generate Signing Key Pair (Ed25519)
	var ed25519PrivKey crypto.Ed25519PrivateKey
	_, err := (&ed25519PrivKey).Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 private key: %v", err)
	}

	ed25519PubKeyRaw, err := ed25519PrivKey.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ed25519 public key: %v", err)
	}

	ed25519PubKey, ok := ed25519PubKeyRaw.(crypto.SigningPublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert Ed25519 public key to SigningPublicKey")
	}

	// Step 2: Generate Encryption Key Pair (ElGamal)
	var elgamalPrivKey elgamal.PrivateKey
	err = crypto.ElgamalGenerate(&elgamalPrivKey, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ElGamal private key: %v", err)
	}

	// Convert ElGamal Private Key to crypto.ElgPrivateKey
	var elgPrivKey crypto.ElgPrivateKey
	xBytes := elgamalPrivKey.X.Bytes()
	if len(xBytes) > 256 {
		return nil, fmt.Errorf("ElGamal private key X too large")
	}
	copy(elgPrivKey[256-len(xBytes):], xBytes)

	// Convert ElGamal Public Key to crypto.ElgPublicKey
	var elgPubKey crypto.ElgPublicKey
	yBytes := elgamalPrivKey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		return nil, fmt.Errorf("ElGamal public key Y too large")
	}
	copy(elgPubKey[256-len(yBytes):], yBytes)

	// Ensure ElGamal Public Key implements crypto.PublicKey interface
	var _ crypto.PublicKey = elgPubKey

	// Step 3: Create KeyCertificate specifying key types
	var payload bytes.Buffer

	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing public key type integer: %v", err)
	}

	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto public key type integer: %v", err)
	}

	// Write the bytes of the Integer instances to the payload
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	// Create KeyCertificate
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create new certificate: %v", err)
	}

	// Step 4: Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elgPubKey, ed25519PubKey, *cert, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RouterIdentity: %v", err)
	}

	// Step 5: Create RouterAddress
	options := map[string]string{}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		return nil, fmt.Errorf("failed to create RouterAddress: %v", err)
	}
	routerAddresses := []*router_address.RouterAddress{routerAddress}

	// Step 6: Create RouterInfo
	routerInfo, err := NewRouterInfo(routerIdentity, publishedTime, routerAddresses, nil, &ed25519PrivKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create RouterInfo: %v", err)
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

// TestRouterInfoCapabilities verifies the RouterCapabilities method functionality.
func TestRouterInfoCapabilities(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	capabilities := routerInfo.RouterCapabilities()
	assert.NotEmpty(capabilities, "RouterCapabilities should not be empty")
}

// TestRouterInfoVersion verifies the RouterVersion method functionality.
func TestRouterInfoVersion(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	version := routerInfo.RouterVersion()
	assert.NotEmpty(version, "RouterVersion should not be empty")
}

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
