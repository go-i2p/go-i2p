// Package testutil provides shared test helpers used across multiple packages.
package testutil

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/require"
)

// RouterAddressConfig controls how the router address is created in CreateSignedTestRouterInfo.
type RouterAddressConfig struct {
	Cost       uint8
	Expiration time.Time
	Transport  string
	Options    map[string]string
}

// DefaultRouterAddressConfig returns an NTCP2 address with no host/port.
func DefaultRouterAddressConfig() RouterAddressConfig {
	return RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "NTCP2",
		Options:    map[string]string{},
	}
}

// CreateSignedTestRouterInfo creates a properly signed RouterInfo for testing.
// Uses Ed25519 signing keys and X25519 encryption keys, matching the I2P standard.
// addrCfg controls the router address parameters; pass nil to use defaults.
func CreateSignedTestRouterInfo(tb testing.TB, options map[string]string, addrCfg *RouterAddressConfig) *router_info.RouterInfo {
	tb.Helper()

	if addrCfg == nil {
		def := DefaultRouterAddressConfig()
		addrCfg = &def
	}

	// Generate Ed25519 signing key pair
	ed25519PrivKey, err := ed25519.GenerateEd25519Key()
	require.NoError(tb, err, "Failed to generate Ed25519 key")

	ed25519PrivKeyTyped := ed25519PrivKey.(ed25519.Ed25519PrivateKey)
	ed25519PubKeyRaw, err := ed25519PrivKeyTyped.Public()
	require.NoError(tb, err, "Failed to derive Ed25519 public key")

	ed25519PubKey := ed25519PubKeyRaw

	// Generate X25519 encryption key pair
	x25519PubKey, _, err := curve25519.GenerateKeyPair()
	require.NoError(tb, err, "Failed to generate X25519 key")

	receivingPubKey, ok := x25519PubKey.(types.ReceivingPublicKey)
	require.True(tb, ok, "X25519 public key does not implement ReceivingPublicKey")

	// Create KEY certificate for Ed25519/X25519
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	require.NoError(tb, err, "Failed to create key certificate")
	cert := &keyCert.Certificate

	// Create padding
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(tb, err, "Failed to generate padding")

	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(receivingPubKey, ed25519PubKey, cert, padding)
	require.NoError(tb, err, "Failed to create router identity")

	// Create router address
	routerAddr, err := router_address.NewRouterAddress(addrCfg.Cost, addrCfg.Expiration, addrCfg.Transport, addrCfg.Options)
	require.NoError(tb, err, "Failed to create router address")

	// Merge default options with provided options. Real RouterInfos always carry
	// both netId and router.version; include them by default so fixtures pass the
	// same network validation a production router applies. Callers may override.
	mergedOptions := map[string]string{"router.version": "0.9.64", "netId": "2"}
	for k, v := range options {
		mergedOptions[k] = v
	}

	// Create RouterInfo (this signs it with the private key)
	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{routerAddr},
		mergedOptions,
		&ed25519PrivKeyTyped,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(tb, err, "Failed to create RouterInfo")

	return ri
}
