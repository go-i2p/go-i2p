package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/certificate"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/require"
)

// newTestCompositeBootstrap creates a CompositeBootstrap with common test defaults.
// It constructs a BootstrapConfig using testLowPeerThreshold and the provided fields,
// then creates and validates the CompositeBootstrap instance.
func newTestCompositeBootstrap(t *testing.T, bootstrapType, reseedFilePath string, reseedServers []*config.ReseedConfig) *CompositeBootstrap {
	t.Helper()
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		BootstrapType:    bootstrapType,
		ReseedFilePath:   reseedFilePath,
		ReseedServers:    reseedServers,
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)
	return cb
}

// assertApplyStrategyNotNil creates a ReseedBootstrap with the given strategy,
// applies it to a single-result set, and asserts the result is not nil.
func assertApplyStrategyNotNil(t *testing.T, strategy string, errMsg string) {
	t.Helper()
	cfg := &config.BootstrapConfig{
		ReseedStrategy: strategy,
	}
	rb := &ReseedBootstrap{config: cfg}
	results := []ReseedResult{
		{ServerURL: "https://s1/", RouterInfos: make([]router_info.RouterInfo, 3)},
	}
	combined := rb.applyStrategy(results)
	if combined == nil {
		t.Error(errMsg)
	}
}

// createTempTestFile creates a temporary file with dummy content in the given directory.
func createTempTestFile(tb testing.TB, dir, name string, size int) string {
	tb.Helper()
	tmpFile := filepath.Join(dir, name)
	err := os.WriteFile(tmpFile, createDummyContent(size), 0o644)
	require.NoError(tb, err)
	return tmpFile
}

// createTestRouterAddress creates a test RouterAddress with the given transport style and options.
func createTestRouterAddress(transportStyle string, options map[string]string) *router_address.RouterAddress {
	expiration := time.Now().Add(24 * time.Hour)
	addr, err := router_address.NewRouterAddress(5, expiration, transportStyle, options)
	if err != nil {
		panic("Failed to create test RouterAddress: " + err.Error())
	}
	return addr
}

// createSignedTestRouterInfo creates a properly signed RouterInfo for testing.
// Uses Ed25519 signing keys and ElGamal encryption keys, matching the I2P standard.
func createSignedTestRouterInfo(tb testing.TB, options map[string]string) *router_info.RouterInfo {
	tb.Helper()

	// Generate Ed25519 signing key pair
	ed25519PrivKey, err := ed25519.GenerateEd25519Key()
	require.NoError(tb, err, "Failed to generate Ed25519 key")

	ed25519PrivKeyTyped := ed25519PrivKey.(ed25519.Ed25519PrivateKey)
	ed25519PubKeyRaw, err := ed25519PrivKeyTyped.Public()
	require.NoError(tb, err, "Failed to derive Ed25519 public key")

	ed25519PubKey, ok := ed25519PubKeyRaw.(types.SigningPublicKey)
	require.True(tb, ok, "Failed to cast Ed25519 public key")

	// Generate ElGamal encryption key pair
	var elgPrivKey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgPrivKey.PrivateKey, rand.Reader)
	require.NoError(tb, err, "Failed to generate ElGamal key")

	var elgPubKey elgamal.ElgPublicKey
	yBytes := elgPrivKey.PublicKey.Y.Bytes()
	require.LessOrEqual(tb, len(yBytes), 256, "ElGamal public key Y too large")
	copy(elgPubKey[256-len(yBytes):], yBytes)

	// Create KEY certificate for Ed25519/ElGamal
	var payload bytes.Buffer
	signingType, err := common.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(tb, err)
	cryptoType, err := common.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(tb, err)
	payload.Write(*signingType)
	payload.Write(*cryptoType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(tb, err, "Failed to create certificate")

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(tb, err, "Failed to create key certificate")

	// Create padding
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(tb, err, "Failed to generate padding")

	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elgPubKey, ed25519PubKey, cert, padding)
	require.NoError(tb, err, "Failed to create router identity")

	// Create router address with NTCP2 and direct connectivity
	routerAddr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", map[string]string{
		"host": testHost,
		"port": testPort,
	})
	require.NoError(tb, err, "Failed to create router address")

	// Merge default options with provided options
	mergedOptions := map[string]string{"router.version": "0.9.64"}
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
