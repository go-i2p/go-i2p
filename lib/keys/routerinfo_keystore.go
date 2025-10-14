package keys

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/util/time/sntp"
	"github.com/samber/oops"
)

// RouterInfoKeystore is an implementation of KeyStore for storing and retrieving RouterInfo private keys and exporting RouterInfos
type RouterInfoKeystore struct {
	*sntp.RouterTimestamper
	dir        string
	name       string
	privateKey types.PrivateKey
}

var riks KeyStore = &RouterInfoKeystore{}

// NewRouterInfoKeystore creates a new RouterInfoKeystore with fresh and new private keys
// it accepts a directory to store the keys in and a name for the keys
// then it generates new private keys for the routerInfo if none exist
func NewRouterInfoKeystore(dir, name string) (*RouterInfoKeystore, error) {
	if err := ensureDirectoryExists(dir); err != nil {
		return nil, err
	}

	privateKey, err := loadOrGenerateKey(dir, name)
	if err != nil {
		return nil, err
	}

	return initializeKeystore(dir, name, privateKey), nil
}

// ensureDirectoryExists creates the directory if it does not exist.
// Returns an error if directory creation fails.
func ensureDirectoryExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// loadOrGenerateKey attempts to load an existing key from the specified path.
// If no key exists, it generates a new key. Returns the loaded or generated
// private key, or an error if the operation fails.
func loadOrGenerateKey(dir, name string) (types.PrivateKey, error) {
	fullPath := filepath.Join(dir, name)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return generateNewKey()
	}

	keyData, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	return loadExistingKey(keyData)
}

// initializeKeystore constructs and returns a configured RouterInfoKeystore
// with the provided directory, name, private key, and a default NTP timestamper.
func initializeKeystore(dir, name string, privateKey types.PrivateKey) *RouterInfoKeystore {
	defaultClient := &sntp.DefaultNTPClient{}
	timestamper := sntp.NewRouterTimestamper(defaultClient)
	return &RouterInfoKeystore{
		dir:               dir,
		name:              name,
		privateKey:        privateKey,
		RouterTimestamper: timestamper,
	}
}

func generateNewKey() (ed25519.Ed25519PrivateKey, error) {
	// Generate a new key pair
	priv, err := ed25519.GenerateEd25519Key()
	if err != nil {
		return nil, err
	}

	// Convert to our type using type assertion
	return priv.(ed25519.Ed25519PrivateKey), nil
}

func loadExistingKey(keyData []byte) (ed25519.Ed25519PrivateKey, error) {
	// Convert to our type
	return ed25519.Ed25519PrivateKey(keyData), nil
}

func (ks *RouterInfoKeystore) GetKeys() (types.PublicKey, types.PrivateKey, error) {
	public, err := ks.privateKey.Public()
	if err != nil {
		return nil, nil, err
	}
	return public, ks.privateKey, nil
}

func (ks *RouterInfoKeystore) StoreKeys() error {
	if _, err := os.Stat(ks.dir); os.IsNotExist(err) {
		err := os.MkdirAll(ks.dir, 0o755)
		if err != nil {
			return err
		}
	}
	// on the disk somewhere
	filename := filepath.Join(ks.dir, ks.KeyID()+".key")
	return os.WriteFile(filename, ks.privateKey.Bytes(), 0o600)
}

func (ks *RouterInfoKeystore) KeyID() string {
	if ks.name == "" {
		public, err := ks.privateKey.Public()
		if err != nil {
			// Generate a random fallback ID instead of returning "error"
			randomBytes := make([]byte, 4)
			if _, randErr := rand.Read(randomBytes); randErr != nil {
				// If random generation also fails, use a timestamped fallback
				return "fallback-key"
			}
			return "fallback-" + hex.EncodeToString(randomBytes)
		}
		if len(public.Bytes()) > 10 {
			return hex.EncodeToString(public.Bytes()[:10])
		}
		return hex.EncodeToString(public.Bytes())
	}
	return ks.name
}

// ConstructRouterInfo creates a complete RouterInfo structure with signing keys and certificate
func (ks *RouterInfoKeystore) ConstructRouterInfo(addresses []*router_address.RouterAddress) (*router_info.RouterInfo, error) {
	publicKey, privateKey, err := ks.validateAndGetKeys()
	if err != nil {
		return nil, err
	}

	cert, err := ks.createEd25519Certificate()
	if err != nil {
		return nil, err
	}

	routerIdentity, err := ks.buildRouterIdentity(publicKey, cert)
	if err != nil {
		return nil, err
	}

	return ks.assembleRouterInfo(routerIdentity, addresses, privateKey)
}

// validateAndGetKeys retrieves and validates the signing keys from the keystore
func (ks *RouterInfoKeystore) validateAndGetKeys() (types.PublicKey, types.PrivateKey, error) {
	publicKey, privateKey, err := ks.GetKeys()
	if err != nil {
		return nil, nil, oops.Errorf("failed to get keys: %w", err)
	}
	return publicKey, privateKey, nil
}

// createEd25519Certificate generates a certificate with Ed25519 key type configuration
func (ks *RouterInfoKeystore) createEd25519Certificate() (*certificate.Certificate, error) {
	payload := new(bytes.Buffer)
	cryptoKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	if err != nil {
		return nil, oops.Errorf("failed to create crypto key type: %w", err)
	}
	signingKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	if err != nil {
		return nil, oops.Errorf("failed to create signing key type: %w", err)
	}
	payload.Write(*cryptoKeyType)
	payload.Write(*signingKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		return nil, oops.Errorf("failed to create certificate: %w", err)
	}
	return cert, nil
}

// buildRouterIdentity constructs a RouterIdentity with proper padding and certificate
func (ks *RouterInfoKeystore) buildRouterIdentity(publicKey types.PublicKey, cert *certificate.Certificate) (*router_identity.RouterIdentity, error) {
	keyCert, err := key_certificate.KeyCertificateFromCertificate(*cert)
	if err != nil {
		return nil, oops.Errorf("failed to create key certificate: %w", err)
	}

	padding, err := ks.generateIdentityPadding(keyCert)
	if err != nil {
		return nil, err
	}

	routerIdentity, err := router_identity.NewRouterIdentity(
		types.ReceivingPublicKey(nil),
		publicKey.(types.SigningPublicKey),
		*cert,
		padding,
	)
	if err != nil {
		return nil, oops.Errorf("failed to create router identity: %w", err)
	}
	return routerIdentity, nil
}

// generateIdentityPadding creates random padding bytes for RouterIdentity structure
func (ks *RouterInfoKeystore) generateIdentityPadding(keyCert *key_certificate.KeyCertificate) ([]byte, error) {
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SignatureSize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (pubKeySize + sigKeySize)
	padding := make([]byte, paddingSize)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}
	return padding, nil
}

// assembleRouterInfo creates the final RouterInfo with all components and standard options
func (ks *RouterInfoKeystore) assembleRouterInfo(routerIdentity *router_identity.RouterIdentity, addresses []*router_address.RouterAddress, privateKey types.PrivateKey) (*router_info.RouterInfo, error) {
	publishedTime := ks.RouterTimestamper.GetCurrentTime()

	options := map[string]string{
		"caps":  "NU", // Standard capabilities - Not floodfill, Not Reachable
		"netId": "2",  // Production network
	}

	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		publishedTime,
		addresses,
		options,
		privateKey.(types.SigningPrivateKey),
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	if err != nil {
		return nil, oops.Errorf("failed to create router info: %w", err)
	}
	return ri, nil
}
