package keys

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"

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
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0o755)
		if err != nil {
			return nil, err
		}
	}
	var privateKey types.PrivateKey
	fullPath := filepath.Join(dir, name)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		privateKey, err = generateNewKey()
		if err != nil {
			return nil, err
		}
	} else {
		keyData, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, err
		}
		privateKey, err = loadExistingKey(keyData)
		if err != nil {
			return nil, err
		}
	}
	defaultClient := &sntp.DefaultNTPClient{}
	timestamper := sntp.NewRouterTimestamper(defaultClient)
	return &RouterInfoKeystore{
		dir:               dir,
		name:              name,
		privateKey:        privateKey,
		RouterTimestamper: timestamper,
	}, nil
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
	return os.WriteFile(filename, ks.privateKey.Bytes(), 0o644)
}

func (ks *RouterInfoKeystore) KeyID() string {
	if ks.name == "" {
		public, err := ks.privateKey.Public()
		if err != nil {
			return "error"
		}
		if len(public.Bytes()) > 10 {
			return string(public.Bytes()[:10])
		}
		return string(public.Bytes())
	}
	return ks.name
}

func (ks *RouterInfoKeystore) ConstructRouterInfo(addresses []*router_address.RouterAddress) (*router_info.RouterInfo, error) {
	// Get signing keys
	publicKey, privateKey, err := ks.GetKeys()
	if err != nil {
		return nil, oops.Errorf("failed to get keys: %w", err)
	}

	// Create certificate with Ed25519 key type
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

	// Create padding
	keyCert, err := key_certificate.KeyCertificateFromCertificate(*cert)
	if err != nil {
		return nil, oops.Errorf("failed to create key certificate: %w", err)
	}

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SignatureSize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (pubKeySize + sigKeySize)
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}

	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(
		types.ReceivingPublicKey(nil),
		publicKey.(types.SigningPublicKey),
		*cert,
		padding,
	)
	if err != nil {
		return nil, oops.Errorf("failed to create router identity: %w", err)
	}

	// Get timestamp
	publishedTime := ks.RouterTimestamper.GetCurrentTime()

	// Standard router options
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
