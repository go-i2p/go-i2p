package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/crypto"
)

// RouterInfoKeystore is an implementation of KeyStore for storing and retrieving RouterInfo private keys and exporting RouterInfos
type RouterInfoKeystore struct {
	dir        string
	name       string
	privateKey crypto.PrivateKey
}

var riks KeyStore = &RouterInfoKeystore{}

// NewRouterInfoKeystore creates a new RouterInfoKeystore with fresh and new private keys
// it accepts a directory to store the keys in and a name for the keys
// then it generates new private keys for the routerInfo if none exist
func NewRouterInfoKeystore(dir, name string) (*RouterInfoKeystore, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, err
		}
	}
	var privateKey crypto.PrivateKey
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
	return &RouterInfoKeystore{
		dir:        dir,
		name:       name,
		privateKey: privateKey,
	}, nil
}

func generateNewKey() (crypto.Ed25519PrivateKey, error) {
	// Generate a new key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Convert to our type
	return crypto.Ed25519PrivateKey(priv), nil
}

func loadExistingKey(keyData []byte) (crypto.Ed25519PrivateKey, error) {
	// Validate key length
	if len(keyData) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid key length")
	}

	// Convert to our type
	return crypto.Ed25519PrivateKey(keyData), nil
}

func (ks *RouterInfoKeystore) GetKeys() (crypto.PublicKey, crypto.PrivateKey, error) {
	public, err := ks.privateKey.Public()
	if err != nil {
		return nil, nil, err
	}
	return public, ks.privateKey, nil
}

func (ks *RouterInfoKeystore) StoreKeys() error {
	if _, err := os.Stat(ks.dir); os.IsNotExist(err) {
		err := os.MkdirAll(ks.dir, 0755)
		if err != nil {
			return err
		}
	}
	// on the disk somewhere
	filename := filepath.Join(ks.dir, ks.name)
	return os.WriteFile(filename, ks.privateKey.Bytes(), 0644)
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
