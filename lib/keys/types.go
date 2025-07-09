package keys

import (
	"fmt"
	"os"

	"github.com/go-i2p/crypto/types"
)

// KeyStore is an interface for storing and retrieving keys
type KeyStore interface {
	KeyID() string
	// GetKeys returns the public and private keys
	GetKeys() (publicKey types.PublicKey, privateKey types.PrivateKey, err error)
	// StoreKeys stores the keys
	StoreKeys() error
}

type KeyStoreImpl struct {
	dir        string
	name       string
	privateKey types.PrivateKey
}

func NewKeyStoreImpl(dir, name string, privateKey types.PrivateKey) *KeyStoreImpl {
	return &KeyStoreImpl{
		dir:        dir,
		name:       name,
		privateKey: privateKey,
	}
}

func (ks *KeyStoreImpl) KeyID() string {
	if ks.name == "" {
		public, err := ks.privateKey.Public()
		if err != nil {
			return "error"
		}
		if len(public.Bytes()) > 10 {
			return string(public.Bytes()[:10])
		} else {
			return string(public.Bytes())
		}
	}
	return ks.name
}

func (ks *KeyStoreImpl) GetKeys() (types.PublicKey, types.PrivateKey, error) {
	public, err := ks.privateKey.Public()
	if err != nil {
		return nil, nil, err
	}
	return public, ks.privateKey, nil
}

func (ks *KeyStoreImpl) StoreKeys() error {
	// make sure the directory exists
	if _, err := os.Stat(ks.dir); os.IsNotExist(err) {
		err := os.MkdirAll(ks.dir, 0o755)
		if err != nil {
			return err
		}
	}
	// on the disk somewhere
	filename := fmt.Sprintf("private-%s.key", ks.KeyID())
	return os.WriteFile(filename, ks.privateKey.Bytes(), 0o644)
}
