# keys
--
    import "github.com/go-i2p/go-i2p/lib/keys"

![keys.svg](keys.svg)



## Usage

#### type DestinationKeyStore

```go
type DestinationKeyStore struct {
}
```

DestinationKeyStore stores both encryption and signing private keys for an I2P
destination, enabling LeaseSet2 creation and message encryption. Uses modern
cryptography: Ed25519 for signing and X25519 for encryption.

#### func  NewDestinationKeyStore

```go
func NewDestinationKeyStore() (*DestinationKeyStore, error)
```
NewDestinationKeyStore creates a new key store with generated Ed25519/X25519
keys. This generates a new destination with fresh keys suitable for creating
LeaseSet2s using modern I2P cryptography (ECIES-X25519-AEAD-Ratchet compatible).

#### func (*DestinationKeyStore) Destination

```go
func (dks *DestinationKeyStore) Destination() *destination.Destination
```
Destination returns the public destination

#### func (*DestinationKeyStore) EncryptionPrivateKey

```go
func (dks *DestinationKeyStore) EncryptionPrivateKey() types.PrivateEncryptionKey
```
EncryptionPrivateKey returns the encryption private key for decrypting messages

#### func (*DestinationKeyStore) EncryptionPublicKey

```go
func (dks *DestinationKeyStore) EncryptionPublicKey() (types.ReceivingPublicKey, error)
```
EncryptionPublicKey returns the encryption public key

#### func (*DestinationKeyStore) SigningPrivateKey

```go
func (dks *DestinationKeyStore) SigningPrivateKey() types.SigningPrivateKey
```
SigningPrivateKey returns the signing private key for creating LeaseSets

#### func (*DestinationKeyStore) SigningPublicKey

```go
func (dks *DestinationKeyStore) SigningPublicKey() (types.SigningPublicKey, error)
```
SigningPublicKey returns the signing public key

#### type KeyStore

```go
type KeyStore interface {
	KeyID() string
	// GetKeys returns the public and private keys
	GetKeys() (publicKey types.PublicKey, privateKey types.PrivateKey, err error)
	// StoreKeys stores the keys
	StoreKeys() error
}
```

KeyStore is an interface for storing and retrieving keys

#### type KeyStoreImpl

```go
type KeyStoreImpl struct {
}
```


#### func  NewKeyStoreImpl

```go
func NewKeyStoreImpl(dir, name string, privateKey types.PrivateKey) *KeyStoreImpl
```

#### func (*KeyStoreImpl) GetKeys

```go
func (ks *KeyStoreImpl) GetKeys() (types.PublicKey, types.PrivateKey, error)
```

#### func (*KeyStoreImpl) KeyID

```go
func (ks *KeyStoreImpl) KeyID() string
```

#### func (*KeyStoreImpl) StoreKeys

```go
func (ks *KeyStoreImpl) StoreKeys() error
```

#### type RouterInfoKeystore

```go
type RouterInfoKeystore struct {
	*sntp.RouterTimestamper
}
```

RouterInfoKeystore is an implementation of KeyStore for storing and retrieving
RouterInfo private keys and exporting RouterInfos

#### func  NewRouterInfoKeystore

```go
func NewRouterInfoKeystore(dir, name string) (*RouterInfoKeystore, error)
```
NewRouterInfoKeystore creates a new RouterInfoKeystore with fresh and new
private keys it accepts a directory to store the keys in and a name for the keys
then it generates new private keys for the routerInfo if none exist

#### func (*RouterInfoKeystore) ConstructRouterInfo

```go
func (ks *RouterInfoKeystore) ConstructRouterInfo(addresses []*router_address.RouterAddress) (*router_info.RouterInfo, error)
```
ConstructRouterInfo creates a complete RouterInfo structure with signing keys
and certificate

#### func (*RouterInfoKeystore) GetEncryptionPrivateKey

```go
func (ks *RouterInfoKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey
```
GetEncryptionPrivateKey returns the X25519 encryption private key used for
NTCP2. This key is used as the static key for NTCP2 transport sessions, ensuring
consistent peer identification across router restarts.

#### func (*RouterInfoKeystore) GetKeys

```go
func (ks *RouterInfoKeystore) GetKeys() (types.PublicKey, types.PrivateKey, error)
```

#### func (*RouterInfoKeystore) KeyID

```go
func (ks *RouterInfoKeystore) KeyID() string
```

#### func (*RouterInfoKeystore) StoreKeys

```go
func (ks *RouterInfoKeystore) StoreKeys() error
```



keys 

github.com/go-i2p/go-i2p/lib/keys

[go-i2p template file](/template.md)
