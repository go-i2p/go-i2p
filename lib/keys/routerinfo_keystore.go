package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/certificate"
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
	dir               string
	name              string
	privateKey        types.PrivateKey           // Ed25519 signing private key
	encryptionPrivKey types.PrivateEncryptionKey // X25519 encryption private key
	encryptionPubKey  types.ReceivingPublicKey   // X25519 encryption public key
	// cachedKeyID stores the fallback KeyID to ensure consistency across multiple calls
	// when privateKey.Public() fails. This prevents race conditions where KeyID()
	// could return different values on each invocation.
	cachedKeyID string
	// keyIDOnce ensures thread-safe initialization of cachedKeyID
	keyIDOnce sync.Once
	// keyIDMutex protects concurrent access to cachedKeyID
	keyIDMutex sync.RWMutex
}

// Ensure RouterInfoKeystore implements KeyStore interface at compile time
var _ KeyStore = (*RouterInfoKeystore)(nil)

// NewRouterInfoKeystore creates a new RouterInfoKeystore with fresh and new private keys
// it accepts a directory to store the keys in and a name for the keys
// then it generates new private keys for the routerInfo if none exist
func NewRouterInfoKeystore(dir, name string) (*RouterInfoKeystore, error) {
	log.WithFields(map[string]interface{}{
		"at":   "NewRouterInfoKeystore",
		"dir":  dir,
		"name": name,
	}).Debug("Creating RouterInfo keystore")

	if err := ensureDirectoryExists(dir); err != nil {
		log.WithError(err).Error("Failed to ensure directory exists")
		return nil, err
	}

	privateKey, err := loadOrGenerateKey(dir, name)
	if err != nil {
		log.WithError(err).Error("Failed to load or generate key")
		return nil, err
	}

	// Generate X25519 encryption key pair for router
	encryptionPubKey, encryptionPrivKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate X25519 encryption key")
		return nil, err
	}

	log.WithField("at", "NewRouterInfoKeystore").Debug("Successfully created RouterInfo keystore")
	return initializeKeystore(dir, name, privateKey, encryptionPubKey, encryptionPrivKey), nil
}

// ensureDirectoryExists creates the directory if it does not exist.
// Uses 0700 permissions to protect key material from other users.
// Returns an error if directory creation fails.
func ensureDirectoryExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.WithField("dir", dir).Debug("Creating keystore directory")
		// Use 0700 to protect private key material from other users
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.WithError(err).Error("Failed to create directory")
			return err
		}
	}
	return nil
}

// loadOrGenerateKey attempts to load an existing key from the specified path.
// If no key exists, it generates a new key. Returns the loaded or generated
// private key, or an error if the operation fails.
func loadOrGenerateKey(dir, name string) (types.PrivateKey, error) {
	// Use the same naming convention as StoreKeys: name + ".key"
	fullPath := filepath.Join(dir, name+".key")
	// Also check the legacy path without ".key" suffix for backward compatibility
	legacyPath := filepath.Join(dir, name)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// Check legacy path
		if _, err := os.Stat(legacyPath); err == nil {
			log.WithField("path", legacyPath).Debug("Loading existing key from legacy path")
			keyData, err := os.ReadFile(legacyPath)
			if err != nil {
				log.WithError(err).Error("Failed to read legacy key file")
				return nil, err
			}
			return loadExistingKey(keyData)
		}
		log.WithField("path", fullPath).Debug("Generating new key")
		return generateNewKey()
	}

	log.WithField("path", fullPath).Debug("Loading existing key")
	keyData, err := os.ReadFile(fullPath)
	if err != nil {
		log.WithError(err).Error("Failed to read key file")
		return nil, err
	}

	return loadExistingKey(keyData)
}

// initializeKeystore constructs and returns a configured RouterInfoKeystore
// with the provided directory, name, private key, encryption keys, and a default NTP timestamper.
func initializeKeystore(dir, name string, privateKey types.PrivateKey, encryptionPubKey types.ReceivingPublicKey, encryptionPrivKey types.PrivateEncryptionKey) *RouterInfoKeystore {
	defaultClient := &sntp.DefaultNTPClient{}
	timestamper := sntp.NewRouterTimestamper(defaultClient)
	return &RouterInfoKeystore{
		dir:               dir,
		name:              name,
		privateKey:        privateKey,
		encryptionPubKey:  encryptionPubKey,
		encryptionPrivKey: encryptionPrivKey,
		RouterTimestamper: timestamper,
	}
}

func generateNewKey() (types.PrivateKey, error) {
	// Generate a new key pair using new concrete API - eliminates type assertion
	_, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate Ed25519 key pair")
		return nil, err
	}

	log.Debug("Generated new Ed25519 key pair")
	// Return pointer to private key (required for interface compliance)
	return privKey, nil
}

func loadExistingKey(keyData []byte) (types.PrivateKey, error) {
	// Convert raw bytes to Ed25519PrivateKey type
	key := ed25519.Ed25519PrivateKey(keyData)
	// Return pointer to ensure it implements all interface methods
	// (NewVerifier has a pointer receiver)
	return &key, nil
}

func (ks *RouterInfoKeystore) GetKeys() (types.PublicKey, types.PrivateKey, error) {
	log.WithField("at", "GetKeys").Debug("Retrieving keys")
	public, err := ks.privateKey.Public()
	if err != nil {
		log.WithError(err).WithField("at", "GetKeys").Error("Failed to derive public key")
		return nil, nil, err
	}
	log.WithField("at", "GetKeys").Debug("Successfully retrieved keys")
	return public, ks.privateKey, nil
}

// GetEncryptionPrivateKey returns the X25519 encryption private key used for NTCP2.
// This key is used as the static key for NTCP2 transport sessions, ensuring
// consistent peer identification across router restarts.
func (ks *RouterInfoKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	log.WithField("at", "GetEncryptionPrivateKey").Debug("Returning X25519 encryption private key")
	return ks.encryptionPrivKey
}

func (ks *RouterInfoKeystore) StoreKeys() error {
	log.WithField("at", "StoreKeys").Debug("Storing keys to disk")
	if _, err := os.Stat(ks.dir); os.IsNotExist(err) {
		log.WithField("dir", ks.dir).Debug("Creating directory for keys")
		// Use 0700 to protect private key material from other users
		err := os.MkdirAll(ks.dir, 0o700)
		if err != nil {
			log.WithError(err).WithField("at", "StoreKeys").Error("Failed to create directory")
			return err
		}
	}
	// on the disk somewhere
	filename := filepath.Join(ks.dir, ks.KeyID()+".key")
	log.WithFields(map[string]interface{}{
		"at":   "StoreKeys",
		"file": filename,
	}).Debug("Writing key file")
	err := os.WriteFile(filename, ks.privateKey.Bytes(), 0o600)
	if err != nil {
		log.WithError(err).WithField("at", "StoreKeys").Error("Failed to write key file")
		return err
	}
	log.WithField("at", "StoreKeys").Debug("Successfully stored keys")
	return nil
}

func (ks *RouterInfoKeystore) KeyID() string {
	// If a name is explicitly set, always return it
	if ks.name != "" {
		return ks.name
	}

	// Check if we already have a cached KeyID (with read lock)
	ks.keyIDMutex.RLock()
	if ks.cachedKeyID != "" {
		cachedID := ks.cachedKeyID
		ks.keyIDMutex.RUnlock()
		return cachedID
	}
	ks.keyIDMutex.RUnlock()

	// Try to generate KeyID from the private key
	keyID, needsFallback := ks.tryGenerateKeyIDFromPrivateKey()

	if needsFallback {
		// Use sync.Once to ensure fallback ID is generated only once
		// This prevents race conditions in concurrent access
		ks.keyIDOnce.Do(func() {
			ks.keyIDMutex.Lock()
			ks.cachedKeyID = ks.generateFallbackKeyID()
			ks.keyIDMutex.Unlock()
		})

		// Return the cached fallback ID
		ks.keyIDMutex.RLock()
		cachedID := ks.cachedKeyID
		ks.keyIDMutex.RUnlock()
		return cachedID
	}

	return keyID
}

// tryGenerateKeyIDFromPrivateKey attempts to generate a KeyID from the private key.
// Returns the keyID and a boolean indicating whether a fallback is needed.
func (ks *RouterInfoKeystore) tryGenerateKeyIDFromPrivateKey() (keyID string, needsFallback bool) {
	// Handle nil privateKey case
	if ks.privateKey == nil {
		log.WithField("at", "tryGenerateKeyIDFromPrivateKey").Warn("Private key is nil, using fallback")
		return "", true
	}

	public, err := ks.privateKey.Public()
	if err != nil {
		log.WithError(err).WithField("at", "tryGenerateKeyIDFromPrivateKey").Warn("Failed to derive public key, using fallback")
		return "", true
	}

	// Generate KeyID from public key bytes
	if len(public.Bytes()) > 10 {
		return hex.EncodeToString(public.Bytes()[:10]), false
	}
	return hex.EncodeToString(public.Bytes()), false
}

// generateFallbackKeyID creates a deterministic fallback KeyID when private key is unavailable.
// Uses a hash of the keystore directory path to produce a consistent ID across restarts,
// preventing key file orphaning. This should only be called once per keystore instance via sync.Once.
func (ks *RouterInfoKeystore) generateFallbackKeyID() string {
	log.WithField("at", "generateFallbackKeyID").Warn("Generating deterministic fallback KeyID from directory path")
	// Use a deterministic derivation from the directory path so the same
	// keystore directory always produces the same fallback ID across restarts.
	dirHash := sha256.Sum256([]byte(ks.dir))
	fallbackID := "fallback-" + hex.EncodeToString(dirHash[:4])
	log.WithFields(map[string]interface{}{
		"at":    "generateFallbackKeyID",
		"keyID": fallbackID,
	}).Debug("Generated deterministic fallback KeyID")
	return fallbackID
}

// RouterInfoOptions contains optional parameters for constructing RouterInfo.
// This allows extending ConstructRouterInfo without breaking existing callers.
type RouterInfoOptions struct {
	// CongestionFlag is the congestion capability flag to advertise (D/E/G or empty).
	// Per PROP_162, this is appended after R/U in the caps string.
	CongestionFlag string
}

// ConstructRouterInfo creates a complete RouterInfo structure with signing keys and certificate.
// The opts parameter allows specifying optional parameters like congestion flags.
func (ks *RouterInfoKeystore) ConstructRouterInfo(addresses []*router_address.RouterAddress, opts ...RouterInfoOptions) (*router_info.RouterInfo, error) {
	ks.logConstructionStart(len(addresses))

	publicKey, privateKey, err := ks.validateAndGetKeys()
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to validate and get keys")
	}

	cert, err := ks.createEd25519Certificate()
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to create certificate")
	}

	routerIdentity, err := ks.buildRouterIdentity(publicKey, cert)
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to build router identity")
	}

	options := ks.mergeOptions(opts)

	ri, err := ks.assembleRouterInfo(routerIdentity, addresses, privateKey, options)
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to assemble RouterInfo")
	}

	log.WithField("at", "ConstructRouterInfo").Debug("Successfully constructed RouterInfo")
	return ri, nil
}

// logConstructionStart logs the start of RouterInfo construction.
func (ks *RouterInfoKeystore) logConstructionStart(addressCount int) {
	log.WithFields(map[string]interface{}{
		"at":            "ConstructRouterInfo",
		"address_count": addressCount,
	}).Debug("Constructing RouterInfo")
}

// logAndWrapError logs an error and returns it for ConstructRouterInfo.
func (ks *RouterInfoKeystore) logAndWrapError(err error, msg string) error {
	log.WithError(err).WithField("at", "ConstructRouterInfo").Error(msg)
	return err
}

// mergeOptions combines RouterInfoOptions, with later options taking precedence.
func (ks *RouterInfoKeystore) mergeOptions(opts []RouterInfoOptions) RouterInfoOptions {
	var options RouterInfoOptions
	for _, opt := range opts {
		if opt.CongestionFlag != "" {
			options.CongestionFlag = opt.CongestionFlag
		}
	}
	return options
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
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		return nil, oops.Errorf("failed to create key certificate: %w", err)
	}
	// Convert KeyCertificate to Certificate - KeyCertificate embeds Certificate
	cert := &keyCert.Certificate
	return cert, nil
}

// buildRouterIdentity constructs a RouterIdentity with proper padding and certificate
func (ks *RouterInfoKeystore) buildRouterIdentity(publicKey types.PublicKey, cert *certificate.Certificate) (*router_identity.RouterIdentity, error) {
	// Use GetKeySizes to calculate padding without creating a KeyCertificate object
	sizes, err := key_certificate.GetKeySizes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	if err != nil {
		return nil, oops.Errorf("failed to get key sizes: %w", err)
	}

	padding, err := ks.generateIdentityPaddingFromSizes(sizes.CryptoPublicKeySize, sizes.SigningPublicKeySize)
	if err != nil {
		return nil, err
	}

	signingPubKey, ok := publicKey.(types.SigningPublicKey)
	if !ok {
		return nil, oops.Errorf("public key does not implement SigningPublicKey (got %T)", publicKey)
	}

	routerIdentity, err := router_identity.NewRouterIdentity(
		ks.encryptionPubKey,
		signingPubKey,
		cert,
		padding,
	)
	if err != nil {
		return nil, oops.Errorf("failed to create router identity: %w", err)
	}
	return routerIdentity, nil
}

// generateIdentityPaddingFromSizes creates random padding bytes for RouterIdentity structure
func (ks *RouterInfoKeystore) generateIdentityPaddingFromSizes(pubKeySize, sigKeySize int) ([]byte, error) {
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (pubKeySize + sigKeySize)
	if paddingSize < 0 {
		return nil, oops.Errorf("key sizes exceed KEYS_AND_CERT_DATA_SIZE: pubKeySize=%d + sigKeySize=%d = %d > %d",
			pubKeySize, sigKeySize, pubKeySize+sigKeySize, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	}
	padding := make([]byte, paddingSize)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}
	return padding, nil
}

// assembleRouterInfo creates the final RouterInfo with all components and standard options
func (ks *RouterInfoKeystore) assembleRouterInfo(routerIdentity *router_identity.RouterIdentity, addresses []*router_address.RouterAddress, privateKey types.PrivateKey, opts RouterInfoOptions) (*router_info.RouterInfo, error) {
	log.WithField("at", "assembleRouterInfo").Debug("Assembling RouterInfo with timestamp and options")

	// Validate key type early to fail fast with a descriptive error
	// instead of panicking on an unchecked type assertion later.
	signingPrivKey, ok := privateKey.(types.SigningPrivateKey)
	if !ok {
		return nil, oops.Errorf("private key does not implement SigningPrivateKey (got %T)", privateKey)
	}

	rawTime := ks.RouterTimestamper.GetCurrentTime()
	// Round to nearest second per NTCP2 spec to prevent clock bias in the network
	// Reference: https://geti2p.net/spec/ntcp2#datetime
	publishedTime := rawTime.Round(time.Second)

	// Build caps string - base caps then congestion flag per PROP_162
	caps := ks.buildCapsString(opts.CongestionFlag)

	options := map[string]string{
		"caps":  caps,
		"netId": "2", // Production network
	}

	log.WithFields(map[string]interface{}{
		"at":              "assembleRouterInfo",
		"timestamp":       publishedTime.Unix(),
		"caps":            options["caps"],
		"netId":           options["netId"],
		"congestion_flag": opts.CongestionFlag,
	}).Debug("Creating RouterInfo with options")

	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		publishedTime,
		addresses,
		options,
		signingPrivKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	if err != nil {
		log.WithError(err).WithField("at", "assembleRouterInfo").Error("Failed to create RouterInfo")
		return nil, oops.Errorf("failed to create router info: %w", err)
	}
	log.WithField("at", "assembleRouterInfo").Debug("Successfully assembled RouterInfo")
	return ri, nil
}

// buildCapsString constructs the capabilities string for RouterInfo.
// Per PROP_162, congestion flags (D/E/G) are appended after R/U.
// Base capabilities: NU = Not floodfill, Not Reachable
func (ks *RouterInfoKeystore) buildCapsString(congestionFlag string) string {
	baseCaps := "NU"

	// Per PROP_162: congestion flag is appended after R/U in caps
	if congestionFlag == "" {
		return baseCaps
	}

	// Validate congestion flag is one of D, E, or G
	if congestionFlag != "D" && congestionFlag != "E" && congestionFlag != "G" {
		log.WithFields(map[string]interface{}{
			"at":              "buildCapsString",
			"congestion_flag": congestionFlag,
			"reason":          "invalid congestion flag, ignoring",
		}).Warn("invalid congestion flag provided")
		return baseCaps
	}

	return baseCaps + congestionFlag
}
