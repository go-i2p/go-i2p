package keys

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"

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
	// cachedPadding stores the identity padding bytes to ensure the router's
	// identity hash remains stable across ConstructRouterInfo() calls.
	// Without caching, random padding would be regenerated on every call,
	// producing a different identity hash each time.
	cachedPadding []byte
}

// Ensure RouterInfoKeystore implements KeyStore interface at compile time
var _ KeyStore = (*RouterInfoKeystore)(nil)

// Close zeroes all private key material from memory. After calling Close,
// the keystore must not be used for signing or encryption operations.
// This implements defense-in-depth key hygiene per cryptographic best practices.
func (ks *RouterInfoKeystore) Close() {
	log.WithField("at", "Close").Debug("Zeroing private key material from memory")
	if ks.privateKey != nil {
		ks.privateKey.Zero()
	}
	if ks.encryptionPrivKey != nil {
		ks.encryptionPrivKey.Zero()
	}
}

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

	// Load or generate X25519 encryption key pair for router.
	// The encryption key is persisted to disk so that the router maintains
	// a stable NTCP2 static key across restarts. Without persistence,
	// peers' cached session data would be invalidated on every restart.
	encryptionPubKey, encryptionPrivKey, err := loadOrGenerateEncryptionKey(dir, name)
	if err != nil {
		log.WithError(err).Error("Failed to load or generate X25519 encryption key")
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

// loadOrGenerateEncryptionKey loads an existing X25519 encryption private key
// from disk, or generates a new one if none exists. The public key is derived
// from the private key. This ensures the router's NTCP2 static key remains
// stable across restarts.
func loadOrGenerateEncryptionKey(dir, name string) (types.ReceivingPublicKey, types.PrivateEncryptionKey, error) {
	fullPath := filepath.Join(dir, name+".enc.key")

	keyData, err := os.ReadFile(fullPath)
	if err == nil {
		return loadExistingEncryptionKey(fullPath, keyData)
	}

	// Only generate a new key if the file truly doesn't exist.
	// Any other error (permissions, I/O) could mean the key exists
	// but is inaccessible — generating a new one would silently
	// change the router's NTCP2 static key and identity.
	if !os.IsNotExist(err) {
		return nil, nil, oops.Wrapf(err, "failed to read encryption key file %s (refusing to regenerate)", fullPath)
	}

	return generateAndPersistEncryptionKey(fullPath)
}

// loadExistingEncryptionKey reconstructs an X25519 key pair from persisted private key data.
func loadExistingEncryptionKey(path string, keyData []byte) (types.ReceivingPublicKey, types.PrivateEncryptionKey, error) {
	log.WithField("path", path).Debug("Loading existing X25519 encryption key")
	privKey, err := curve25519.NewCurve25519PrivateKey(keyData)
	if err != nil {
		log.WithError(err).Error("Failed to reconstruct X25519 private key from disk")
		return nil, nil, err
	}
	pubKey, err := privKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to derive X25519 public key")
		return nil, nil, err
	}
	receivingPubKey, ok := pubKey.(types.ReceivingPublicKey)
	if !ok {
		return nil, nil, oops.Errorf("X25519 public key does not implement ReceivingPublicKey")
	}
	log.WithField("path", path).Debug("Successfully loaded X25519 encryption key from disk")
	return receivingPubKey, privKey, nil
}

// generateAndPersistEncryptionKey creates a new X25519 key pair and writes
// the private key to disk for persistence across restarts.
func generateAndPersistEncryptionKey(fullPath string) (types.ReceivingPublicKey, types.PrivateEncryptionKey, error) {
	log.WithField("path", fullPath).Debug("Generating new X25519 encryption key")
	encryptionPubKey, encryptionPrivKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	if err := atomicWriteFile(fullPath, encryptionPrivKey.Bytes(), 0o600); err != nil {
		log.WithError(err).Error("Failed to write X25519 encryption key to disk")
		return nil, nil, err
	}

	receivingPubKey, ok := encryptionPubKey.(types.ReceivingPublicKey)
	if !ok {
		return nil, nil, oops.Errorf("X25519 public key does not implement ReceivingPublicKey")
	}
	log.WithField("path", fullPath).Debug("Generated and stored new X25519 encryption key")
	return receivingPubKey, encryptionPrivKey, nil
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

	log.WithFields(logger.Fields{"at": "generateNewKey"}).Debug("Generated new Ed25519 key pair")
	// Return pointer to private key (required for interface compliance)
	return privKey, nil
}

func loadExistingKey(keyData []byte) (types.PrivateKey, error) {
	// Ed25519 private keys are 32 bytes (seed) or 64 bytes (seed+public).
	// Reject anything else to prevent malformed keys from causing
	// panics or incorrect signatures downstream.
	if len(keyData) != 32 && len(keyData) != 64 {
		return nil, oops.Errorf("invalid Ed25519 key length: got %d bytes, want 32 or 64", len(keyData))
	}
	key := ed25519.Ed25519PrivateKey(keyData)
	return &key, nil
}

// GetKeys returns the public and private signing key pair held by this RouterInfoKeystore.
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

// GetSigningPrivateKey returns the Ed25519 signing private key.
func (ks *RouterInfoKeystore) GetSigningPrivateKey() types.PrivateKey {
	return ks.privateKey
}

// GetEncryptionPrivateKey returns the X25519 encryption private key used for NTCP2.
// This key is used as the static key for NTCP2 transport sessions, ensuring
// consistent peer identification across router restarts.
func (ks *RouterInfoKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	log.WithField("at", "GetEncryptionPrivateKey").Debug("Returning X25519 encryption private key")
	return ks.encryptionPrivKey
}

// StoreKeys persists the signing and encryption private keys to disk in the configured directory.
func (ks *RouterInfoKeystore) StoreKeys() error {
	log.WithField("at", "StoreKeys").Debug("Storing keys to disk")

	if err := ks.ensureKeyDirectory(); err != nil {
		return err
	}

	keyName := ks.resolveKeyName()

	if err := ks.storeSigningKey(keyName); err != nil {
		return err
	}

	if err := ks.storeEncryptionKey(keyName); err != nil {
		return err
	}

	log.WithField("at", "StoreKeys").Debug("Successfully stored all keys")
	return nil
}

// ensureKeyDirectory creates the key directory if it doesn't exist.
func (ks *RouterInfoKeystore) ensureKeyDirectory() error {
	if _, err := os.Stat(ks.dir); os.IsNotExist(err) {
		log.WithField("dir", ks.dir).Debug("Creating directory for keys")
		if err := os.MkdirAll(ks.dir, 0o700); err != nil {
			log.WithError(err).WithField("at", "StoreKeys").Error("Failed to create directory")
			return err
		}
	}
	return nil
}

// resolveKeyName determines the filename prefix for key files.
func (ks *RouterInfoKeystore) resolveKeyName() string {
	if ks.name != "" {
		return ks.name
	}
	return ks.KeyID()
}

// storeSigningKey writes the Ed25519 signing private key to disk.
func (ks *RouterInfoKeystore) storeSigningKey(keyName string) error {
	sigFilename := filepath.Join(ks.dir, keyName+".key")
	log.WithFields(map[string]interface{}{
		"at":   "StoreKeys",
		"file": sigFilename,
	}).Debug("Writing signing key file")
	if err := atomicWriteFile(sigFilename, ks.privateKey.Bytes(), 0o600); err != nil {
		log.WithError(err).WithField("at", "StoreKeys").Error("Failed to write signing key file")
		return err
	}
	return nil
}

// storeEncryptionKey writes the X25519 encryption private key to disk.
func (ks *RouterInfoKeystore) storeEncryptionKey(keyName string) error {
	if ks.encryptionPrivKey == nil {
		return nil
	}
	encFilename := filepath.Join(ks.dir, keyName+".enc.key")
	log.WithFields(map[string]interface{}{
		"at":   "StoreKeys",
		"file": encFilename,
	}).Debug("Writing encryption key file")
	if err := atomicWriteFile(encFilename, ks.encryptionPrivKey.Bytes(), 0o600); err != nil {
		log.WithError(err).WithField("at", "StoreKeys").Error("Failed to write encryption key file")
		return err
	}
	return nil
}

// KeyID returns a stable, filesystem-safe identifier for this keystore, derived from the configured name or the public key.
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

	// Cache the successfully generated KeyID so we don't re-derive
	// the public key on every subsequent call.
	ks.keyIDMutex.Lock()
	ks.cachedKeyID = keyID
	ks.keyIDMutex.Unlock()

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
	dirHash := types.SHA256([]byte(ks.dir))
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
	// Reachable indicates whether the router has at least one active transport
	// address and can accept inbound connections. When true, the caps string
	// uses "R" (Reachable); when false, "U" (Unreachable).
	Reachable bool
	// Floodfill indicates whether the router should advertise the "f" (floodfill)
	// capability. When true, "f" replaces "N" (not floodfill) in the caps string.
	// Floodfills store and distribute netDB entries.
	Floodfill bool
	// NetID is the network identifier. Defaults to "2" (production I2P network).
	// Set to "3" for testnet or other values for experimental networks.
	NetID string
	// Version is the router.version string advertised in RouterInfo options.
	// Defaults to "0.9.63". Must be >= "0.9.58" to pass i2pd's NETDB_MIN_ALLOWED_VERSION check.
	Version string
	// Hidden indicates that the router operates in hidden mode (Java I2P
	// semantics). When true, the caps string includes "H" (hidden) and forces
	// "U" (unreachable) regardless of the Reachable flag, signalling to the
	// rest of the network that this router will not accept inbound connections
	// or transit tunnels.
	Hidden bool
}

// ConstructRouterInfo creates a complete RouterInfo structure with signing keys and certificate.
// The opts parameter allows specifying optional parameters like congestion flags.
func (ks *RouterInfoKeystore) ConstructRouterInfo(addresses []*router_address.RouterAddress, opts ...RouterInfoOptions) (*router_info.RouterInfo, error) {
	ks.logConstructionStart(len(addresses))

	log.WithField("at", "ConstructRouterInfo").Debug("step 1/5: validating and getting keys")
	publicKey, privateKey, err := ks.validateAndGetKeys()
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to validate and get keys")
	}

	log.WithField("at", "ConstructRouterInfo").Debug("step 2/5: creating Ed25519 certificate")
	cert, err := ks.createEd25519Certificate()
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to create certificate")
	}

	log.WithField("at", "ConstructRouterInfo").Debug("step 3/5: building router identity")
	routerIdentity, err := ks.buildRouterIdentity(publicKey, cert)
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to build router identity")
	}

	options := ks.mergeOptions(opts)

	log.WithField("at", "ConstructRouterInfo").Debug("step 4/5: assembling router info (includes signing)")
	ri, err := ks.assembleRouterInfo(routerIdentity, addresses, privateKey, options)
	if err != nil {
		return nil, ks.logAndWrapError(err, "Failed to assemble RouterInfo")
	}

	log.WithField("at", "ConstructRouterInfo").Debug("step 5/5: construction complete")
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
		if opt.Reachable {
			options.Reachable = true
		}
		if opt.Floodfill {
			options.Floodfill = true
		}
		if opt.NetID != "" {
			options.NetID = opt.NetID
		}
		if opt.Version != "" {
			options.Version = opt.Version
		}
		if opt.Hidden {
			options.Hidden = true
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

// generateIdentityPaddingFromSizes returns stable padding bytes for RouterIdentity structure.
// The padding is generated once and cached for the lifetime of the keystore to ensure
// the router's identity hash remains stable across ConstructRouterInfo() calls.
// The padding is also persisted to disk so it survives restarts.
func (ks *RouterInfoKeystore) generateIdentityPaddingFromSizes(pubKeySize, sigKeySize int) ([]byte, error) {
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (pubKeySize + sigKeySize)
	if paddingSize < 0 {
		return nil, oops.Errorf("key sizes exceed KEYS_AND_CERT_DATA_SIZE: pubKeySize=%d + sigKeySize=%d = %d > %d",
			pubKeySize, sigKeySize, pubKeySize+sigKeySize, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	}

	if len(ks.cachedPadding) == paddingSize {
		return ks.cachedPadding, nil
	}

	padding, err := ks.loadOrGeneratePadding(paddingSize)
	if err != nil {
		return nil, err
	}
	ks.cachedPadding = padding
	return ks.cachedPadding, nil
}

// loadOrGeneratePadding tries to load persisted padding or generates new padding.
func (ks *RouterInfoKeystore) loadOrGeneratePadding(paddingSize int) ([]byte, error) {
	paddingPath := filepath.Join(ks.dir, ks.name+".padding")

	padding, err := ks.tryLoadPaddingFromDisk(paddingPath, paddingSize)
	if err != nil {
		return nil, err
	}
	if padding != nil {
		return padding, nil
	}

	return ks.generateAndPersistPadding(paddingPath, paddingSize)
}

// tryLoadPaddingFromDisk attempts to load padding from disk. Returns nil, nil if file doesn't exist.
func (ks *RouterInfoKeystore) tryLoadPaddingFromDisk(paddingPath string, expectedSize int) ([]byte, error) {
	paddingData, readErr := os.ReadFile(paddingPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil
		}
		return nil, oops.Errorf("failed to read padding file %s (refusing to regenerate — would change identity): %w", paddingPath, readErr)
	}

	if len(paddingData) == expectedSize {
		log.WithField("at", "generateIdentityPaddingFromSizes").Debug("Loaded identity padding from disk")
		return paddingData, nil
	}

	log.WithField("at", "generateIdentityPaddingFromSizes").Warn("Padding file size mismatch, regenerating")
	return nil, nil
}

// generateAndPersistPadding creates new random padding and saves it to disk.
func (ks *RouterInfoKeystore) generateAndPersistPadding(paddingPath string, paddingSize int) ([]byte, error) {
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}

	if err := atomicWriteFile(paddingPath, padding, 0o600); err != nil {
		log.WithError(err).Warn("Failed to persist identity padding to disk; identity hash may change on restart")
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
	caps := ks.buildCapsString(opts.CongestionFlag, opts.Reachable, opts.Floodfill, opts.Hidden)

	netID := opts.NetID
	if netID == "" {
		netID = "2" // Default: production I2P network
	}

	// router.version is required by i2pd (and Java I2P): if absent, i2pd sets
	// m_Version=0 which triggers SetUnreachable(true) → reason_code=15 in NTCP2
	// ProcessSessionConfirmed.  Minimum accepted by i2pd is NETDB_MIN_ALLOWED_VERSION
	// = 0.9.58; use 0.9.63 which also clears NETDB_MIN_PEER_TEST_VERSION (0.9.62).
	routerVersion := opts.Version
	if routerVersion == "" {
		routerVersion = "0.9.67"
	}

	options := map[string]string{
		"caps":           caps,
		"netId":          netID,
		"router.version": routerVersion,
	}

	log.WithFields(map[string]interface{}{
		"at":              "assembleRouterInfo",
		"timestamp":       publishedTime.Unix(),
		"caps":            options["caps"],
		"netId":           options["netId"],
		"router.version":  options["router.version"],
		"congestion_flag": opts.CongestionFlag,
	}).Debug("Creating RouterInfo with options")

	log.WithField("at", "assembleRouterInfo").Debug("entering router_info.NewRouterInfo — if no further log appears, stall is inside dependency")
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
	log.WithField("at", "assembleRouterInfo").Debug("router_info.NewRouterInfo returned successfully")
	return ri, nil
}

// buildCapsString constructs the capabilities string for RouterInfo.
// Per PROP_162, congestion flags (D/E/G) are appended after R/U.
// Capabilities: f = Floodfill, N = Not floodfill, R = Reachable, U = Unreachable, H = Hidden.
// When hidden is true, the reachability flag is forced to "U" and "H" is appended,
// matching Java I2P's hidden-mode RouterInfo semantics.
func (ks *RouterInfoKeystore) buildCapsString(congestionFlag string, reachable, floodfill, hidden bool) string {
	reachabilityFlag := "U"
	if reachable && !hidden {
		reachabilityFlag = "R"
	}

	floodfillFlag := "N"
	if floodfill {
		floodfillFlag = "f"
	}

	baseCaps := floodfillFlag + reachabilityFlag
	if hidden {
		baseCaps += "H"
	}

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
