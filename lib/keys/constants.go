package keys

// ──────────────────────────────────────────────────────────────────────────────
// Key identifier derivation
// ──────────────────────────────────────────────────────────────────────────────

// keyIDPrefixBytes is how many leading bytes of a public key are taken to form
// a KeyID. The result is hex-encoded, so a KeyID is 2× this many characters.
// Truncating keeps keystore filenames short and readable while staying unique
// enough across the handful of identities a single router holds.
// Moved from: types.go
const keyIDPrefixBytes = 10

// ──────────────────────────────────────────────────────────────────────────────
// Ed25519 key sizes
// ──────────────────────────────────────────────────────────────────────────────

// Ed25519 keys are accepted on disk in either of two forms, and nothing else:
// a bare 32-byte seed, or the 64-byte seed+public concatenation Go's
// ed25519 package uses for a full private key.
// Moved from: routerinfo_keystore.go
const (
	// Ed25519SeedSize is the length of an Ed25519 private key seed, which is
	// also the length of an Ed25519 public key.
	Ed25519SeedSize = 32

	// Ed25519PrivateKeySize is the length of a full Ed25519 private key as
	// encoded by crypto/ed25519: the seed followed by the public key.
	Ed25519PrivateKeySize = 64
)

// ──────────────────────────────────────────────────────────────────────────────
// Destination keystore file format
// ──────────────────────────────────────────────────────────────────────────────

// A persisted destination keystore opens with a magic header whose last byte is
// the format version, followed by length-prefixed fields. Version 1 stores the
// signing and encryption private keys; version 2 adds the identity padding, which
// is what makes the reconstructed .b32.i2p address stable. The version numbers
// below are named so the reader's comparisons and the magic bytes cannot disagree
// about which format a file is.
//
// Moved from: destination_persistence.go
const (
	// destinationKeyStoreVersion1 is the two-field format: signing and encryption
	// private keys.
	destinationKeyStoreVersion1 = 1

	// destinationKeyStoreVersion2 adds the identity padding field.
	destinationKeyStoreVersion2 = 2

	// keyStoreMagicSize is how many bytes the magic header occupies, which is also
	// the minimum buffer the version probe needs.
	keyStoreMagicSize = 4

	// keyStoreFieldLengthSize is the big-endian uint32 that prefixes each stored
	// field.
	keyStoreFieldLengthSize = 4

	// keyStoreFieldCountV2 is how many length-prefixed fields a version-2 keystore
	// writes: signing key, encryption key, and padding.
	keyStoreFieldCountV2 = 3
)

// ──────────────────────────────────────────────────────────────────────────────
// Key material file permissions
// ──────────────────────────────────────────────────────────────────────────────

// Signing and encryption private keys are the material that makes a destination's
// identity usable by anyone who holds it, so every file holding one is written
// owner-only and the directory that contains them is traversable but not listable
// by other accounts.
//
// Moved from: destination_persistence.go, routerinfo_keystore.go
const (
	// keyMaterialFileMode is the permission for files holding private key material.
	keyMaterialFileMode = 0o600

	// keyMaterialDirMode is the permission for the directories holding them.
	keyMaterialDirMode = 0o700
)
