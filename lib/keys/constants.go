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
