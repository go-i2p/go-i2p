package keys

import "os"

// Shared test constants for the keys package test suite.
// These replace magic literals that appear across multiple test files.
const (
	// testEd25519PubKeySize is the expected Ed25519 public key size in bytes.
	testEd25519PubKeySize = 32

	// testEd25519PrivKeySize is the expected Ed25519 private key size in bytes (expanded form).
	testEd25519PrivKeySize = 64

	// testX25519KeySize is the expected X25519 key size in bytes (both public and private).
	testX25519KeySize = 32

	// testEd25519SignatureSize is the expected Ed25519 signature size in bytes.
	testEd25519SignatureSize = 64

	// testExpectedPaddingSize is the expected identity padding size for Ed25519/X25519
	// key combination: KEYS_AND_CERT_DATA_SIZE(384) - X25519(32) - Ed25519(32) = 320.
	testExpectedPaddingSize = 320

	// testKeyFilePerms is the expected permission mode for key files.
	testKeyFilePerms os.FileMode = 0o600

	// testDirPerms is the expected permission mode for keystore directories.
	testDirPerms os.FileMode = 0o700
)
