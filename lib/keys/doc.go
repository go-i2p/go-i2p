// Package keys provides key management for I2P destinations and routers.
//
// # What is a key store?
//
// Every I2P identity is backed by a pair of private keys. A key store holds
// those keys and keeps them on disk so the identity survives a restart. This
// package manages two kinds of key stores:
//
//   - DestinationKeyStore: the keys for a destination (an I2P service). It
//     holds an Ed25519 signing key and an X25519 encryption key, which are
//     used to create LeaseSet2s and to encrypt messages.
//
//   - RouterInfoKeystore: the identity key for a router, used to sign the
//     router's RouterInfo.
//
// Both use modern cryptography (Ed25519 for signing, X25519 for encryption),
// compatible with ECIES-X25519-AEAD-Ratchet.
//
// # Stable identity
//
// LoadOrCreateDestinationKeyStore is the main entry point for services that
// need a stable identity. It loads an existing key store from disk, or creates
// and persists a new one if none exists. If the file exists but is corrupted,
// it returns an error rather than silently generating a new identity, which
// would cause identity loss.
//
// # Usage example
//
//	// Load an existing key store, or create and persist a new one.
//	store, err := keys.LoadOrCreateDestinationKeyStore("/path/to/keys", "mydest")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// The store's destination is stable across restarts.
//	dest := store.Destination()
//
// # Persistence
//
// Keys are written atomically (write to a temp file, then rename) so a crash
// mid-write cannot corrupt the stored identity.
package keys
