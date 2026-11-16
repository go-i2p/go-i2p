package i2np

import (
	"testing"

	"github.com/go-i2p/crypto/ecies"
)

// validKey returns a valid Curve25519 private key for constructing a session
// manager (a zero key is rejected by the key-derivation step).
func validKey(t *testing.T) [32]byte {
	t.Helper()
	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	var key [32]byte
	copy(key[:], privBytes)
	return key
}

// TestSetGarlicEncryptionCacheSize_ReachesNewManagers is the C1 guard for
// performance.garlic_encryption_cache_size: the operator's cap must reach newly
// created GarlicSessionManagers (via go-noise WithMaxSessions). Before this fix
// every manager used go-noise's hardcoded MaxGarlicSessions and the knob was
// dead.
func TestSetGarlicEncryptionCacheSize_ReachesNewManagers(t *testing.T) {
	t.Cleanup(func() { SetGarlicEncryptionCacheSize(0) })

	SetGarlicEncryptionCacheSize(123)
	if got := GetGarlicEncryptionCacheSize(); got != 123 {
		t.Fatalf("GetGarlicEncryptionCacheSize() = %d, want 123", got)
	}

	key := validKey(t)
	sm, err := NewGarlicSessionManager(key)
	if err != nil {
		t.Fatalf("NewGarlicSessionManager failed: %v", err)
	}
	defer sm.Close()

	if got := sm.inner.MaxSessions(); got != 123 {
		t.Fatalf("session manager MaxSessions() = %d, want 123 (knob did not reach the manager)", got)
	}
}

// TestSetGarlicEncryptionCacheSize_ZeroUsesBuiltIn pins that an unset value
// leaves go-noise's built-in default in effect.
func TestSetGarlicEncryptionCacheSize_ZeroUsesBuiltIn(t *testing.T) {
	t.Cleanup(func() { SetGarlicEncryptionCacheSize(0) })

	SetGarlicEncryptionCacheSize(0)

	key := validKey(t)
	sm, err := NewGarlicSessionManager(key)
	if err != nil {
		t.Fatalf("NewGarlicSessionManager failed: %v", err)
	}
	defer sm.Close()

	// go-noise's built-in default (MaxGarlicSessions) must apply when unset.
	if got := sm.inner.MaxSessions(); got <= 0 {
		t.Fatalf("session manager MaxSessions() = %d, want the built-in positive default", got)
	}
}
