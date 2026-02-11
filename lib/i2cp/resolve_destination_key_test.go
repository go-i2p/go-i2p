package i2cp

import (
	"errors"
	"testing"

	common "github.com/go-i2p/common/data"
)

// mockDestinationResolver is a test double for the destination resolver interface.
type mockDestinationResolver struct {
	key [32]byte
	err error
}

func (m *mockDestinationResolver) ResolveDestination(destHash common.Hash) ([32]byte, error) {
	return m.key, m.err
}

// TestResolveDestinationKey_NilResolver verifies that resolveDestinationKey returns
// ErrNoDestinationResolver when no resolver is configured, instead of silently
// returning a zero encryption key.
func TestResolveDestinationKey_NilResolver(t *testing.T) {
	server := &Server{}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	key, err := server.resolveDestinationKey(destHash)
	if err == nil {
		t.Fatal("expected error when destinationResolver is nil, got nil")
	}
	if !errors.Is(err, ErrNoDestinationResolver) {
		t.Fatalf("expected ErrNoDestinationResolver, got: %v", err)
	}

	// Verify the returned key is zero (no partial key leakage)
	var zeroKey [32]byte
	if key != zeroKey {
		t.Error("expected zero key on error, got non-zero key")
	}
}

// TestResolveDestinationKey_WithResolver verifies that resolveDestinationKey
// returns the key from the resolver when one is configured.
func TestResolveDestinationKey_WithResolver(t *testing.T) {
	var expectedKey [32]byte
	for i := range expectedKey {
		expectedKey[i] = byte(i + 1)
	}

	server := &Server{
		destinationResolver: &mockDestinationResolver{
			key: expectedKey,
			err: nil,
		},
	}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	key, err := server.resolveDestinationKey(destHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != expectedKey {
		t.Errorf("expected key %x, got %x", expectedKey, key)
	}
}

// TestResolveDestinationKey_ResolverError verifies that errors from the resolver
// are properly propagated.
func TestResolveDestinationKey_ResolverError(t *testing.T) {
	resolverErr := errors.New("destination not found in NetDB")
	server := &Server{
		destinationResolver: &mockDestinationResolver{
			err: resolverErr,
		},
	}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	_, err := server.resolveDestinationKey(destHash)
	if err == nil {
		t.Fatal("expected error from resolver, got nil")
	}
	if !errors.Is(err, resolverErr) {
		t.Fatalf("expected wrapped resolver error, got: %v", err)
	}
}

// TestErrNoDestinationResolver_ErrorMessage verifies the sentinel error message
// is descriptive enough for debugging.
func TestErrNoDestinationResolver_ErrorMessage(t *testing.T) {
	expected := "no destination resolver configured: cannot resolve encryption key"
	if ErrNoDestinationResolver.Error() != expected {
		t.Errorf("unexpected error message: %q", ErrNoDestinationResolver.Error())
	}
}
