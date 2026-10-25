// Mock types for garlic-related interfaces used in I2NP tests.
package i2np

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// Compile-time interface verification for mocks.
var (
	_ GarlicMessageDecryptor = (*mockGarlicDecryptor)(nil)
)

// mockGarlicDecryptor implements GarlicMessageDecryptor for testing.
// Allows configuring return values per-call or via callback functions.
type mockGarlicDecryptor struct {
	// decryptFunc is called when DecryptGarlicMessage is invoked. If nil,
	// the mock returns decryptPlaintexts/decryptTag/decryptErr.
	decryptFunc func(encrypted []byte) ([][]byte, [8]byte, *[32]byte, error)

	// Default return values when decryptFunc is nil.
	// Each element is the payload of one GarlicClove block.
	decryptPlaintexts [][]byte
	decryptTag        [8]byte
	decryptErr        error

	// callCount tracks how many times DecryptGarlicMessage was called.
	callCount int
	// lastEncrypted records the last encrypted payload passed.
	lastEncrypted []byte
}

// DecryptGarlicMessage implements GarlicMessageDecryptor.
func (m *mockGarlicDecryptor) DecryptGarlicMessage(encrypted []byte) ([][]byte, [8]byte, *[32]byte, error) {
	m.callCount++
	m.lastEncrypted = encrypted
	if m.decryptFunc != nil {
		return m.decryptFunc(encrypted)
	}
	return m.decryptPlaintexts, m.decryptTag, nil, m.decryptErr
}

// newMockGarlicDecryptor creates a mock decryptor with default success behavior.
// The returned plaintext is empty by default; callers should set decryptPlaintexts
// or decryptFunc for meaningful responses.
func newMockGarlicDecryptor() *mockGarlicDecryptor {
	return &mockGarlicDecryptor{}
}

// newMockGarlicDecryptorWithError creates a mock that always returns an error.
func newMockGarlicDecryptorWithError(err error) *mockGarlicDecryptor {
	return &mockGarlicDecryptor{
		decryptErr: err,
	}
}

// newMockGarlicDecryptorWithPlaintext creates a mock that returns the given plaintext
// wrapped as a single GarlicClove payload.
func newMockGarlicDecryptorWithPlaintext(plaintext []byte, tag [8]byte) *mockGarlicDecryptor {
	return &mockGarlicDecryptor{
		decryptPlaintexts: [][]byte{plaintext},
		decryptTag:        tag,
	}
}

// mockGarlicDecryptorRoundTrip creates a mock that "decrypts" by returning
// the encrypted data unmodified. Useful for testing the processing pipeline
// without exercising real crypto.
func mockGarlicDecryptorRoundTrip() *mockGarlicDecryptor {
	return &mockGarlicDecryptor{
		decryptFunc: func(encrypted []byte) ([][]byte, [8]byte, *[32]byte, error) {
			if len(encrypted) == 0 {
				return nil, [8]byte{}, nil, fmt.Errorf("empty encrypted data")
			}
			return [][]byte{encrypted}, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, nil, nil
		},
	}
}

// mockCloveForwarder implements GarlicCloveForwarder for unit testing
// the DESTINATION, ROUTER, and TUNNEL delivery dispatch paths in
// processor_handlers.go without requiring a real GarlicMessageRouter.
type mockCloveForwarder struct {
	// Per-call return errors (nil means success).
	destErr   error
	routerErr error
	tunnelErr error

	// Captured arguments for assertion.
	destHash    common.Hash
	routerHash  common.Hash
	gatewayHash common.Hash
	tunnelID    tunnel.TunnelID

	// Call counters.
	destCalls   int
	routerCalls int
	tunnelCalls int
}

// Compile-time check: mockCloveForwarder must satisfy GarlicCloveForwarder.
var _ GarlicCloveForwarder = (*mockCloveForwarder)(nil)

func (m *mockCloveForwarder) ForwardToDestination(destHash common.Hash, msg Message) error {
	m.destCalls++
	m.destHash = destHash
	return m.destErr
}

func (m *mockCloveForwarder) ForwardToRouter(routerHash common.Hash, msg Message) error {
	m.routerCalls++
	m.routerHash = routerHash
	return m.routerErr
}

func (m *mockCloveForwarder) ForwardThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, msg Message) error {
	m.tunnelCalls++
	m.gatewayHash = gatewayHash
	m.tunnelID = tunnelID
	return m.tunnelErr
}
