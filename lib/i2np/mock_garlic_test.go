package i2np

import (
	"fmt"

	"github.com/go-i2p/common/session_key"
)

// Compile-time interface verification for mocks.
var _ GarlicMessageDecryptor = (*mockGarlicDecryptor)(nil)
var _ ReplyRecordEncryptor = (*mockReplyEncryptor)(nil)

// mockGarlicDecryptor implements GarlicMessageDecryptor for testing.
// Allows configuring return values per-call or via callback functions.
type mockGarlicDecryptor struct {
	// decryptFunc is called when DecryptGarlicMessage is invoked. If nil,
	// the mock returns decryptPlaintext/decryptTag/decryptErr.
	decryptFunc func(encrypted []byte) ([]byte, [8]byte, *[32]byte, error)

	// Default return values when decryptFunc is nil.
	decryptPlaintext []byte
	decryptTag       [8]byte
	decryptErr       error

	// callCount tracks how many times DecryptGarlicMessage was called.
	callCount int
	// lastEncrypted records the last encrypted payload passed.
	lastEncrypted []byte
}

// DecryptGarlicMessage implements GarlicMessageDecryptor.
func (m *mockGarlicDecryptor) DecryptGarlicMessage(encrypted []byte) ([]byte, [8]byte, *[32]byte, error) {
	m.callCount++
	m.lastEncrypted = encrypted
	if m.decryptFunc != nil {
		return m.decryptFunc(encrypted)
	}
	return m.decryptPlaintext, m.decryptTag, nil, m.decryptErr
}

// newMockGarlicDecryptor creates a mock decryptor with default success behavior.
// The returned plaintext is empty by default; callers should set decryptPlaintext
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

// newMockGarlicDecryptorWithPlaintext creates a mock that returns the given plaintext.
func newMockGarlicDecryptorWithPlaintext(plaintext []byte, tag [8]byte) *mockGarlicDecryptor {
	return &mockGarlicDecryptor{
		decryptPlaintext: plaintext,
		decryptTag:       tag,
	}
}

// mockReplyEncryptor implements ReplyRecordEncryptor for testing.
type mockReplyEncryptor struct {
	// encryptFunc is called when EncryptReplyRecord is invoked. If nil,
	// the mock returns encryptResult/encryptErr.
	encryptFunc func(record BuildResponseRecord, replyKey session_key.SessionKey, replyIV [16]byte) ([]byte, error)

	// Default return values when encryptFunc is nil.
	encryptResult []byte
	encryptErr    error

	// callCount tracks how many times EncryptReplyRecord was called.
	callCount int
	// lastRecord records the last BuildResponseRecord passed.
	lastRecord BuildResponseRecord
}

// EncryptReplyRecord implements ReplyRecordEncryptor.
func (m *mockReplyEncryptor) EncryptReplyRecord(record BuildResponseRecord, replyKey session_key.SessionKey, replyIV [16]byte) ([]byte, error) {
	m.callCount++
	m.lastRecord = record
	if m.encryptFunc != nil {
		return m.encryptFunc(record, replyKey, replyIV)
	}
	return m.encryptResult, m.encryptErr
}

// newMockReplyEncryptor creates a mock reply encryptor with default success behavior.
// Returns a 544-byte zero slice by default (matching ChaCha20-Poly1305 output size).
func newMockReplyEncryptor() *mockReplyEncryptor {
	return &mockReplyEncryptor{
		encryptResult: make([]byte, 544),
	}
}

// newMockReplyEncryptorWithError creates a mock that always returns an error.
func newMockReplyEncryptorWithError(err error) *mockReplyEncryptor {
	return &mockReplyEncryptor{
		encryptErr: err,
	}
}

// mockGarlicDecryptorRoundTrip creates a mock that "decrypts" by returning
// the encrypted data unmodified. Useful for testing the processing pipeline
// without exercising real crypto.
func mockGarlicDecryptorRoundTrip() *mockGarlicDecryptor {
	return &mockGarlicDecryptor{
		decryptFunc: func(encrypted []byte) ([]byte, [8]byte, *[32]byte, error) {
			if len(encrypted) == 0 {
				return nil, [8]byte{}, nil, fmt.Errorf("empty encrypted data")
			}
			return encrypted, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, nil, nil
		},
	}
}
