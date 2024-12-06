package offline_signature

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/stretchr/testify/assert"
)

// TestSigTypeKeyLengths tests that the correct key and signature lengths are returned for known sigtypes.
func TestSigTypeKeyLengths(t *testing.T) {
	keyLen, sigLen, err := sigTypeKeyLengths(signature.SIGNATURE_TYPE_DSA_SHA1)
	assert.Nil(t, err)
	assert.Equal(t, 128, keyLen)
	assert.Equal(t, 40, sigLen)

	keyLen, sigLen, err = sigTypeKeyLengths(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.Nil(t, err)
	assert.Equal(t, 32, keyLen)
	assert.Equal(t, 64, sigLen)

	// Test unsupported sigtype
	_, _, err = sigTypeKeyLengths(9999)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsupported sigtype")
}

// TestNewOfflineSignature checks that NewOfflineSignature properly validates sizes.
func TestNewOfflineSignature(t *testing.T) {
	// For Ed25519: keyLen=32, sigLen=64
	transientKey := make([]byte, 32)
	signatureBytes := make([]byte, 64)

	osig, err := NewOfflineSignature(12345, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, transientKey, signatureBytes)
	assert.Nil(t, err)
	assert.NotNil(t, osig)
	assert.Equal(t, uint32(12345), osig.Expires)
	assert.Equal(t, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519), osig.SigType)
	assert.Equal(t, 32, len(osig.TransientPublicKey))
	assert.Equal(t, 64, len(osig.Signature))

	// Wrong key length
	wrongKey := make([]byte, 16) // Should be 32 for EDDSA
	_, err = NewOfflineSignature(12345, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, wrongKey, signatureBytes)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid transient public key length")

	// Wrong signature length
	wrongSig := make([]byte, 10)
	_, err = NewOfflineSignature(12345, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, transientKey, wrongSig)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid signature length")
}

// TestBytes checks that OfflineSignature.Bytes() returns the correct serialized form.
func TestBytes(t *testing.T) {
	transientKey := make([]byte, 32)
	signatureBytes := make([]byte, 64)
	var expires uint32 = 987654321
	var sigtype uint16 = signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	osig, err := NewOfflineSignature(expires, sigtype, transientKey, signatureBytes)
	assert.Nil(t, err)
	assert.NotNil(t, osig)

	buf := osig.Bytes()
	assert.Equal(t, 6+32+64, len(buf))

	exp := binary.BigEndian.Uint32(buf[0:4])
	st := binary.BigEndian.Uint16(buf[4:6])
	assert.Equal(t, expires, exp)
	assert.Equal(t, sigtype, st)
	assert.Equal(t, transientKey, buf[6:6+32])
	assert.Equal(t, signatureBytes, buf[6+32:6+32+64])
}

// TestReadOfflineSignature checks parsing from bytes.
func TestReadOfflineSignature(t *testing.T) {
	transientKey := make([]byte, 32)
	sigBytes := make([]byte, 64)
	var expires uint32 = 1234
	var sigtype uint16 = signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	// Construct valid data
	data := make([]byte, 6+32+64)
	binary.BigEndian.PutUint32(data[0:4], expires)
	binary.BigEndian.PutUint16(data[4:6], sigtype)
	copy(data[6:6+32], transientKey)
	copy(data[6+32:], sigBytes)

	osig, remainder, err := ReadOfflineSignature(data)
	assert.Nil(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, expires, osig.Expires)
	assert.Equal(t, sigtype, osig.SigType)
	assert.Equal(t, transientKey, osig.TransientPublicKey)
	assert.Equal(t, sigBytes, osig.Signature)

	// Test insufficient data
	shortData := data[:4]
	_, _, err = ReadOfflineSignature(shortData)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "not enough data to read offline signature header")
}

// TestReadOfflineSignatureNotEnoughForFullStructure tests scenario where header is present but not full structure.
func TestReadOfflineSignatureNotEnoughForFullStructure(t *testing.T) {
	transientKey := make([]byte, 32)
	sigBytes := make([]byte, 64)
	var expires uint32 = 1234
	var sigtype uint16 = signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	data := make([]byte, 6+32+64)
	binary.BigEndian.PutUint32(data[0:4], expires)
	binary.BigEndian.PutUint16(data[4:6], sigtype)
	copy(data[6:6+32], transientKey)
	copy(data[6+32:], sigBytes)

	// Cut off the data so it becomes incomplete
	incompleteData := data[:50] // less than needed
	_, _, err := ReadOfflineSignature(incompleteData)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "not enough data to read full offline signature")
}

// TestVerifyOfflineSignature checks verification logic.
func TestVerifyOfflineSignature(t *testing.T) {
	transientKey := make([]byte, 32)
	sigBytes := make([]byte, 64) // Dummy sig
	expires := uint32(2222)
	sigtype := signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	osig, err := NewOfflineSignature(expires, uint16(sigtype), transientKey, sigBytes)
	assert.Nil(t, err)

	mockVerifyFunc := func(data, sig []byte) error {
		if len(data) != 6+32 {
			return errors.New("data length incorrect")
		}
		if len(sig) != 64 {
			return errors.New("signature length incorrect")
		}
		return nil
	}

	err = osig.VerifyOfflineSignature(mockVerifyFunc)
	assert.Nil(t, err)

	mockVerifyFail := func(data, sig []byte) error {
		return errors.New("verification failed")
	}
	err = osig.VerifyOfflineSignature(mockVerifyFail)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// TestRoundTrip tests a round-trip create -> serialize -> parse and ensures equality.
func TestRoundTrip(t *testing.T) {
	transientKey := make([]byte, 32)
	sigBytes := make([]byte, 64)
	expires := uint32(9999)
	sigtype := signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	osig, err := NewOfflineSignature(expires, uint16(sigtype), transientKey, sigBytes)
	assert.Nil(t, err)

	serialized := osig.Bytes()
	parsedOsig, remainder, err := ReadOfflineSignature(serialized)
	assert.Nil(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, osig.Expires, parsedOsig.Expires)
	assert.Equal(t, osig.SigType, parsedOsig.SigType)
	assert.Equal(t, osig.TransientPublicKey, parsedOsig.TransientPublicKey)
	assert.Equal(t, osig.Signature, parsedOsig.Signature)
}
