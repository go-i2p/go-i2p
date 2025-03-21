package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSigningPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	assert := assert.New(t)

	// Create certificate with signing key type P521 (3)
	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x03, 0x00, 0x07})
	assert.Nil(err)

	pk_type := key_cert.SigningPublicKeyType()
	assert.Equal(KEYCERT_SIGN_P521, pk_type, "SigningPublicKeyType() did not return correct type")
}

func TestSigningPublicKeyTypeWithInvalidData(t *testing.T) {
	assert := assert.New(t)

	// Test with invalid short data
	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x01, 0x00})
	assert.NotNil(err)
	assert.Contains(err.Error(), "key certificate data too short")
	assert.Nil(key_cert)
}

func TestPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	assert := assert.New(t)

	// Create certificate with crypto type ELG (0)
	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	assert.Nil(err)

	pk_type := key_cert.PublicKeyType()
	assert.Equal(KEYCERT_CRYPTO_ELG, pk_type, "PublicKeyType() did not return correct type")
}

func TestPublicKeyTypeWithInvalidData(t *testing.T) {
	assert := assert.New(t)

	// Test with invalid short data
	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x02})
	assert.NotNil(err)
	assert.Contains(err.Error(), "certificate parsing warning: certificate data is shorter than specified by length", "Expected error for invalid data")
	assert.Nil(key_cert)
}

func TestConstructPublicKeyWithInsufficientData(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	assert.Nil(err)

	// Test with data smaller than required size
	data := make([]byte, 255) // ELG requires 256 bytes
	_, err = key_cert.ConstructPublicKey(data)

	assert.NotNil(err)
	assert.Equal("error constructing public key: not enough data", err.Error())
}

func TestConstructPublicKeyReturnsCorrectDataWithElg(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 256)
	pk, err := key_cert.ConstructPublicKey(data)

	assert.Nil(err, "ConstructPublicKey() returned error with valid data")
	assert.Equal(pk.Len(), 256, "ConstructPublicKey() did not return public key with correct length")
}

func TestConstructSigningPublicKeyReportsWhenDataTooSmall(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 127)
	_, err = key_cert.ConstructSigningPublicKey(data)

	if assert.NotNil(err) {
		assert.Equal("error constructing signing public key: not enough data", err.Error(), "correct error message should be returned")
	}
}

func TestConstructSigningPublicKeyWithDSASHA1(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with DSA SHA1 returned error with valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_DSA_SHA1_SIZE, "ConstructSigningPublicKey() with DSA SHA1 returned incorrect signingPublicKey length")
}

func TestConstructSigningPublicKeyWithP256(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P256 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P256_SIZE, "ConstructSigningPublicKey() with P256 returned incorrect signingPublicKey length")
}

func TestConstructSigningPublicKeyWithP384(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P384 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P384_SIZE, "ConstructSigningPublicKey() with P384 returned incorrect signingPublicKey length")
}

/*
func TestConstructSigningPublicKeyWithP521(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate([]byte{0x05, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 132)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P521 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P521_SIZE, "ConstructSigningPublicKey() with P521 returned incorrect signingPublicKey length")
}
*/ //TODO -> Before implementing this test, we need to implement P521 first.
