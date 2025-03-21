package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadSignatureErrors(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe, 0xef}
	unsupportedSigType := 1000
	_, _, err := ReadSignature(data, unsupportedSigType)
	assert.NotNil(err, "unsupported signature error should be reported")

	sigType := SIGNATURE_TYPE_DSA_SHA1
	_, _, err = ReadSignature(data, sigType)
	assert.NotNil(err, "insufficient data error should be reported")
}

func TestReadSignature(t *testing.T) {
	assert := assert.New(t)

	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1, SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_ECDSA_SHA384_P384, SIGNATURE_TYPE_ECDSA_SHA512_P521,
		SIGNATURE_TYPE_RSA_SHA256_2048, SIGNATURE_TYPE_RSA_SHA384_3072,
		SIGNATURE_TYPE_RSA_SHA512_4096, SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}
	sigLengths := []int{
		DSA_SHA1_SIZE, EdDSA_SHA512_Ed25519_SIZE,
		ECDSA_SHA384_P384_SIZE, ECDSA_SHA512_P512_SIZE,
		RSA_SHA256_2048_SIZE, RSA_SHA384_3072_SIZE,
		RSA_SHA512_4096_SIZE, EdDSA_SHA512_Ed25519_SIZE,
		EdDSA_SHA512_Ed25519ph_SIZE, RedDSA_SHA512_Ed25519_SIZE,
	}

	dataLen := 1024
	data := []byte{}
	for i := 0; i < dataLen; i++ {
		data = append(data, byte(i%10))
	}

	for i, sigType := range sigTypes {
		sig, rem, err := ReadSignature(data, sigType)
		assert.Nil(err, "no errors should be returned")
		assert.Equal(sig, Signature(data[:sigLengths[i]]), "signature should be sliced from data")
		assert.Equal(rem, data[sigLengths[i]:], "remainder should be sliced from data ")
	}
}

func TestNewSignatureError(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe, 0xef}
	unsupportedSigType := 1000
	_, _, err := NewSignature(data, unsupportedSigType)
	assert.NotNil(err, "NewSignature error should be reported")
}

func TestNewSignature(t *testing.T) {
	assert := assert.New(t)

	data := []byte{}
	sigLength := EdDSA_SHA512_Ed25519_SIZE
	remLength := 20
	for i := 0; i < sigLength+remLength; i++ {
		data = append(data, byte(i%10))
	}
	sigType := SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	sig, rem, err := NewSignature(data, sigType)
	assert.Nil(err, "no errors should be returned")
	assert.Equal(*sig, Signature(data[:sigLength]), "signature should be sliced from data")
	assert.Equal(rem, data[sigLength:], "remainder should be sliced from data ")
}
