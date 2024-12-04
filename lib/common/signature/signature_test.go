package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestReadSignatureErrors(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe,0xef}
	unsupportedSigType := 1000
	_, _, err := ReadSignature(data, unsupportedSigType)
	assert.NotNil(err, "unsupported signature error should be reported")

	sigType := SIGNATURE_TYPE_DSA_SHA1
	_, _, err = ReadSignature(data, sigType)
	assert.NotNil(err, "insufficient data error should be reported")
}

func TestReadSignature(t *testing.T) {
	assert := assert.New(t)

	sigTypes := []int{SIGNATURE_TYPE_DSA_SHA1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519}
	sigLengths := []int{DSA_SHA1_SIZE, EdDSA_SHA512_Ed25519_SIZE}

	data := []byte{}
	for i := 0; i < EdDSA_SHA512_Ed25519_SIZE; i++ {
		data = append(data, byte(i % 10))
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

	data := []byte{0xbe,0xef}
	unsupportedSigType := 1000
	_, _, err := NewSignature(data, unsupportedSigType)
	assert.NotNil(err, "NewSignature error should be reported")
}

func TestNewSignature(t *testing.T) {
	assert := assert.New(t)

	data := []byte{}
	sigLength := EdDSA_SHA512_Ed25519_SIZE
	remLength := 20
	for i := 0; i < sigLength + remLength; i++ {
		data = append(data, byte(i % 10))
	}
	sigType := SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	sig, rem, err := NewSignature(data, sigType)
	assert.Nil(err, "no errors should be returned")
	assert.Equal(*sig, Signature(data[:sigLength]), "signature should be sliced from data")
	assert.Equal(rem, data[sigLength:], "remainder should be sliced from data ")
}
