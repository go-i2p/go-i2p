package keys_and_cert

import (
	"bytes"
	"crypto/rand"
	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"golang.org/x/crypto/openpgp/elgamal"
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
func TestCertificateWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	data := make([]byte, 128+256)
	data = append(data, cert_data...)
	_, _, err := NewKeysAndCert(data)
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
}

*/

// createValidKeyCertificate creates a valid KeyCertificate for testing.
func createValidKeyAndCert(t *testing.T) *KeysAndCert {
	// Generate signing key pair (Ed25519)
	var ed25519_privkey crypto.Ed25519PrivateKey
	_, err := (&ed25519_privkey).Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	ed25519_pubkey, ok := ed25519_pubkey_raw.(crypto.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate encryption key pair (ElGamal)
	var elgamal_privkey elgamal.PrivateKey
	err = crypto.ElgamalGenerate(&elgamal_privkey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}

	// Convert elgamal public key to crypto.ElgPublicKey
	var elg_pubkey crypto.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	// Create KeyCertificate specifying key types
	var payload bytes.Buffer
	signingPublicKeyType, _ := data.NewIntegerFromInt(key_certificate.KEYCERT_SIGN_ED25519, 2)
	cryptoPublicKeyType, _ := data.NewIntegerFromInt(key_certificate.KEYCERT_CRYPTO_ELG, 2)
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	// Create certificate
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create certificate: %v\n", err)
	}

	keyCert := key_certificate.KeyCertificateFromCertificate(*cert)
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SignatureSize()
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	// Generate random padding
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatal(err)
	}

	keysAndCert, err := NewKeysAndCert(keyCert, elg_pubkey, padding, ed25519_pubkey)
	if err != nil {
		t.Fatal(err)
	}

	return keysAndCert
}

func TestCertificateWithValidDataDeux(t *testing.T) {
	assert := assert.New(t)
	keysAndCert := createValidKeyAndCert(t)

	// Serialize KeysAndCert to bytes
	serialized := keysAndCert.Bytes()

	// Deserialize KeysAndCert from bytes
	parsedKeysAndCert, remainder, err := ReadKeysAndCert(serialized)
	assert.Nil(err, "ReadKeysAndCert should not error with valid data")
	assert.Empty(remainder, "There should be no remainder after parsing KeysAndCert")

	// Compare individual fields
	assert.Equal(keysAndCert.keyCertificate.Bytes(), parsedKeysAndCert.keyCertificate.Bytes(), "KeyCertificates should match")
	assert.Equal(keysAndCert.publicKey.Bytes(), parsedKeysAndCert.publicKey.Bytes(), "PublicKeys should match")
	assert.Equal(keysAndCert.Padding, parsedKeysAndCert.Padding, "Padding should match")
	assert.Equal(keysAndCert.signingPublicKey.Bytes(), parsedKeysAndCert.signingPublicKey.Bytes(), "SigningPublicKeys should match")
}
func TestCertificateWithValidDataManual(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	data := make([]byte, 128+256)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)
	assert.Nil(err)

	cert := keys_and_cert.Certificate()

	cert_bytes := cert.Bytes()
	if assert.Equal(len(cert_data), len(cert_bytes)) {
		assert.Equal(cert_bytes, cert_data, "keys_and_cert.Certificate() did not return correct data with valid cert")
	}
}

func TestPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 193)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	pub_key := keys_and_cert.PublicKey()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
	assert.Nil(pub_key)
}

func TestPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)
	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	if assert.NotNil(err) {
		log.WithError(err).Debug("Correctly got error")
	}
	pub_key := keys_and_cert.PublicKey()
	assert.Nil(pub_key)
}

func TestPublicKeyWithNullCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x00, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	pub_key := keys_and_cert.PublicKey()
	assert.Nil(err)
	assert.Equal(len(pub_key_data), pub_key.Len())
}

func TestPublicKeyWithKeyCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	pub_key := keys_and_cert.PublicKey()
	assert.Nil(err)
	assert.Equal(len(pub_key_data), pub_key.Len())
}

func TestSigningPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 93)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	signing_pub_key := keys_and_cert.SigningPublicKey()
	assert.NotNil(err)
	assert.Nil(signing_pub_key)
}

func TestSigningPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)
	signing_pub_key := keys_and_cert.SigningPublicKey()
	assert.NotNil(err)
	assert.Nil(signing_pub_key)
}

func TestSigningPublicKeyWithNullCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x00, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	signing_pub_key_data := make([]byte, 128)
	data := append(pub_key_data, signing_pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	signing_pub_key := keys_and_cert.SigningPublicKey()
	assert.Nil(err)
	assert.Equal(len(signing_pub_key_data), signing_pub_key.Len())
}

func TestSigningPublicKeyWithKeyCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	signing_pub_key_data := make([]byte, 128)
	data := append(pub_key_data, signing_pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	signing_pub_key := keys_and_cert.SigningPublicKey()
	assert.Nil(err)
	assert.Equal(len(signing_pub_key_data), signing_pub_key.Len())
}

func TestNewKeysAndCertWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
}

func TestNewKeysAndCertWithMissingCertData(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
}

func TestNewKeysAndCertWithValidDataWithCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	assert.Nil(err)
}

func TestNewKeysAndCertWithValidDataWithoutCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x00, 0x00, 0x00}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	assert.Nil(err)
}

func TestNewKeysAndCertWithValidDataWithCertificateAndRemainder(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x41}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	if assert.Equal(1, len(remainder)) {
		assert.Equal("A", string(remainder[0]))
	}
	assert.Nil(err)
}

func TestNewKeysAndCertWithValidDataWithoutCertificateAndRemainder(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x00, 0x00, 0x00, 0x41}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	if assert.Equal(1, len(remainder)) {
		assert.Equal("A", string(remainder[0]))
	}
	assert.Nil(err)
}
