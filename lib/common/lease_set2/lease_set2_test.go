package lease_set2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/go-i2p/go-i2p/lib/common/lease_set2_header"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/destination"
	"github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	"github.com/go-i2p/go-i2p/lib/common/lease2"
	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp/elgamal"
)

// createTestDestination creates a minimal Destination with Ed25519 and ElGamal keys.
func createTestDestination(t *testing.T) (destination.Destination, crypto.SigningPrivateKey) {
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
	cryptoPublicKeyType, err := NewIntegerFromInt(key_certificate.KEYCERT_CRYPTO_ELG, 2)
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}
	signingPublicKeyType, err := NewIntegerFromInt(key_certificate.KEYCERT_SIGN_ED25519, 2)
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}
	payload.Write(*cryptoPublicKeyType)
	payload.Write(*signingPublicKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	keyCert, err := key_certificate.KeyCertificateFromCertificate(*cert)
	if err != nil {
		t.Fatalf("KeyCertificateFromCertificate failed: %v\n", err)
	}

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SignatureSize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (pubKeySize + sigKeySize)
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}

	kac, err := keys_and_cert.NewKeysAndCert(keyCert, elg_pubkey, padding, ed25519_pubkey)
	if err != nil {
		t.Fatalf("Failed to create KeysAndCert: %v", err)
	}

	dest := destination.Destination{KeysAndCert: *kac}
	return dest, &ed25519_privkey
}

func TestReadLeaseSet2Empty(t *testing.T) {
	// Not enough data
	_, _, err := ReadLeaseSet2([]byte{})
	assert.NotNil(t, err)
}
func mustToI2PString(s string) I2PString {
	str, err := ToI2PString(s)
	if err != nil {
		panic(err)
	}
	return str
}
func TestNewAndReadLeaseSet2(t *testing.T) {
	assert := assert.New(t)

	dest, signingPriv := createTestDestination(t)

	header := lease_set2_header.ParsedLeaseSet2Header{
		Destination: dest,
		Published:   123456,
		Expires:     3600,
		Flags:       0,
	}

	encryptionKeyData := make([]byte, 256)
	_, err := rand.Read(encryptionKeyData)
	assert.Nil(err)
	encKeys := []EncryptionKeyEntry{
		{
			KeyType: key_certificate.KEYCERT_CRYPTO_ELG,
			KeyLen:  256,
			KeyData: encryptionKeyData,
		},
	}

	var lease lease2.Lease2
	copy(lease[:32], []byte("example_gatewayhash_32_bytes___"))
	binary.BigEndian.PutUint32(lease[32:36], 9999) // TunnelID
	binary.BigEndian.PutUint32(lease[36:40], uint32(time.Now().Unix()))

	leases := []lease2.Lease2{lease}

	options := map[string]string{
		"foo": "bar",
	}
	ls2, err := NewLeaseSet2(header, options, encKeys, leases, signingPriv, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.Nil(err)
	assert.NotEmpty(ls2)

	parsed, remainder, err := ReadLeaseSet2(ls2)
	assert.Nil(err)
	assert.Empty(remainder)

	assert.Equal(header.Published, parsed.Header.Published)
	assert.Equal(header.Expires, parsed.Header.Expires)
	assert.Equal(header.Flags, parsed.Header.Flags)
	assert.Equal(dest.Bytes(), parsed.Destination.Bytes())

	val := parsed.Options.Values().Get(mustToI2PString("foo"))
	vdata, _ := val.Data()
	assert.Equal("bar", vdata)

	assert.Equal(1, len(parsed.EncryptionKeys))
	assert.Equal(256, int(parsed.EncryptionKeys[0].KeyLen))
	assert.Equal(len(encryptionKeyData), len(parsed.EncryptionKeys[0].KeyData))
	assert.Equal(1, len(parsed.Leases))
	assert.Equal(64, len(parsed.Signature))

	// Mock verify
	mockVerify := func(data, sig []byte) error {
		if len(sig) != 64 {
			return errors.New("invalid sig length")
		}
		return nil
	}
	err = parsed.VerifyLeaseSet2(mockVerify)
	assert.Nil(err)
}
