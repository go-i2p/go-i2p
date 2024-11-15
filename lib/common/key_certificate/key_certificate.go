// Package key_certificate implements the I2P Destination common data structure
package key_certificate

/*
I2P Key Certificate
https://geti2p.net/spec/common-structures#certificate
Accurate for version 0.9.24

+----+----+----+----+----+-//
|type| length  | payload
+----+----+----+----+----+-//

type :: Integer
        length -> 1 byte

        case 0 -> NULL
        case 1 -> HASHCASH
        case 2 -> HIDDEN
        case 3 -> SIGNED
        case 4 -> MULTIPLE
        case 5 -> KEY

length :: Integer
          length -> 2 bytes

payload :: data
           length -> $length bytes
*/

import (
	"errors"

	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/crypto"
)

var log = logger.GetGoI2PLogger()

// Key Certificate Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1 = iota
	KEYCERT_SIGN_P256
	KEYCERT_SIGN_P384
	KEYCERT_SIGN_P521
	KEYCERT_SIGN_RSA2048
	KEYCERT_SIGN_RSA3072
	KEYCERT_SIGN_RSA4096
	KEYCERT_SIGN_ED25519
	KEYCERT_SIGN_ED25519PH
)

// Key Certificate Public Key Types
const (
	KEYCERT_CRYPTO_ELG = iota
	KEYCERT_CRYPTO_P256
	KEYCERT_CRYPTO_P384
	KEYCERT_CRYPTO_P521
	KEYCERT_CRYPTO_X25519
)

const (
	KEYCERT_MIN_SIZE = 7
)

// signingPublicKey sizes for Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1_SIZE  = 128
	KEYCERT_SIGN_P256_SIZE      = 64
	KEYCERT_SIGN_P384_SIZE      = 96
	KEYCERT_SIGN_P521_SIZE      = 132
	KEYCERT_SIGN_RSA2048_SIZE   = 256
	KEYCERT_SIGN_RSA3072_SIZE   = 384
	KEYCERT_SIGN_RSA4096_SIZE   = 512
	KEYCERT_SIGN_ED25519_SIZE   = 32
	KEYCERT_SIGN_ED25519PH_SIZE = 32
)

// publicKey sizes for Public Key Types
const (
	KEYCERT_CRYPTO_ELG_SIZE    = 256
	KEYCERT_CRYPTO_P256_SIZE   = 64
	KEYCERT_CRYPTO_P384_SIZE   = 96
	KEYCERT_CRYPTO_P521_SIZE   = 132
	KEYCERT_CRYPTO_X25519_SIZE = 32
)

// Sizes of structures in KeyCertificates
const (
	KEYCERT_PUBKEY_SIZE = 256
	KEYCERT_SPK_SIZE    = 128
)

// type KeyCertificate []byte
type KeyCertificate struct {
	Certificate
	spkType Integer
	cpkType Integer
}

// Data returns the raw []byte contained in the Certificate.
func (key_certificate KeyCertificate) Data() ([]byte, error) {
	data := key_certificate.Certificate.RawBytes()
	log.WithFields(logrus.Fields{
		"data_length": len(data),
	}).Debug("Retrieved raw data from keyCertificate")
	return key_certificate.Certificate.RawBytes(), nil
}

// SigningPublicKeyType returns the signingPublicKey type as a Go integer.
func (key_certificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int) {
	signing_pubkey_type = key_certificate.spkType.Int()
	log.WithFields(logrus.Fields{
		"signing_pubkey_type": signing_pubkey_type,
	}).Debug("Retrieved signingPublicKey type")
	return key_certificate.spkType.Int()
}

// PublicKeyType returns the publicKey type as a Go integer.
func (key_certificate KeyCertificate) PublicKeyType() (pubkey_type int) {
	pubkey_type = key_certificate.cpkType.Int()
	log.WithFields(logrus.Fields{
		"pubkey_type": pubkey_type,
	}).Debug("Retrieved publicKey type")
	return key_certificate.cpkType.Int()
}

// ConstructPublicKey returns a publicKey constructed using any excess data that may be stored in the KeyCertififcate.
// Returns enr errors encountered while parsing.
func (key_certificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.PublicKey, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Constructing publicKey from keyCertificate")
	key_type := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < key_certificate.CryptoSize() {
		log.WithFields(logrus.Fields{
			"at":           "(keyCertificate) ConstructPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing public key")
		err = errors.New("error constructing public key: not enough data")
		return
	}
	switch key_type {
	case KEYCERT_CRYPTO_ELG:
		var elg_key crypto.ElgPublicKey
		copy(elg_key[:], data[KEYCERT_PUBKEY_SIZE-KEYCERT_CRYPTO_ELG_SIZE:KEYCERT_PUBKEY_SIZE])
		public_key = elg_key
		log.Debug("Constructed ElgPublicKey")
	case KEYCERT_CRYPTO_X25519:
		var ed25519_key crypto.Ed25519PublicKey
		copy(ed25519_key[:], data[KEYCERT_PUBKEY_SIZE-KEYCERT_CRYPTO_ELG_SIZE:KEYCERT_PUBKEY_SIZE])
		public_key = ed25519_key
		log.Debug("Constructed Ed25519PublicKey")
	default:
		log.WithFields(logrus.Fields{
			"key_type": key_type,
		}).Warn("Unknown public key type")
	}

	return
}

// ConstructSigningPublicKey returns a SingingPublicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
func (key_certificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Constructing signingPublicKey from keyCertificate")
	signing_key_type := key_certificate.SigningPublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < key_certificate.SignatureSize() {
		log.WithFields(logrus.Fields{
			"at":           "(keyCertificate) ConstructSigningPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing signing public key")
		err = errors.New("error constructing signing public key: not enough data")
		return
	}
	switch signing_key_type {
	case KEYCERT_SIGN_DSA_SHA1:
		var dsa_key crypto.DSAPublicKey
		copy(dsa_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_DSA_SHA1_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = dsa_key
		log.Debug("Constructed DSAPublicKey")
	case KEYCERT_SIGN_P256:
		var ec_key crypto.ECP256PublicKey
		copy(ec_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P256_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_key
		log.Debug("Constructed ECP256PublicKey")
	case KEYCERT_SIGN_P384:
		var ec_key crypto.ECP384PublicKey
		copy(ec_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P384_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_key
		log.Debug("Constructed ECP384PublicKey")
	case KEYCERT_SIGN_P521:
		var ec_key crypto.ECP521PublicKey
		extra := KEYCERT_SIGN_P521_SIZE - KEYCERT_SPK_SIZE
		copy(ec_key[:], data)
		copy(ec_key[KEYCERT_SPK_SIZE:], key_certificate.Certificate.RawBytes()[4:4+extra])
		signing_public_key = ec_key
		log.Debug("Constructed ECP521PublicKey")
	case KEYCERT_SIGN_RSA2048:
		var rsa2048_key crypto.RSA2048PublicKey
		extra := KEYCERT_SIGN_RSA2048_SIZE - 128
		copy(rsa2048_key[:], data)
		copy(rsa2048_key[128:], key_certificate.Certificate.RawBytes()[4:4+extra])
		signing_public_key = rsa2048_key
	case KEYCERT_SIGN_RSA3072:
		var rsa3072_key crypto.RSA3072PublicKey
		extra := KEYCERT_SIGN_RSA3072_SIZE - 128
		copy(rsa3072_key[:], data)
		copy(rsa3072_key[128:], key_certificate.Certificate.RawBytes()[4:4+extra])
		signing_public_key = rsa3072_key
	case KEYCERT_SIGN_RSA4096:
		var rsa4096_key crypto.RSA4096PublicKey
		extra := KEYCERT_SIGN_RSA4096_SIZE - 128
		copy(rsa4096_key[:], data)
		copy(rsa4096_key[128:], key_certificate.Certificate.RawBytes()[4:4+extra])
		signing_public_key = rsa4096_key
	case KEYCERT_SIGN_ED25519:
		var ed25519_key crypto.Ed25519PublicKey
		extra := KEYCERT_SIGN_ED25519_SIZE - 128
		copy(ed25519_key[:], data)
		copy(ed25519_key[32:], key_certificate.Certificate.RawBytes()[4:4+extra])
		signing_public_key = ed25519_key
	case KEYCERT_SIGN_ED25519PH:
		var ed25519ph_key crypto.Ed25519PublicKey
		extra := KEYCERT_SIGN_ED25519PH_SIZE - 128
		copy(ed25519ph_key[:], data)
		copy(ed25519ph_key[128:], key_certificate.Certificate.RawBytes()[4:4+extra])
		signing_public_key = ed25519ph_key
	default:
		log.WithFields(logrus.Fields{
			"signing_key_type": signing_key_type,
		}).Warn("Unknown signing key type")
		panic(err)
	}

	return
}

// SignatureSize return the size of a Signature corresponding to the Key Certificate's signingPublicKey type.
func (key_certificate KeyCertificate) SignatureSize() (size int) {
	sizes := map[int]int{
		KEYCERT_SIGN_DSA_SHA1:  KEYCERT_SIGN_DSA_SHA1_SIZE,
		KEYCERT_SIGN_P256:      KEYCERT_SIGN_P256_SIZE,
		KEYCERT_SIGN_P384:      KEYCERT_SIGN_P384_SIZE,
		KEYCERT_SIGN_P521:      KEYCERT_SIGN_P521_SIZE,
		KEYCERT_SIGN_RSA2048:   KEYCERT_SIGN_RSA2048_SIZE,
		KEYCERT_SIGN_RSA3072:   KEYCERT_SIGN_RSA3072_SIZE,
		KEYCERT_SIGN_RSA4096:   KEYCERT_SIGN_RSA4096_SIZE,
		KEYCERT_SIGN_ED25519:   KEYCERT_SIGN_ED25519_SIZE,
		KEYCERT_SIGN_ED25519PH: KEYCERT_SIGN_ED25519PH_SIZE,
	}
	key_type := key_certificate.SigningPublicKeyType()
	size = sizes[int(key_type)]
	log.WithFields(logrus.Fields{
		"key_type":       key_type,
		"signature_size": size,
	}).Debug("Retrieved signature size")
	return sizes[int(key_type)]
}

// CryptoSize return the size of a Public Key corresponding to the Key Certificate's publicKey type.
func (key_certificate KeyCertificate) CryptoSize() (size int) {
	sizes := map[int]int{
		KEYCERT_CRYPTO_ELG:    KEYCERT_CRYPTO_ELG_SIZE,
		KEYCERT_CRYPTO_P256:   KEYCERT_CRYPTO_P256_SIZE,
		KEYCERT_CRYPTO_P384:   KEYCERT_CRYPTO_P384_SIZE,
		KEYCERT_CRYPTO_P521:   KEYCERT_CRYPTO_P521_SIZE,
		KEYCERT_CRYPTO_X25519: KEYCERT_CRYPTO_X25519_SIZE,
	}
	key_type := key_certificate.PublicKeyType()
	size = sizes[int(key_type)]
	log.WithFields(logrus.Fields{
		"key_type":    key_type,
		"crypto_size": size,
	}).Debug("Retrieved crypto size")
	return sizes[int(key_type)]
}

// NewKeyCertificate creates a new *KeyCertificate from []byte using ReadCertificate.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func NewKeyCertificate(bytes []byte) (key_certificate *KeyCertificate, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(bytes),
	}).Debug("Creating new keyCertificate")

	var certificate Certificate
	certificate, remainder, err = ReadCertificate(bytes)
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate")
		return
	}
	if len(bytes) < KEYCERT_MIN_SIZE {
		log.WithError(err).Error("keyCertificate data too short")
		err = errors.New("error parsing key certificate: not enough data")
		remainder = bytes[KEYCERT_MIN_SIZE:]
	}
	key_certificate = &KeyCertificate{
		Certificate: certificate,
	}
	if len(bytes) >= 5 {
		key_certificate.spkType = Integer(bytes[4:5])
	}
	if len(bytes) >= 7 {
		key_certificate.cpkType = Integer(bytes[6:7])
	}

	log.WithFields(logrus.Fields{
		"spk_type":         key_certificate.spkType.Int(),
		"cpk_type":         key_certificate.cpkType.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new keyCertificate")

	return
}

// KeyCertificateFromCertificate returns a *KeyCertificate from a *Certificate.
func KeyCertificateFromCertificate(certificate Certificate) *KeyCertificate {
	log.Debug("Creating keyCertificate from Certificate")
	// k, _, _ := NewKeyCertificate(certificate.RawBytes())
	k, _, err := NewKeyCertificate(certificate.RawBytes())
	if err != nil {
		log.WithError(err).Error("Failed to create keyCertificate from Certificate")
	} else {
		log.Debug("Successfully created keyCertificate from Certificate")
	}
	return k
}
