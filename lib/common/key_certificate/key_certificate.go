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

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/crypto"
	log "github.com/sirupsen/logrus"
)

// KEYCERT_MIN_SIZE is the minimum size of a Key Certificate
const KEYCERT_MIN_SIZE = 7

// Signing Public Key Types
const (
	KEYCERT_SIGN_PUBKEY_DSA_SHA1 = iota
	KEYCERT_SIGN_PUBKEY_P256
	KEYCERT_SIGN_PUBKEY_P384
	KEYCERT_SIGN_PUBKEY_P521
	KEYCERT_SIGN_PUBKEY_RSA2048
	KEYCERT_SIGN_PUBKEY_RSA3072
	KEYCERT_SIGN_PUBKEY_RSA4096
	KEYCERT_SIGN_PUBKEY_ED25519
	KEYCERT_SIGN_PUBKEY_ED25519PH
)

// Crypto Public Key Types
const (
	KEYCERT_CRYPTO_PUBKEY_ELGAMAL = iota
	KEYCERT_CRYPTO_PUBKEY_P256
	KEYCERT_CRYPTO_PUBKEY_P384
	KEYCERT_CRYPTO_PUBKEY_P521
	KEYCERT_CRYPTO_PUBKEY_X25519
)

// Signing Public Key sizes in bytes for Signing Public Key Types
const (
	KEYCERT_SIGN_PUBKEY_DSA_SHA1_SIZE  = 128
	KEYCERT_SIGN_PUBKEY_P256_SIZE      = 64
	KEYCERT_SIGN_PUBKEY_P384_SIZE      = 96
	KEYCERT_SIGN_PUBKEY_P521_SIZE      = 132
	KEYCERT_SIGN_PUBKEY_RSA2048_SIZE   = 256
	KEYCERT_SIGN_PUBKEY_RSA3072_SIZE   = 384
	KEYCERT_SIGN_PUBKEY_RSA4096_SIZE   = 512
	KEYCERT_SIGN_PUBKEY_ED25519_SIZE   = 32
	KEYCERT_SIGN_PUBKEY_ED25519PH_SIZE = 32
)

// Crypto Public Key sizes in bytes for Crypto Public Key Types
const (
	KEYCERT_CRYPTO_PUBKEY_ELGAMAL_SIZE = 256
	KEYCERT_CRYPTO_PUBKEY_P256_SIZE    = 64
	KEYCERT_CRYPTO_PUBKEY_P384_SIZE    = 96
	KEYCERT_CRYPTO_PUBKEY_P521_SIZE    = 132
	KEYCERT_CRYPTO_PUBKEY_X25519_SIZE  = 32
)

// type KeyCertificate []byte
type KeyCertificate struct {
	*Certificate
	signingPubKeyType Integer
	cryptoPubKeyType  Integer
}

// Data returns the raw []byte contained in the Certificate.
func (key_certificate KeyCertificate) Data() ([]byte, error) {
	return key_certificate.Certificate.RawBytes(), nil
}

// SigningPublicKeyType returns the SigningPublicKey type as a Go integer.
func (key_certificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int) {
	return key_certificate.signingPubKeyType.Int()
}

// PublicKeyType returns the PublicKey type as a Go integer.
func (key_certificate KeyCertificate) PublicKeyType() (pubkey_type int) {
	return key_certificate.cryptoPubKeyType.Int()
}

// ConstructPublicKey returns a PublicKey constructed using any excess data that may be stored in the KeyCertififcate.
// Returns enr errors encountered while parsing.
func (key_certificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.PublicKey, err error) {
	keyType := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	cryptoPubKeyLength := key_certificate.CryptoPublicKeySize()
	if data_len < cryptoPubKeyLength {
		log.WithFields(log.Fields{
			"at":               "(KeyCertificate) ConstructPublicKey",
			"data_len":         data_len,
			"specified_length": cryptoPubKeyLength,
			"reason":           "not enough data",
		}).Error("error constructing public key")
		err = errors.New("error constructing public key: not enough data")
		return
	}
	switch keyType {
	case KEYCERT_CRYPTO_PUBKEY_ELGAMAL:
		var elg_key crypto.ElgPublicKey
		copy(elg_key[:], data[:cryptoPubKeyLength])
		public_key = elg_key
	case KEYCERT_CRYPTO_PUBKEY_P256:
		panic("KEYCERT_CRYPTO_PUBKEY_P256 Not implemented")
	case KEYCERT_CRYPTO_PUBKEY_P384:
		panic("KEYCERT_CRYPTO_PUBKEY_P384 Not implemented")
	case KEYCERT_CRYPTO_PUBKEY_P521:
		panic("KEYCERT_CRYPTO_PUBKEY_P521 Not implemented")
	case KEYCERT_CRYPTO_PUBKEY_X25519:
		panic("KEYCERT_CRYPTO_PUBKEY_X25519 Not implemented")
	}
	return
}

// ConstructSigningPublicKey returns a SingingPublicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
func (key_certificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey, err error) {
	signing_key_type := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	signingPublicKeySize := key_certificate.SigningPublicKeySize()
	data_len := len(data)
	if data_len < signingPublicKeySize {
		log.WithFields(log.Fields{
			"at":           "(KeyCertificate) ConstructSigningPublicKey",
			"data_len":     data_len,
			"required_len": signingPublicKeySize,
			"reason":       "not enough data",
		}).Error("error constructing signing public key")
		err = errors.New("error constructing signing public key: not enough data")
		return
	}
	switch signing_key_type {
	case KEYCERT_SIGN_PUBKEY_DSA_SHA1:
		var dsa_key crypto.DSAPublicKey
		copy(dsa_key[:], data[:signingPublicKeySize])
		signing_public_key = dsa_key
	case KEYCERT_SIGN_PUBKEY_P256:
		var ec_key crypto.ECP256PublicKey
		copy(ec_key[:], data[:signingPublicKeySize])
		signing_public_key = ec_key
	case KEYCERT_SIGN_PUBKEY_P384:
		var ec_key crypto.ECP384PublicKey
		copy(ec_key[:], data[:signingPublicKeySize])
		signing_public_key = ec_key
	case KEYCERT_SIGN_PUBKEY_P521:
		// Build the entire pubkey using the bytes available in the PublicKey + 4 excess bytes from the certificate
		var fullCertData []byte
		fullCertData = append(fullCertData, data[:signingPublicKeySize]...)
		fullCertData = append(fullCertData, key_certificate.Certificate.RawBytes()[:4]...)
		var ec_key crypto.ECP521PublicKey
		copy(ec_key[:], fullCertData)
		signing_public_key = ec_key
	case KEYCERT_SIGN_PUBKEY_RSA2048:
		//var rsa_key crypto.RSA2048PublicKey
		//extra := KEYCERT_SIGN_RSA2048_SIZE - 128
		//copy(rsa_key[:], data)
		//copy(rsa_key[128:], key_certificate[4:4+extra])
		//signing_public_key = rsa_key
	case KEYCERT_SIGN_PUBKEY_RSA3072:
		panic("KEYCERT_SIGN_PUBKEY_RSA3072 not implemented")
	case KEYCERT_SIGN_PUBKEY_RSA4096:
		panic("KEYCERT_SIGN_PUBKEY_RSA4096 not implemented")
	case KEYCERT_SIGN_PUBKEY_ED25519:
		panic("KEYCERT_SIGN_PUBKEY_ED25519 not implemented")
	case KEYCERT_SIGN_PUBKEY_ED25519PH:
		panic("KEYCERT_SIGN_PUBKEY_ED25519PH not implemented")
	}
	return
}

// SignatureSize return the size of a Signature corresponding to the Key Certificate's SigningPublicKey type.
func (key_certificate KeyCertificate) SignatureSize() (size int) {
	sizes := map[int]int{
		KEYCERT_SIGN_PUBKEY_DSA_SHA1:  40,
		KEYCERT_SIGN_PUBKEY_P256:      64,
		KEYCERT_SIGN_PUBKEY_P384:      96,
		KEYCERT_SIGN_PUBKEY_P521:      132,
		KEYCERT_SIGN_PUBKEY_RSA2048:   256,
		KEYCERT_SIGN_PUBKEY_RSA3072:   384,
		KEYCERT_SIGN_PUBKEY_RSA4096:   512,
		KEYCERT_SIGN_PUBKEY_ED25519:   64,
		KEYCERT_SIGN_PUBKEY_ED25519PH: 64,
	}
	key_type := key_certificate.SigningPublicKeyType()
	return sizes[int(key_type)]
}

// SigningPublicKeySize return the size of a Signing Public Key in bytes corresponding to the Key Certificate's SigningPublicKey type.
func (key_certificate KeyCertificate) SigningPublicKeySize() (size int) {
	sizes := map[int]int{
		KEYCERT_SIGN_PUBKEY_DSA_SHA1:  KEYCERT_SIGN_PUBKEY_DSA_SHA1_SIZE,
		KEYCERT_SIGN_PUBKEY_P256:      KEYCERT_SIGN_PUBKEY_P256_SIZE,
		KEYCERT_SIGN_PUBKEY_P384:      KEYCERT_SIGN_PUBKEY_P384_SIZE,
		KEYCERT_SIGN_PUBKEY_P521:      KEYCERT_SIGN_PUBKEY_P521_SIZE,
		KEYCERT_SIGN_PUBKEY_RSA2048:   KEYCERT_SIGN_PUBKEY_RSA2048_SIZE,
		KEYCERT_SIGN_PUBKEY_RSA3072:   KEYCERT_SIGN_PUBKEY_RSA3072_SIZE,
		KEYCERT_SIGN_PUBKEY_RSA4096:   KEYCERT_SIGN_PUBKEY_RSA4096_SIZE,
		KEYCERT_SIGN_PUBKEY_ED25519:   KEYCERT_SIGN_PUBKEY_ED25519_SIZE,
		KEYCERT_SIGN_PUBKEY_ED25519PH: KEYCERT_SIGN_PUBKEY_ED25519PH_SIZE,
	}
	key_type := key_certificate.SigningPublicKeyType()
	return sizes[int(key_type)]
}

// PublicKeySize returns the size of the Public Key in bytes corresponding to the Key Certificate's CyrptoPublicKey type.
func (key_certificate KeyCertificate) CryptoPublicKeySize() int {
	sizes := map[int]int{
		KEYCERT_CRYPTO_PUBKEY_ELGAMAL: KEYCERT_CRYPTO_PUBKEY_ELGAMAL_SIZE,
		KEYCERT_CRYPTO_PUBKEY_P256:    KEYCERT_CRYPTO_PUBKEY_P256_SIZE,
		KEYCERT_CRYPTO_PUBKEY_P384:    KEYCERT_CRYPTO_PUBKEY_P384_SIZE,
		KEYCERT_CRYPTO_PUBKEY_P521:    KEYCERT_CRYPTO_PUBKEY_P521_SIZE,
		KEYCERT_CRYPTO_PUBKEY_X25519:  KEYCERT_CRYPTO_PUBKEY_X25519_SIZE,
	}
	keyType := key_certificate.PublicKeyType()
	return sizes[keyType]
}

// NewKeyCertificate creates a new *KeyCertificate from []byte using ReadCertificate.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func NewKeyCertificate(bytes []byte) (key_certificate *KeyCertificate, remainder []byte, err error) {
	var certificate *Certificate
	certificate, remainder, err = ReadCertificate(bytes)
	//if err != nil {
	//	return nil, err
	//}
	if len(bytes) < KEYCERT_MIN_SIZE {
		err = errors.New("error parsing key certificate: not enough data")
	}
	switch len(bytes) {
	case 4:
		key_certificate = &KeyCertificate{
			Certificate:       certificate,
			signingPubKeyType: Integer(bytes[4:]),
			cryptoPubKeyType:  Integer([]byte{0}),
		}
		remainder = []byte{}
	case 5:
		key_certificate = &KeyCertificate{
			Certificate:       certificate,
			signingPubKeyType: Integer(bytes[4:5]),
			cryptoPubKeyType:  Integer([]byte{0}),
		}
		remainder = []byte{}
	case 6:
		key_certificate = &KeyCertificate{
			Certificate:       certificate,
			signingPubKeyType: Integer(bytes[4:5]),
			cryptoPubKeyType:  Integer(bytes[6:]),
		}
		remainder = []byte{}
	default:
		key_certificate = &KeyCertificate{
			Certificate:       certificate,
			signingPubKeyType: Integer(bytes[4:5]),
			cryptoPubKeyType:  Integer(bytes[6:7]),
		}
		remainder = bytes[7:]
	}

	//key_certificate.PublicKey = NewPublicKey(bytes)
	return
}

// KeyCertificateFromCertificate returns a *KeyCertificate from a *Certificate.
func KeyCertificateFromCertificate(certificate *Certificate) *KeyCertificate {
	k, _, _ := NewKeyCertificate(certificate.RawBytes())
	return k
}
