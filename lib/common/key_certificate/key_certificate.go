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
	"fmt"

	"github.com/go-i2p/go-i2p/lib/common/signature"
	"github.com/go-i2p/go-i2p/lib/crypto/dsa"
	"github.com/go-i2p/go-i2p/lib/crypto/ecdsa"
	"github.com/go-i2p/go-i2p/lib/crypto/ed25519"
	elgamal "github.com/go-i2p/go-i2p/lib/crypto/elg"
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/data"
)

var log = logger.GetGoI2PLogger()

// Key Certificate Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1  = 0
	KEYCERT_SIGN_P256      = 1
	KEYCERT_SIGN_P384      = 2
	KEYCERT_SIGN_P521      = 3
	KEYCERT_SIGN_RSA2048   = 4
	KEYCERT_SIGN_RSA3072   = 5
	KEYCERT_SIGN_RSA4096   = 6
	KEYCERT_SIGN_ED25519   = 7
	KEYCERT_SIGN_ED25519PH = 8
)

// Key Certificate Public Key Types
const (
	KEYCERT_CRYPTO_ELG    = 0
	KEYCERT_CRYPTO_P256   = 1
	KEYCERT_CRYPTO_P384   = 2
	KEYCERT_CRYPTO_P521   = 3
	KEYCERT_CRYPTO_X25519 = 4
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
	SpkType Integer
	CpkType Integer
}

// Data returns the raw []byte contained in the Certificate.
func (keyCertificate KeyCertificate) Data() ([]byte, error) {
	data := keyCertificate.Certificate.RawBytes()
	log.WithFields(logrus.Fields{
		"data_length": len(data),
	}).Debug("Retrieved raw data from keyCertificate")
	return keyCertificate.Certificate.RawBytes(), nil
}

// SigningPublicKeyType returns the signingPublicKey type as a Go integer.
func (keyCertificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int) {
	signing_pubkey_type = keyCertificate.SpkType.Int()
	log.WithFields(logrus.Fields{
		"signing_pubkey_type": signing_pubkey_type,
	}).Debug("Retrieved signingPublicKey type")
	return keyCertificate.SpkType.Int()
}

// PublicKeyType returns the publicKey type as a Go integer.
func (keyCertificate KeyCertificate) PublicKeyType() (pubkey_type int) {
	pubkey_type = keyCertificate.CpkType.Int()
	log.WithFields(logrus.Fields{
		"pubkey_type": pubkey_type,
	}).Debug("Retrieved publicKey type")
	return keyCertificate.CpkType.Int()
}

// ConstructPublicKey returns a publicKey constructed using any excess data that may be stored in the KeyCertififcate.
// Returns enr errors encountered while parsing.
func (keyCertificate KeyCertificate) ConstructPublicKey(data []byte) (public_key types.RecievingPublicKey, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Constructing publicKey from keyCertificate")
	key_type := keyCertificate.PublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < keyCertificate.CryptoSize() {
		log.WithFields(logrus.Fields{
			"at":           "(keyCertificate) ConstructPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing public key")
		err = oops.Errorf("error constructing public key: not enough data")
		return
	}
	switch key_type {
	case KEYCERT_CRYPTO_ELG:
		var elg_key elgamal.ElgPublicKey
		copy(elg_key[:], data[KEYCERT_PUBKEY_SIZE-KEYCERT_CRYPTO_ELG_SIZE:KEYCERT_PUBKEY_SIZE])
		public_key = elg_key
		log.Debug("Constructed ElgPublicKey")
	case KEYCERT_CRYPTO_X25519:
		var ed25519_key ed25519.Ed25519PublicKey
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

const (
	CRYPTO_KEY_TYPE_ELGAMAL = 0 // ElGamal

	// Signature Types
	SIGNATURE_TYPE_DSA_SHA1       = 0 // DSA-SHA1
	SIGNATURE_TYPE_ED25519_SHA512 = 7 // Ed25519
)

var CryptoPublicKeySizes = map[uint16]int{
	CRYPTO_KEY_TYPE_ELGAMAL: 256,
}

var SignaturePublicKeySizes = map[uint16]int{
	SIGNATURE_TYPE_DSA_SHA1:       128,
	SIGNATURE_TYPE_ED25519_SHA512: 32,
}

func (keyCertificate *KeyCertificate) CryptoPublicKeySize() (int, error) {
	size, exists := CryptoPublicKeySizes[uint16(keyCertificate.CpkType.Int())]
	if !exists {
		return 0, oops.Errorf("unknown crypto key type: %d", keyCertificate.CpkType.Int())
	}
	return size, nil
}

func (keyCertificate *KeyCertificate) SigningPublicKeySize() int {
	spk_type := keyCertificate.SpkType
	switch spk_type.Int() {
	case SIGNATURE_TYPE_DSA_SHA1:
		log.Debug("Returning DSA_SHA1")
		return 128
	case signature.SIGNATURE_TYPE_ECDSA_SHA256_P256:
		log.Debug("Returning ECDSA_SHA256_P256")
		return 64
	case signature.SIGNATURE_TYPE_ECDSA_SHA384_P384:
		return 96
	case signature.SIGNATURE_TYPE_ECDSA_SHA512_P521:
		return 132
	case signature.SIGNATURE_TYPE_RSA_SHA256_2048:
		return 256
	case signature.SIGNATURE_TYPE_RSA_SHA384_3072:
		return 384
	case signature.SIGNATURE_TYPE_RSA_SHA512_4096:
		return 512
	case SIGNATURE_TYPE_ED25519_SHA512:
		return 32
	default:
		return 128
	}
}

// ConstructSigningPublicKey returns a SingingPublicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
func (keyCertificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key types.SigningPublicKey, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Constructing signingPublicKey from keyCertificate")
	signing_key_type := keyCertificate.SigningPublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < keyCertificate.SignatureSize() {
		log.WithFields(logrus.Fields{
			"at":           "(keyCertificate) ConstructSigningPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing signing public key")
		err = oops.Errorf("error constructing signing public key: not enough data")
		return
	}
	switch signing_key_type {
	case KEYCERT_SIGN_DSA_SHA1:
		var dsa_key dsa.DSAPublicKey
		copy(dsa_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_DSA_SHA1_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = dsa_key
		log.Debug("Constructed DSAPublicKey")
	case KEYCERT_SIGN_P256:
		var ec_p256_key ecdsa.ECP256PublicKey
		copy(ec_p256_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P256_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_p256_key
		log.Debug("Constructed P256PublicKey")
	case KEYCERT_SIGN_P384:
		var ec_p384_key ecdsa.ECP384PublicKey
		copy(ec_p384_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P384_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_p384_key
		log.Debug("Constructed P384PublicKey")
	case KEYCERT_SIGN_P521:
		/*var ec_p521_key crypto.ECP521PublicKey
		copy(ec_p521_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P521_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_p521_key
		log.Debug("Constructed P521PublicKey")*/
		panic("unimplemented P521SigningPublicKey")
	case KEYCERT_SIGN_RSA2048:
		/*var rsa2048_key crypto.RSA2048PublicKey
		copy(rsa2048_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_RSA2048_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = rsa2048_key
		log.Debug("Constructed RSA2048PublicKey")*/
		panic("unimplemented RSA2048SigningPublicKey")
	case KEYCERT_SIGN_RSA3072:
		/*var rsa3072_key crypto.RSA3072PublicKey
		copy(rsa3072_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_RSA3072_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = rsa3072_key
		log.Debug("Constructed RSA3072PublicKey")*/
		panic("unimplemented RSA3072SigningPublicKey")
	case KEYCERT_SIGN_RSA4096:
		/*var rsa4096_key crypto.RSA4096PublicKey
		copy(rsa4096_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_RSA4096_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = rsa4096_key
		log.Debug("Constructed RSA4096PublicKey")*/
		panic("unimplemented RSA4096SigningPublicKey")
	case KEYCERT_SIGN_ED25519:
		var ed25519_key ed25519.Ed25519PublicKey
		copy(ed25519_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_ED25519_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ed25519_key
		log.Debug("Constructed Ed25519PublicKey")
	case KEYCERT_SIGN_ED25519PH:
		var ed25519ph_key ed25519.Ed25519PublicKey
		copy(ed25519ph_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_ED25519PH_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ed25519ph_key
		log.Debug("Constructed Ed25519PHPublicKey")
	default:
		log.WithFields(logrus.Fields{
			"signing_key_type": signing_key_type,
		}).Warn("Unknown signing key type")
		return nil, oops.Errorf("unknown signing key type")
	}

	return
}

// SignatureSize return the size of a Signature corresponding to the Key Certificate's signingPublicKey type.
func (keyCertificate KeyCertificate) SignatureSize() (size int) {
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
	key_type := keyCertificate.SigningPublicKeyType()
	size, exists := sizes[key_type]
	if !exists {
		log.WithFields(logrus.Fields{
			"key_type": key_type,
		}).Warn("Unknown signing key type")
		return 0 // Or handle error appropriately
	}
	log.WithFields(logrus.Fields{
		"key_type":       key_type,
		"signature_size": size,
	}).Debug("Retrieved signature size")
	return sizes[int(key_type)]
}

// CryptoSize return the size of a Public Key corresponding to the Key Certificate's publicKey type.
func (keyCertificate KeyCertificate) CryptoSize() (size int) {
	sizes := map[int]int{
		KEYCERT_CRYPTO_ELG:    KEYCERT_CRYPTO_ELG_SIZE,
		KEYCERT_CRYPTO_P256:   KEYCERT_CRYPTO_P256_SIZE,
		KEYCERT_CRYPTO_P384:   KEYCERT_CRYPTO_P384_SIZE,
		KEYCERT_CRYPTO_P521:   KEYCERT_CRYPTO_P521_SIZE,
		KEYCERT_CRYPTO_X25519: KEYCERT_CRYPTO_X25519_SIZE,
	}
	key_type := keyCertificate.PublicKeyType()
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

	if certificate.Type() != CERT_KEY {
		return nil, remainder, oops.Errorf("invalid certificate type: %d", certificate.Type())
	}

	if len(certificate.Data()) < 4 {
		return nil, remainder, oops.Errorf("key certificate data too short")
	}
	log.Println("Certificate Data in NewKeyCertificate: ", certificate.Data()[0:2], certificate.Data()[2:4])

	cpkType, _ := ReadInteger(certificate.Data()[2:4], 2)
	spkType, _ := ReadInteger(certificate.Data()[0:2], 2)
	key_certificate = &KeyCertificate{
		Certificate: certificate,
		CpkType:     cpkType,
		SpkType:     spkType,
	}
	log.Println("cpkType in NewKeyCertificate: ", cpkType.Int(), "spkType in NewKeyCertificate: ", spkType.Int())

	log.WithFields(logrus.Fields{
		"spk_type":         key_certificate.SpkType.Int(),
		"cpk_type":         key_certificate.CpkType.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new keyCertificate")

	return
}

func KeyCertificateFromCertificate(cert Certificate) (*KeyCertificate, error) {
	if cert.Type() != CERT_KEY {
		return nil, oops.Errorf("expected Key Certificate type, got %d", cert.Type())
	}

	data := cert.Data()
	fmt.Printf("Certificate Data Length in KeyCertificateFromCertificate: %d\n", len(data))
	fmt.Printf("Certificate Data Bytes in KeyCertificateFromCertificate: %v\n", data)

	if len(data) < 4 {
		return nil, oops.Errorf("certificate payload too short in KeyCertificateFromCertificate")
	}

	cpkTypeBytes := data[0:2]
	spkTypeBytes := data[2:4]

	fmt.Printf("cpkTypeBytes in KeyCertificateFromCertificate: %v\n", cpkTypeBytes)
	fmt.Printf("spkTypeBytes in KeyCertificateFromCertificate: %v\n", spkTypeBytes)

	cpkType := Integer(cpkTypeBytes)
	spkType := Integer(spkTypeBytes)

	fmt.Printf("cpkType (Int) in KeyCertificateFromCertificate: %d\n", cpkType.Int())
	fmt.Printf("spkType (Int) in KeyCertificateFromCertificate: %d\n", spkType.Int())

	keyCert := &KeyCertificate{
		Certificate: cert,
		CpkType:     cpkType,
		SpkType:     spkType,
	}

	return keyCert, nil
}
