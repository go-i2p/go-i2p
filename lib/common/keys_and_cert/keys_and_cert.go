// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"github.com/go-i2p/go-i2p/lib/crypto/ed25519"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/key_certificate"
	elgamal "github.com/go-i2p/go-i2p/lib/crypto/elg"
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

// Sizes of various KeysAndCert structures and requirements
const (
	KEYS_AND_CERT_PUBKEY_SIZE = 256
	KEYS_AND_CERT_SPK_SIZE    = 128
	KEYS_AND_CERT_MIN_SIZE    = 387
	KEYS_AND_CERT_DATA_SIZE   = 384
)

// Key sizes in bytes

/*
[KeysAndCert]
Accurate for version 0.9.49

Description
An encryption public key, a signing public key, and a certificate, used as either a RouterIdentity or a Destination.

Contents
A publicKey followed by a signingPublicKey and then a Certificate.

+----+----+----+----+----+----+----+----+
| public_key                            |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| padding (optional)                    |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signing_key                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| certificate                           |
+----+----+----+-//

public_key :: publicKey (partial or full)
              length -> 256 bytes or as specified in key certificate

padding :: random data
              length -> 0 bytes or as specified in key certificate
              padding length + signing_key length == 128 bytes

signing__key :: signingPublicKey (partial or full)
              length -> 128 bytes or as specified in key certificate
              padding length + signing_key length == 128 bytes

certificate :: Certificate
               length -> >= 3 bytes

total length: 387+ bytes
*/

// KeysAndCert is the represenation of an I2P KeysAndCert.
//
// https://geti2p.net/spec/common-structures#keysandcert
type KeysAndCert struct {
	KeyCertificate  *KeyCertificate
	ReceivingPublic types.RecievingPublicKey
	Padding         []byte
	SigningPublic   types.SigningPublicKey
}

// Bytes returns the entire keyCertificate in []byte form, trims payload to specified length.
func (keys_and_cert KeysAndCert) Bytes() []byte {
	bytes := []byte{}
	rpublen := 0
	if keys_and_cert.ReceivingPublic != nil {
		bytes = append(bytes, keys_and_cert.ReceivingPublic.Bytes()...)
		rpublen = len(keys_and_cert.ReceivingPublic.Bytes())
	}
	// bytes = append(bytes, keys_and_cert.ReceivingPublic.Bytes()...)
	padlen := 0
	if keys_and_cert.Padding != nil {
		bytes = append(bytes, keys_and_cert.Padding...)
		padlen = len(keys_and_cert.Padding)
	}
	// bytes = append(bytes, keys_and_cert.Padding...)
	spublen := 0
	if keys_and_cert.SigningPublic != nil {
		bytes = append(bytes, keys_and_cert.SigningPublic.Bytes()...)
		spublen = len(keys_and_cert.SigningPublic.Bytes())
	}
	// bytes = append(bytes, keys_and_cert.SigningPublic.Bytes()...)
	certlen := 0
	if keys_and_cert.KeyCertificate != nil {
		bytes = append(bytes, keys_and_cert.KeyCertificate.Bytes()...)
		certlen = len(keys_and_cert.KeyCertificate.Bytes())
	}
	// bytes = append(bytes, keys_and_cert.KeyCertificate.Bytes()...)
	log.WithFields(logrus.Fields{
		"bytes":                bytes,
		"padding":              keys_and_cert.Padding,
		"bytes_length":         len(bytes),
		"pk_bytes_length":      rpublen,
		"padding_bytes_length": padlen,
		"spk_bytes_length":     spublen,
		"cert_bytes_length":    certlen,
	}).Debug("Retrieved bytes from KeysAndCert")
	return bytes
}

// publicKey returns the public key as a types.publicKey.
func (keys_and_cert *KeysAndCert) PublicKey() (key types.RecievingPublicKey) {
	return keys_and_cert.ReceivingPublic
}

// signingPublicKey returns the signing public key.
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key types.SigningPublicKey) {
	return keys_and_cert.SigningPublic
}

// Certfificate returns the certificate.
func (keys_and_cert *KeysAndCert) Certificate() (cert Certificate) {
	return keys_and_cert.KeyCertificate.Certificate
}

// ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
// Returns a pointer to KeysAndCert unlike ReadKeysAndCert.
func ReadKeysAndCert(data []byte) (*KeysAndCert, []byte, error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")
	var err error
	var remainder []byte
	var keys_and_cert KeysAndCert

	data_len := len(data)
	if data_len < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(logrus.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = oops.Errorf("error parsing KeysAndCert: data is smaller than minimum valid size")
		return &keys_and_cert, remainder, err
	}

	keys_and_cert.KeyCertificate, remainder, err = NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		log.WithError(err).Error("Failed to create keyCertificate")
		return &keys_and_cert, remainder, err
	}

	// Get the actual key sizes from the certificate
	pubKeySize := keys_and_cert.KeyCertificate.CryptoSize()
	sigKeySize := keys_and_cert.KeyCertificate.SignatureSize()

	// Construct public key
	keys_and_cert.ReceivingPublic, err = keys_and_cert.KeyCertificate.ConstructPublicKey(data[:pubKeySize])
	if err != nil {
		log.WithError(err).Error("Failed to construct publicKey")
		return &keys_and_cert, remainder, err
	}

	// Calculate padding size and extract padding
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if paddingSize > 0 {
		keys_and_cert.Padding = make([]byte, paddingSize)
		copy(keys_and_cert.Padding, data[pubKeySize:pubKeySize+paddingSize])
	}

	// Construct signing public key
	keys_and_cert.SigningPublic, err = keys_and_cert.KeyCertificate.ConstructSigningPublicKey(
		data[KEYS_AND_CERT_DATA_SIZE-sigKeySize : KEYS_AND_CERT_DATA_SIZE],
	)
	if err != nil {
		log.WithError(err).Error("Failed to construct signingPublicKey")
		return &keys_and_cert, remainder, err
	}

	log.WithFields(logrus.Fields{
		"public_key_type":         keys_and_cert.KeyCertificate.PublicKeyType(),
		"signing_public_key_type": keys_and_cert.KeyCertificate.SigningPublicKeyType(),
		"padding_length":          len(keys_and_cert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return &keys_and_cert, remainder, err
}

func ReadKeysAndCertElgAndEd25519(data []byte) (keysAndCert *KeysAndCert, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")

	// Constants based on fixed key sizes
	const (
		pubKeySize    = 256                                    // ElGamal public key size
		sigKeySize    = 32                                     // Ed25519 public key size
		totalKeySize  = 384                                    // KEYS_AND_CERT_DATA_SIZE
		paddingSize   = totalKeySize - pubKeySize - sigKeySize // 96 bytes
		minDataLength = totalKeySize + 3
	)

	dataLen := len(data)
	if dataLen < minDataLength {
		err = oops.Errorf("error parsing KeysAndCert: data is smaller than minimum valid size, got %d bytes", dataLen)
		log.WithError(err).Error("Data is smaller than minimum valid size")
		return
	}

	// Initialize KeysAndCert
	keysAndCert = &KeysAndCert{}

	// Extract public key
	publicKeyData := data[:pubKeySize]
	if len(publicKeyData) != pubKeySize {
		err = oops.Errorf("invalid ElGamal public key length")
		log.WithError(err).Error("Invalid ElGamal public key length")
		return
	}
	var elgPublicKey elgamal.ElgPublicKey
	copy(elgPublicKey[:], publicKeyData)
	keysAndCert.ReceivingPublic = elgPublicKey

	// Extract padding
	paddingStart := pubKeySize
	paddingEnd := paddingStart + paddingSize
	keysAndCert.Padding = data[paddingStart:paddingEnd]

	// Extract signing public key
	signingPubKeyData := data[paddingEnd : paddingEnd+sigKeySize]
	if len(signingPubKeyData) != sigKeySize {
		err = oops.Errorf("invalid Ed25519 public key length")
		log.WithError(err).Error("Invalid Ed25519 public key length")
		return
	}
	edPublicKey := ed25519.Ed25519PublicKey(signingPubKeyData)
	keysAndCert.SigningPublic = edPublicKey

	// Extract the certificate
	certData := data[totalKeySize:]
	keysAndCert.KeyCertificate, remainder, err = NewKeyCertificate(certData)
	if err != nil {
		log.WithError(err).Error("Failed to read keyCertificate")
		return
	}

	log.WithFields(logrus.Fields{
		"public_key_type":         "ElGamal",
		"signing_public_key_type": "Ed25519",
		"padding_length":          len(keysAndCert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return
}

func constructPublicKey(data []byte, cryptoType uint16) (types.RecievingPublicKey, error) {
	switch cryptoType {
	case CRYPTO_KEY_TYPE_ELGAMAL:
		if len(data) != 256 {
			return nil, oops.Errorf("invalid ElGamal public key length")
		}
		var elgPublicKey elgamal.ElgPublicKey
		copy(elgPublicKey[:], data)
		return elgPublicKey, nil
	// Handle other crypto types...
	default:
		return nil, oops.Errorf("unsupported crypto key type: %d", cryptoType)
	}
}

func constructSigningPublicKey(data []byte, sigType uint16) (types.SigningPublicKey, error) {
	switch sigType {
	case SIGNATURE_TYPE_ED25519_SHA512:
		if len(data) != 32 {
			return nil, oops.Errorf("invalid Ed25519 public key length")
		}
		return ed25519.Ed25519PublicKey(data), nil
	// Handle other signature types...
	default:
		return nil, oops.Errorf("unsupported signature key type: %d", sigType)
	}
}

// NewKeysAndCert creates a new KeysAndCert instance with the provided parameters.
// It validates the sizes of the provided keys and padding before assembling the struct.
func NewKeysAndCert(
	keyCertificate *KeyCertificate,
	publicKey types.RecievingPublicKey,
	padding []byte,
	signingPublicKey types.SigningPublicKey,
) (*KeysAndCert, error) {
	log.Debug("Creating new KeysAndCert with provided parameters")

	if keyCertificate == nil {
		log.Error("KeyCertificate is nil")
		return nil, oops.Errorf("KeyCertificate cannot be nil")
	}

	// Get actual key sizes from certificate
	pubKeySize := keyCertificate.CryptoSize()
	sigKeySize := keyCertificate.SignatureSize()

	// Validate public key size
	if publicKey != nil {
		if publicKey.Len() != pubKeySize {
			log.WithFields(logrus.Fields{
				"expected_size": pubKeySize,
				"actual_size":   publicKey.Len(),
			}).Error("Invalid publicKey size")
			return nil, oops.Errorf("publicKey has invalid size: expected %d, got %d", pubKeySize, publicKey.Len())
		}
	}

	if signingPublicKey != nil {
		// Validate signing key size
		if signingPublicKey.Len() != sigKeySize {
			log.WithFields(logrus.Fields{
				"expected_size": sigKeySize,
				"actual_size":   signingPublicKey.Len(),
			}).Error("Invalid signingPublicKey size")
			return nil, oops.Errorf("signingPublicKey has invalid size: expected %d, got %d", sigKeySize, signingPublicKey.Len())
		}
	}

	// Calculate expected padding size
	expectedPaddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if len(padding) != expectedPaddingSize {
		log.WithFields(logrus.Fields{
			"expected_size": expectedPaddingSize,
			"actual_size":   len(padding),
		}).Error("Invalid padding size")
		return nil, oops.Errorf("invalid padding size")
	}

	keysAndCert := &KeysAndCert{
		KeyCertificate:  keyCertificate,
		ReceivingPublic: publicKey,
		Padding:         padding,
		SigningPublic:   signingPublicKey,
	}

	/*log.WithFields(logrus.Fields{
		"public_key_length":         publicKey.Len(),
		"signing_public_key_length": signingPublicKey.Len(),
		"padding_length":            len(padding),
	}).Debug("Successfully created KeysAndCert")*/

	return keysAndCert, nil
}
