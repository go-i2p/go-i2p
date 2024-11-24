// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"errors"
	"fmt"

	"github.com/go-i2p/go-i2p/lib/util/logger"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/crypto"
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
	keyCertificate   *KeyCertificate
	publicKey        crypto.PublicKey
	Padding          []byte
	signingPublicKey crypto.SigningPublicKey
}

// Bytes returns the entire keyCertificate in []byte form, trims payload to specified length.
func (keys_and_cert KeysAndCert) Bytes() []byte {
	bytes := keys_and_cert.publicKey.Bytes()
	bytes = append(bytes, keys_and_cert.Padding...)
	bytes = append(bytes, keys_and_cert.signingPublicKey.Bytes()...)
	bytes = append(bytes, keys_and_cert.keyCertificate.Bytes()...)
	log.WithFields(logrus.Fields{
		"bytes_length":         len(bytes),
		"pk_bytes_length":      len(keys_and_cert.publicKey.Bytes()),
		"padding_bytes_length": len(keys_and_cert.Padding),
		"spk_bytes_length":     len(keys_and_cert.signingPublicKey.Bytes()),
		"cert_bytes_length":    len(keys_and_cert.keyCertificate.Bytes()),
	}).Debug("Retrieved bytes from KeysAndCert")
	return bytes
}

// publicKey returns the public key as a crypto.publicKey.
func (keys_and_cert *KeysAndCert) PublicKey() (key crypto.PublicKey) {
	return keys_and_cert.publicKey
}

// signingPublicKey returns the signing public key.
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key crypto.SigningPublicKey) {
	return keys_and_cert.signingPublicKey
}

// Certfificate returns the certificate.
func (keys_and_cert *KeysAndCert) Certificate() (cert Certificate) {
	return keys_and_cert.keyCertificate.Certificate
}

// ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
// Returns a pointer to KeysAndCert unlike ReadKeysAndCert.
func ReadKeysAndCert(data []byte) (keys_and_cert KeysAndCert, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")

	data_len := len(data)
	if data_len < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(logrus.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		return
	}

	keys_and_cert.keyCertificate, remainder, err = NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		log.WithError(err).Error("Failed to create keyCertificate")
		return
	}

	// Get the actual key sizes from the certificate
	pubKeySize := keys_and_cert.keyCertificate.CryptoSize()
	sigKeySize := keys_and_cert.keyCertificate.SignatureSize()

	// Construct public key
	keys_and_cert.publicKey, err = keys_and_cert.keyCertificate.ConstructPublicKey(data[:pubKeySize])
	if err != nil {
		log.WithError(err).Error("Failed to construct publicKey")
		return
	}

	// Calculate padding size and extract padding
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if paddingSize > 0 {
		keys_and_cert.Padding = make([]byte, paddingSize)
		copy(keys_and_cert.Padding, data[pubKeySize:pubKeySize+paddingSize])
	}

	// Construct signing public key
	keys_and_cert.signingPublicKey, err = keys_and_cert.keyCertificate.ConstructSigningPublicKey(
		data[KEYS_AND_CERT_DATA_SIZE-sigKeySize : KEYS_AND_CERT_DATA_SIZE],
	)
	if err != nil {
		log.WithError(err).Error("Failed to construct signingPublicKey")
		return
	}

	log.WithFields(logrus.Fields{
		"public_key_type":         keys_and_cert.keyCertificate.PublicKeyType(),
		"signing_public_key_type": keys_and_cert.keyCertificate.SigningPublicKeyType(),
		"padding_length":          len(keys_and_cert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return
}

// NewKeysAndCert creates a new KeysAndCert instance with the provided parameters.
// It validates the sizes of the provided keys and padding before assembling the struct.
func NewKeysAndCert(
	keyCertificate *KeyCertificate,
	publicKey crypto.PublicKey,
	padding []byte,
	signingPublicKey crypto.SigningPublicKey,
) (*KeysAndCert, error) {
	log.Debug("Creating new KeysAndCert with provided parameters")

	if keyCertificate == nil {
		log.Error("KeyCertificate is nil")
		return nil, errors.New("KeyCertificate cannot be nil")
	}

	// Get actual key sizes from certificate
	pubKeySize := keyCertificate.CryptoSize()
	sigKeySize := keyCertificate.SignatureSize()

	// Validate public key size
	if publicKey.Len() != pubKeySize {
		log.WithFields(logrus.Fields{
			"expected_size": pubKeySize,
			"actual_size":   publicKey.Len(),
		}).Error("Invalid publicKey size")
		return nil, fmt.Errorf("publicKey has invalid size: expected %d, got %d", pubKeySize, publicKey.Len())
	}

	// Validate signing key size
	if signingPublicKey.Len() != sigKeySize {
		log.WithFields(logrus.Fields{
			"expected_size": sigKeySize,
			"actual_size":   signingPublicKey.Len(),
		}).Error("Invalid signingPublicKey size")
		return nil, fmt.Errorf("signingPublicKey has invalid size: expected %d, got %d", sigKeySize, signingPublicKey.Len())
	}

	// Calculate expected padding size
	expectedPaddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if len(padding) != expectedPaddingSize {
		log.WithFields(logrus.Fields{
			"expected_size": expectedPaddingSize,
			"actual_size":   len(padding),
		}).Error("Invalid padding size")
		return nil, fmt.Errorf("Invalid padding size")
		/*
			// Generate random padding if invalid or missing
			padding = make([]byte, expectedPaddingSize)
			if _, err := rand.Read(padding); err != nil {
				log.WithError(err).Error("Failed to generate random padding")
				return nil, err
			}
			log.Debug("Generated random padding")

		*/
	}

	keysAndCert := &KeysAndCert{
		keyCertificate:   keyCertificate,
		publicKey:        publicKey,
		Padding:          padding,
		signingPublicKey: signingPublicKey,
	}

	log.WithFields(logrus.Fields{
		"public_key_length":         publicKey.Len(),
		"signing_public_key_length": signingPublicKey.Len(),
		"padding_length":            len(padding),
	}).Debug("Successfully created KeysAndCert")

	return keysAndCert, nil
}
