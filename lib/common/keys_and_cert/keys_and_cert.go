// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"errors"
	"github.com/go-i2p/go-i2p/lib/util/logger"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/sirupsen/logrus"
)

var log = logger.GetLogger()

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
A PublicKey followed by a SigningPublicKey and then a Certificate.

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

public_key :: PublicKey (partial or full)
              length -> 256 bytes or as specified in key certificate

padding :: random data
              length -> 0 bytes or as specified in key certificate
              padding length + signing_key length == 128 bytes

signing__key :: SigningPublicKey (partial or full)
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
	KeyCertificate   *KeyCertificate
	publicKey        crypto.PublicKey
	padding          []byte
	signingPublicKey crypto.SigningPublicKey
}

// Bytes returns the entire KeyCertificate in []byte form, trims payload to specified length.
func (keys_and_cert KeysAndCert) Bytes() []byte {
	bytes := keys_and_cert.KeyCertificate.Bytes()
	log.WithFields(logrus.Fields{
		"bytes_length": len(bytes),
	}).Debug("Retrieved bytes from KeysAndCert")
	return bytes
}

// PublicKey returns the public key as a crypto.PublicKey.
func (keys_and_cert *KeysAndCert) PublicKey() (key crypto.PublicKey) {
	return keys_and_cert.publicKey
}

// SigningPublicKey returns the signing public key.
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key crypto.SigningPublicKey) {
	return keys_and_cert.signingPublicKey
}

// Certfificate returns the certificate.
func (keys_and_cert *KeysAndCert) Certificate() (cert Certificate) {
	return keys_and_cert.KeyCertificate.Certificate
}

// ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
// Returns a pointer to KeysAndCert unlike ReadKeysAndCert.
func ReadKeysAndCert(data []byte) (keys_and_cert KeysAndCert, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")

	data_len := len(data)
	// keys_and_cert = KeysAndCert{}
	if data_len < KEYS_AND_CERT_MIN_SIZE && data_len > KEYS_AND_CERT_DATA_SIZE {
		log.WithFields(logrus.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		keys_and_cert.KeyCertificate, remainder, _ = NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
		return
	} else if data_len < KEYS_AND_CERT_DATA_SIZE {
		log.WithFields(logrus.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		return
	}
	keys_and_cert.KeyCertificate, remainder, err = NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		log.WithError(err).Error("Failed to create KeyCertificate")
		return
	}
	// TODO: this only supports one key type right now and it's the old key type, but the layout is the same.
	// a case-switch which sets the size of the SPK and the PK should be used to replace the referenced KEYS_AND_CERT_PUBKEY_SIZE
	// and KEYS_AND_CERT_SPK_SIZE constants in the future.
	keys_and_cert.publicKey, err = keys_and_cert.KeyCertificate.ConstructPublicKey(data[:keys_and_cert.KeyCertificate.CryptoSize()])
	if err != nil {
		log.WithError(err).Error("Failed to construct PublicKey")
		return
	}
	keys_and_cert.signingPublicKey, err = keys_and_cert.KeyCertificate.ConstructSigningPublicKey(data[KEYS_AND_CERT_DATA_SIZE-keys_and_cert.KeyCertificate.SignatureSize() : KEYS_AND_CERT_DATA_SIZE])
	if err != nil {
		log.WithError(err).Error("Failed to construct SigningPublicKey")
		return
	}
	padding := data[KEYS_AND_CERT_PUBKEY_SIZE : KEYS_AND_CERT_DATA_SIZE-KEYS_AND_CERT_SPK_SIZE]
	keys_and_cert.padding = padding

	log.WithFields(logrus.Fields{
		"public_key_type":         keys_and_cert.KeyCertificate.PublicKeyType(),
		"signing_public_key_type": keys_and_cert.KeyCertificate.SigningPublicKeyType(),
		"padding_length":          len(padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return
}
