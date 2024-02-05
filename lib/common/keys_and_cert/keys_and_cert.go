// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"errors"

	. "github.com/go-i2p/go-i2p/lib/common/certificate"
	. "github.com/go-i2p/go-i2p/lib/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/crypto"
	log "github.com/sirupsen/logrus"
)

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
func (keys_and_cert *KeysAndCert) Bytes() []byte {
	return keys_and_cert.KeyCertificate.Bytes()
}

// PublicKey returns the public key as a crypto.PublicKey.
func (keys_and_cert *KeysAndCert) PublicKey() (key crypto.PublicKey) {
	/*cert := keys_and_cert.Certificate()
	cert_len := cert.Length()
	if err != nil {
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the KEYS_AND_CERT_PUBKEY_SIZE byte
		// PublicKey space as ElgPublicKey.
		var elg_key crypto.ElgPublicKey
		copy(keys_and_cert[:KEYS_AND_CERT_PUBKEY_SIZE], elg_key[:])
		key = elg_key
	} else {
		// A Certificate is present in this KeysAndCert
		cert_type := cert.Type()
		if cert_type == CERT_KEY {
			// This KeysAndCert contains a Key Certificate, construct
			// a PublicKey from the data in the KeysAndCert and
			// any additional data in the Certificate.
			key, err = KeyCertificateFromCertificate(cert).ConstructPublicKey(
				keys_and_cert[:KEYS_AND_CERT_PUBKEY_SIZE],
			)
		} else {
			// Key Certificate is not present, return the KEYS_AND_CERT_PUBKEY_SIZE byte
			// PublicKey space as ElgPublicKey.  No other Certificate
			// types are currently in use.
			var elg_key crypto.ElgPublicKey
			copy(keys_and_cert[:KEYS_AND_CERT_PUBKEY_SIZE], elg_key[:])
			key = elg_key
			log.WithFields(log.Fields{
				"at":        "(KeysAndCert) PublicKey",
				"cert_type": cert_type,
			}).Warn("unused certificate type observed")
		}

	}
	return*/
	return keys_and_cert.publicKey
}

// SigningPublicKey returns the signing public key.
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key crypto.SigningPublicKey) {
	/*cert := keys_and_cert.Certificate()
	cert_len := cert.Length()
	if err != nil {
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the KEYS_AND_CERT_SPK_SIZE byte
		// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
		var dsa_pk crypto.DSAPublicKey
		copy(dsa_pk[:], keys_and_cert[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE])
		signing_public_key = dsa_pk
	} else {
		// A Certificate is present in this KeysAndCert
		cert_type := cert.Type()
		if cert_type == CERT_KEY {
			// This KeysAndCert contains a Key Certificate, construct
			// a SigningPublicKey from the data in the KeysAndCert and
			// any additional data in the Certificate.
			signing_public_key, err = KeyCertificateFromCertificate(cert).ConstructSigningPublicKey(
				keys_and_cert[KEYS_AND_CERT_PUBKEY_SIZE : KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE],
			)
		} else {
			// Key Certificate is not present, return the KEYS_AND_CERT_SPK_SIZE byte
			// SigningPublicKey space as legacy SHA DSA1 SigningPublicKey.
			// No other Certificate types are currently in use.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], keys_and_cert[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE])
			signing_public_key = dsa_pk
		}

	}*/
	return keys_and_cert.signingPublicKey
}

// Certfificate returns the certificate.
func (keys_and_cert *KeysAndCert) Certificate() (cert *Certificate) {
	return keys_and_cert.KeyCertificate.Certificate
}

// NewKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
// Returns a pointer to KeysAndCert unlike ReadKeysAndCert.
func NewKeysAndCert(data []byte) (keys_and_cert *KeysAndCert, remainder []byte, err error) {
	data_len := len(data)
	keys_and_cert = &KeysAndCert{}
	if data_len < KEYS_AND_CERT_MIN_SIZE && data_len > KEYS_AND_CERT_DATA_SIZE {
		log.WithFields(log.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		keys_and_cert.KeyCertificate, remainder, _ = NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
		return
	} else if data_len < KEYS_AND_CERT_DATA_SIZE {
		log.WithFields(log.Fields{
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
		return nil, nil, err
	}
	// TODO: this only supports one key type right now and it's the old key type, but the layout is the same.
	// a case-switch which sets the size of the SPK and the PK should be used to replace the referenced KEYS_AND_CERT_PUBKEY_SIZE
	// and KEYS_AND_CERT_SPK_SIZE constants in the future.
	keys_and_cert.publicKey, err = keys_and_cert.KeyCertificate.ConstructPublicKey(data[:KEYS_AND_CERT_PUBKEY_SIZE])
	if err != nil {
		return nil, nil, err
	}
	keys_and_cert.signingPublicKey, err = keys_and_cert.KeyCertificate.ConstructSigningPublicKey(data[KEYS_AND_CERT_DATA_SIZE-KEYS_AND_CERT_SPK_SIZE : KEYS_AND_CERT_DATA_SIZE])
	if err != nil {
		return nil, nil, err
	}
	padding := data[KEYS_AND_CERT_PUBKEY_SIZE : KEYS_AND_CERT_DATA_SIZE-KEYS_AND_CERT_SPK_SIZE]
	keys_and_cert.padding = padding
	return keys_and_cert, remainder, err
}
