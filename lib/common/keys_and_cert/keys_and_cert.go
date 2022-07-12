package keys_and_cert

/*
I2P KeysAndCert
https://geti2p.net/spec/common-structures#keysandcert
Accurate for version 0.9.24

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
              padding length + signing_key length == KEYS_AND_CERT_SPK_SIZE bytes

signing__key :: SigningPublicKey (partial or full)
              length -> 128 bytes or as specified in key certificate
              padding length + signing_key length == KEYS_AND_CERT_SPK_SIZE bytes

certificate :: Certificate
               length -> >= 3 bytes

total length: 387+ bytes
*/

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

type KeysAndCert struct {
	KeyCertificate   *KeyCertificate
	publicKey        crypto.PublicKey
	padding          []byte
	signingPublicKey crypto.SigningPublicKey
}

//
// Return the PublicKey for this KeysAndCert, reading from the Key Certificate if it is present to
// determine correct lengths.
//
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

//
// Return the SigningPublicKey for this KeysAndCert, reading from the Key Certificate if it is present to
// determine correct lengths.
//
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

//
// Return the Certificate contained in the KeysAndCert and any errors encountered while parsing the
// KeysAndCert or Certificate.
//
func (keys_and_cert *KeysAndCert) Certificate() (cert *Certificate) {
	return keys_and_cert.KeyCertificate.Certificate
}

//
// Read a KeysAndCert from a slice of bytes, retuning it and the remaining data as well as any errors
// encoutered parsing the KeysAndCert.
//
func ReadKeysAndCert(data []byte) (keys_and_cert KeysAndCert, remainder []byte, err error) {
	/*data_len := len(data)
	if data_len < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		return
	}
	keys_and_cert = KeysAndCert(data[:KEYS_AND_CERT_MIN_SIZE])
	cert, _ := keys_and_cert.Certificate()
	cert_len := cert.Length()
	if cert_len == 0 {
		remainder = data[KEYS_AND_CERT_MIN_SIZE:]
		return
	}
	if data_len < KEYS_AND_CERT_MIN_SIZE+cert_len {
		keys_and_cert = append(keys_and_cert, data[KEYS_AND_CERT_MIN_SIZE:]...)
		//err = cert_len_err
	} else {
		keys_and_cert = append(keys_and_cert, data[KEYS_AND_CERT_MIN_SIZE:KEYS_AND_CERT_MIN_SIZE+cert_len]...)
		remainder = data[KEYS_AND_CERT_MIN_SIZE+cert_len:]
	}*/
	keys_and_cert_pointer, remainder, err := NewKeysAndCert(data)
	keys_and_cert = *keys_and_cert_pointer
	return
}

func NewKeysAndCert(data []byte) (keys_and_cert *KeysAndCert, remainder []byte, err error) {
	data_len := len(data)
	keys_and_cert = &KeysAndCert{}
	if data_len < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		return
	}
	cert, remainder, err := NewKeyCertificate(data)
	keys_and_cert.KeyCertificate = cert
	if err != nil {
		return nil, nil, err
	}
	padding := data[KEYS_AND_CERT_MIN_SIZE+cert.Length():]
	keys_and_cert.padding = padding
	publicKey, err := cert.ConstructPublicKey(padding)
	keys_and_cert.publicKey = publicKey
	if err != nil {
		return nil, nil, err
	}
	signingPublicKey, err := cert.ConstructSigningPublicKey(padding)
	keys_and_cert.signingPublicKey = signingPublicKey
	if err != nil {
		return nil, nil, err
	}
	return keys_and_cert, remainder, err
}
