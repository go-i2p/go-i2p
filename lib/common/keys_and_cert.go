package common

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

type KeysAndCertInterface interface {
	GetPublicKey() (key crypto.PublicKey, err error)
	GetSigningPublicKey() (signing_public_key crypto.SigningPublicKey, err error)
	GetCertificate() (cert Certificate, err error)
	Bytes() (bytes []byte)
}

type KeysAndCert struct {
	crypto.SigningPublicKey
	crypto.PublicKey
	CertificateInterface
}

func (keys_and_cert KeysAndCert) Bytes() (bytes []byte) { //, err error) {
	pubkey, _ := keys_and_cert.GetPublicKey()
	signpubkey, _ := keys_and_cert.GetSigningPublicKey()
	elg_key := pubkey.(crypto.ElgPublicKey)
	dsa_key := signpubkey.(crypto.DSAPublicKey)
	bytes = append(bytes, dsa_key[:]...)
	bytes = append(bytes, elg_key[:]...)
	bytes = append(bytes, keys_and_cert.CertificateInterface.Cert()...)
	return
}

//
// Return the PublicKey for this KeysAndCert, reading from the Key Certificate if it is present to
// determine correct lengths.
//
func (keys_and_cert KeysAndCert) GetPublicKey() (key crypto.PublicKey, err error) {
	data := make([]byte, KEYS_AND_CERT_PUBKEY_SIZE)
	if keys_and_cert.PublicKey == nil {
		epk := crypto.ElgPublicKey{}
		copy(data[:KEYS_AND_CERT_PUBKEY_SIZE], epk[:])
		keys_and_cert.PublicKey = epk
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
	}
	/*cert, err := keys_and_cert.GetCertificate()
	if err != nil {
		return
	}
	cert_len, err := cert.Length()
	if err != nil {
		return
	}
	if cert_len != 0 {*/
	key = keys_and_cert.PublicKey
	/*}*/
	return
}

//
// Return the SigningPublicKey for this KeysAndCert, reading from the Key Certificate if it is present to
// determine correct lengths.
//
func (keys_and_cert KeysAndCert) GetSigningPublicKey() (signing_public_key crypto.SigningPublicKey, err error) {
	if keys_and_cert.SigningPublicKey == nil {
		keys_and_cert.SigningPublicKey = crypto.DSAPublicKey{}
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
	}
	/*cert, err := keys_and_cert.GetCertificate()
	if err != nil {
		return
	}
	cert_len, err := cert.Length()
	if err != nil {
		return
	}
	if cert_len != 0 {*/
	signing_public_key = keys_and_cert.SigningPublicKey
	/*}*/
	return
}

//
// Return the Certificate contained in the KeysAndCert and any errors encountered while parsing the
// KeysAndCert or Certificate.
//
func (keys_and_cert KeysAndCert) GetCertificate() (cert CertificateInterface, err error) {
	data_len := len(keys_and_cert.Cert())
	if data_len < CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("certificate parsing warning: certificate data is shorter than specified by length")
	}
	if data_len > CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "too much data",
		}).Error("error parsing keys and cert")
		err = errors.New("certificate parsing warning: certificate data is longer than specified by length")
	}
	cert = keys_and_cert.CertificateInterface
	return
}

func ReadKeys(data []byte, cert CertificateInterface) (spk crypto.SigningPublicKey, pk crypto.PublicKey, remainder []byte, err error) {
	data_len := len(data)
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
	if cert == nil {
		// No Certificate is present, return the KEYS_AND_CERT_PUBKEY_SIZE byte
		// PublicKey space as ElgPublicKey.
		var elg_key crypto.ElgPublicKey
		copy(data[:KEYS_AND_CERT_PUBKEY_SIZE], elg_key[:])
		pk = elg_key
	} else {
		// A Certificate is present in this KeysAndCert
		cert_type, cert_bytes, _ := cert.Type()
		if cert_type == CERT_KEY {
			// This KeysAndCert contains a Key Certificate, construct
			// a PublicKey from the data in the KeysAndCert and
			// any additional data in the Certificate.
			cert_integer, _ := NewInteger(cert_bytes)
			pk, err = KeyCertificate{PKType: cert_integer}.ConstructPublicKey(
				data[:KEYS_AND_CERT_PUBKEY_SIZE],
			)
		} else {
			// Key Certificate is not present, return the KEYS_AND_CERT_PUBKEY_SIZE byte
			// PublicKey space as ElgPublicKey.  No other Certificate
			// types are currently in use.
			var elg_key crypto.ElgPublicKey
			copy(data[:KEYS_AND_CERT_PUBKEY_SIZE], elg_key[:])
			pk = elg_key
			log.WithFields(log.Fields{
				"at":        "(KeysAndCert) PublicKey",
				"cert_type": cert_type,
			}).Warn("unused certificate type observed")
		}
		//	}
		if data_len == 0 {
			// No Certificate is present, return the KEYS_AND_CERT_SPK_SIZE byte
			// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], data[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE])
			spk = dsa_pk
		} else {
			// A Certificate is present in this KeysAndCert
			cert_type, cert_bytes, _ := cert.Type()
			if cert_type == CERT_KEY {
				// This KeysAndCert contains a Key Certificate, construct
				// a SigningPublicKey from the data in the KeysAndCert and
				// any additional data in the Certificate.
				cert_integer, _ := NewInteger(cert_bytes)
				spk, err = KeyCertificate{SPKType: cert_integer}.ConstructSigningPublicKey(
					data[KEYS_AND_CERT_PUBKEY_SIZE : KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE],
				)
			} else {
				// Key Certificate is not present, return the KEYS_AND_CERT_SPK_SIZE byte
				// SigningPublicKey space as legacy SHA DSA1 SigningPublicKey.
				// No other Certificate types are currently in use.
				var dsa_pk crypto.DSAPublicKey
				copy(dsa_pk[:], data[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE])
				spk = dsa_pk
			}
		}
		cert_len, _ := cert.Length()
		if cert_len == 0 {
			remainder = data[KEYS_AND_CERT_MIN_SIZE:]
			return
		}
		remainder = data[KEYS_AND_CERT_PUBKEY_SIZE+KEYS_AND_CERT_SPK_SIZE:]
	}
	return

}

//
// Read a KeysAndCert from a slice of bytes, retuning it and the remaining data as well as any errors
// encoutered parsing the KeysAndCert.
//
func ReadKeysAndCert(data []byte) (keys_and_cert KeysAndCert, remainder []byte, err error) {
	data_len := len(data)
	keys_and_cert.CertificateInterface = &Certificate{}
	if data_len < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		//		return
	}
	cert, remainder, err := ReadCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		//return
		log.Error("ERROR READ CERTIFICATE", err)
		err = nil

	}
	log.Println("READ CERTIFICATE", cert.Cert())
	keys_and_cert.CertificateInterface = cert
	spk, pk, remainder, err := ReadKeys(data, cert)
	if err != nil {
		//		return
		log.Error("ERROR READ KEYS", err)
		err = nil

	}
	log.Println("READ KEYS")
	keys_and_cert.SigningPublicKey = spk
	keys_and_cert.PublicKey = pk
	return
}
