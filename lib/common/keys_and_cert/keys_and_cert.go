// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"encoding/binary"
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
	KeyCertificate   *KeyCertificate
	publicKey        crypto.PublicKey
	Padding          []byte
	signingPublicKey crypto.SigningPublicKey
}

// Bytes returns the entire keyCertificate in []byte form, trims payload to specified length.
func (keys_and_cert KeysAndCert) Bytes() []byte {
	bytes := keys_and_cert.publicKey.Bytes()
	bytes = append(bytes, keys_and_cert.Padding...)
	bytes = append(bytes, keys_and_cert.signingPublicKey.Bytes()...)
	bytes = append(bytes, keys_and_cert.KeyCertificate.Bytes()...)
	log.WithFields(logrus.Fields{
		"bytes":                bytes,
		"padding":              keys_and_cert.Padding,
		"bytes_length":         len(bytes),
		"pk_bytes_length":      len(keys_and_cert.publicKey.Bytes()),
		"padding_bytes_length": len(keys_and_cert.Padding),
		"spk_bytes_length":     len(keys_and_cert.signingPublicKey.Bytes()),
		"cert_bytes_length":    len(keys_and_cert.KeyCertificate.Bytes()),
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
	return keys_and_cert.KeyCertificate.Certificate
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

	keys_and_cert.KeyCertificate, remainder, err = NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		log.WithError(err).Error("Failed to create keyCertificate")
		return
	}

	// Get the actual key sizes from the certificate
	pubKeySize := keys_and_cert.KeyCertificate.CryptoSize()
	sigKeySize := keys_and_cert.KeyCertificate.SignatureSize()

	// Construct public key
	keys_and_cert.publicKey, err = keys_and_cert.KeyCertificate.ConstructPublicKey(data[:pubKeySize])
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
	keys_and_cert.signingPublicKey, err = keys_and_cert.KeyCertificate.ConstructSigningPublicKey(
		data[KEYS_AND_CERT_DATA_SIZE-sigKeySize : KEYS_AND_CERT_DATA_SIZE],
	)
	if err != nil {
		log.WithError(err).Error("Failed to construct signingPublicKey")
		return
	}

	log.WithFields(logrus.Fields{
		"public_key_type":         keys_and_cert.KeyCertificate.PublicKeyType(),
		"signing_public_key_type": keys_and_cert.KeyCertificate.SigningPublicKeyType(),
		"padding_length":          len(keys_and_cert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return
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
		err = fmt.Errorf("error parsing KeysAndCert: data is smaller than minimum valid size, got %d bytes", dataLen)
		log.WithError(err).Error("Data is smaller than minimum valid size")
		return
	}

	// Initialize KeysAndCert
	keysAndCert = &KeysAndCert{}

	// Extract public key
	publicKeyData := data[:pubKeySize]
	if len(publicKeyData) != pubKeySize {
		err = errors.New("invalid ElGamal public key length")
		log.WithError(err).Error("Invalid ElGamal public key length")
		return
	}
	var elgPublicKey crypto.ElgPublicKey
	copy(elgPublicKey[:], publicKeyData)
	keysAndCert.publicKey = elgPublicKey

	// Extract padding
	paddingStart := pubKeySize
	paddingEnd := paddingStart + paddingSize
	keysAndCert.Padding = data[paddingStart:paddingEnd]

	// Extract signing public key
	signingPubKeyData := data[paddingEnd : paddingEnd+sigKeySize]
	if len(signingPubKeyData) != sigKeySize {
		err = errors.New("invalid Ed25519 public key length")
		log.WithError(err).Error("Invalid Ed25519 public key length")
		return
	}
	edPublicKey := crypto.Ed25519PublicKey(signingPubKeyData)
	keysAndCert.signingPublicKey = edPublicKey

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

func ReadKeysAndCertDeux(data []byte) (keysAndCert *KeysAndCert, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")

	dataLen := len(data)
	if dataLen < CERT_MIN_SIZE {
		err = errors.New("data is too short to contain a certificate")
		log.WithError(err).Error("Data is too short to contain a certificate")
		return
	}

	// Read the certificate from the end
	cert, certStartIndex, err := readCertificateFromEnd(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate")
		return
	}

	log.WithFields(logrus.Fields{
		"cert_type": cert.Type(),
	}).Debug("Certificate type read")

	// Check if the certificate is of type CERT_KEY
	if cert.Type() != CERT_KEY {
		err = fmt.Errorf("unsupported certificate type: %d", cert.Type())
		log.WithError(err).Error("Unsupported certificate type")
		return
	}

	// Parse the Key Certificate from the certificate payload
	keyCert, err := NewKeyCertificateFromCertificate(cert)
	if err != nil {
		log.WithError(err).Error("Failed to parse KeyCertificate")
		return
	}

	// Get key sizes
	pubKeySize, err := keyCert.CryptoPublicKeySize()
	if err != nil {
		log.WithError(err).Error("Failed to get crypto public key size")
		return
	}
	sigKeySize, err := keyCert.SigningPublicKeySize()
	if err != nil {
		log.WithError(err).Error("Failed to get signing public key size")
		return
	}

	// Calculate positions
	signingKeyEndIndex := certStartIndex
	signingKeyStartIndex := signingKeyEndIndex - sigKeySize
	paddingEndIndex := signingKeyStartIndex
	paddingStartIndex := pubKeySize
	paddingSize := paddingEndIndex - paddingStartIndex

	// Validate positions
	if signingKeyStartIndex < 0 || paddingStartIndex < 0 || paddingSize < 0 {
		err = errors.New("error parsing KeysAndCert: invalid key sizes or data too short")
		log.WithError(err).Error("Invalid key sizes or data too short")
		return
	}

	keysAndCert = &KeysAndCert{
		KeyCertificate: keyCert,
	}

	// Extract public key
	publicKeyData := data[:pubKeySize]
	keysAndCert.publicKey, err = constructPublicKey(publicKeyData, uint16(keyCert.CpkType.Int()))
	if err != nil {
		log.WithError(err).Error("Failed to construct public key")
		return
	}

	// Extract padding
	if paddingSize > 0 {
		keysAndCert.Padding = data[paddingStartIndex:paddingEndIndex]
	} else {
		keysAndCert.Padding = []byte{}
	}

	// Extract signing public key
	signingPubKeyData := data[signingKeyStartIndex:signingKeyEndIndex]
	keysAndCert.signingPublicKey, err = constructSigningPublicKey(signingPubKeyData, uint16(keyCert.SpkType.Int()))
	if err != nil {
		log.WithError(err).Error("Failed to construct signing public key")
		return
	}

	// Set remainder to any data before the KeysAndCert
	totalCertLen := 1 + 2 + cert.Length() // type (1 byte) + length (2 bytes) + payload

	/*
		Set remainder to any data after the KeysAndCert
		Since certStartIndex is the index where the certificate starts,
		certStartIndex + totalCertLen should equal dataLen if there's no extra data.
		If there's extra data after the certificate, remainder will contain it.
	*/
	remainderIndex := certStartIndex + totalCertLen
	if remainderIndex < dataLen {
		remainder = data[remainderIndex:]
	} else {
		remainder = []byte{}
	}

	log.WithFields(logrus.Fields{
		"public_key_type":         keyCert.CpkType,
		"signing_public_key_type": keyCert.SpkType,
		"padding_length":          len(keysAndCert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return
}

func readCertificateFromEnd(data []byte) (cert Certificate, certStartIndex int, err error) {
	dataLen := len(data)

	// Minimum certificate size is 3 bytes (type + length)
	if dataLen < CERT_MIN_SIZE {
		err = errors.New("data is too short to contain a certificate")
		return
	}

	// Start from the end and work backwards
	for certLen := 0; certLen <= dataLen-CERT_MIN_SIZE; certLen++ {
		totalCertLen := 1 + 2 + certLen
		certStartIndex = dataLen - totalCertLen
		if certStartIndex < 0 {
			continue
		}

		certTypeIndex := certStartIndex
		certLenBytesIndex := certStartIndex + 1

		// Ensure we have enough data to read type and length
		if certLenBytesIndex+2 > dataLen {
			continue
		}

		// Extract certificate type
		certType := data[certTypeIndex]

		// Extract certificate length
		certLenBytes := data[certLenBytesIndex : certLenBytesIndex+2]
		expectedCertLen := int(binary.BigEndian.Uint16(certLenBytes))

		if expectedCertLen != certLen {
			continue
		}

		// Optionally, check for valid certificate types
		if certType != CERT_KEY && certType != CERT_NULL && certType != CERT_HASHCASH &&
			certType != CERT_HIDDEN && certType != CERT_SIGNED && certType != CERT_MULTIPLE {
			continue
		}

		certData := data[certStartIndex:dataLen]

		// Attempt to read the certificate
		cert, _, err = ReadCertificate(certData)
		if err == nil {
			// Successfully read certificate
			return
		}
	}

	err = errors.New("could not find certificate in data")
	return
}

func constructPublicKey(data []byte, cryptoType uint16) (crypto.PublicKey, error) {
	switch cryptoType {
	case CRYPTO_KEY_TYPE_ELGAMAL:
		if len(data) != 256 {
			return nil, errors.New("invalid ElGamal public key length")
		}
		var elgPublicKey crypto.ElgPublicKey
		copy(elgPublicKey[:], data)
		return elgPublicKey, nil
	// Handle other crypto types...
	default:
		return nil, fmt.Errorf("unsupported crypto key type: %d", cryptoType)
	}
}

func constructSigningPublicKey(data []byte, sigType uint16) (crypto.SigningPublicKey, error) {
	switch sigType {
	case SIGNATURE_TYPE_ED25519_SHA512:
		if len(data) != 32 {
			return nil, errors.New("invalid Ed25519 public key length")
		}
		return crypto.Ed25519PublicKey(data), nil
	// Handle other signature types...
	default:
		return nil, fmt.Errorf("unsupported signature key type: %d", sigType)
	}
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
		return nil, fmt.Errorf("invalid padding size")
	}

	keysAndCert := &KeysAndCert{
		KeyCertificate:   keyCertificate,
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
